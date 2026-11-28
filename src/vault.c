#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "vault.h"
#include "auth.h"
#include "backup.h"
#include "crypto.h"
#include "logging.h"
#include "paths.h"
#include "utils.h"

#define MAX_FIELD       99                    /* longest username/password */
#define ENC_LEN         CRYPTO_HEX_LEN(MAX_FIELD)
#define VAULT_LINE_LEN  1024

#ifndef REVEAL_SECONDS
#define REVEAL_SECONDS  10
#endif

#ifndef SESSION_TIMEOUT_SECONDS
#define SESSION_TIMEOUT_SECONDS 900           /* 15 minutes of inactivity */
#endif

/* Every user has their own vault file, vault_<username>.txt, one line per
 * credential:   site enc_username enc_password
 * The site name stays readable so entries can be listed; username and
 * password are AES-256-GCM encrypted (hex) with that user's own key, so a
 * vault can only be opened with its owner's master password. */
struct record {
    char site[65];
    char enc_user[ENC_LEN];
    char enc_pw[ENC_LEN];
};

/* Widths in parse_line() below must match the buffers above. */
_Static_assert(ENC_LEN == 255, "update the %254s widths in parse_line()");

/* Set when re-authentication fails too many times.
 * The session is then logged out. */
static int force_logout = 0;

static int parse_line(const char *line, struct record *r)
{
    return sscanf(line, "%64s %254s %254s",
                  r->site, r->enc_user, r->enc_pw) == 3;
}

/* The file name comes from the authenticated owner (never from typed input)
 * and owner names only contain [A-Za-z0-9._-], so it cannot point outside the
 * data directory. */
static int vault_name(const char *owner, char *out, size_t size, int tmp)
{
    int n = snprintf(out, size, tmp ? "vault_%s.txt.tmp" : "vault_%s.txt", owner);
    return (n < 0 || (size_t)n >= size) ? -1 : 0;
}

/* The AAD ties each ciphertext to its owner, site and field.  The owner and
 * site columns in vault.txt are plain text that anyone with file access could
 * edit, but the AAD makes such edits fail closed:
 *   - an entry moved to another owner or site no longer decrypts (wrong AAD,
 *     and also the wrong user's key);
 *   - the username and password of an entry can't be swapped.
 * owner/site only contain [A-Za-z0-9._-], so "|" is an unambiguous separator. */
static void make_aad(char *aad, size_t size, const char *owner,
                     const char *site, const char *field)
{
    snprintf(aad, size, "%s|%s|%s", owner, site, field);
}

static int seal_record(const unsigned char *key, const char *owner,
                       const char *site, const char *user, const char *pw,
                       struct record *r)
{
    char aad[256];

    snprintf(r->site, sizeof(r->site), "%s", site);

    make_aad(aad, sizeof(aad), owner, site, "username");
    if (crypto_encrypt(key, aad, user, r->enc_user, sizeof(r->enc_user)) != 0) {
        return 0;
    }
    make_aad(aad, sizeof(aad), owner, site, "password");
    if (crypto_encrypt(key, aad, pw, r->enc_pw, sizeof(r->enc_pw)) != 0) {
        return 0;
    }
    return 1;
}

static void write_record(FILE *f, const struct record *r)
{
    fprintf(f, "%s %s %s\n", r->site, r->enc_user, r->enc_pw);
}

/* Access control: the owner is always the authenticated user passed down from
 * login (never typed in), and every lookup matches BOTH owner and site, so a
 * user can only ever find their own records. */
static int find_record(const char *owner, const char *site, struct record *out)
{
    char line[VAULT_LINE_LEN];
    char name[64];
    struct record r;
    int found = 0;

    if (vault_name(owner, name, sizeof(name), 0) != 0) {
        return 0;
    }
    FILE *f = data_fopen(name, "r");
    if (f == NULL) {
        return 0;
    }
    while (fgets(line, sizeof(line), f) != NULL) {
        if (parse_line(line, &r) && strcmp(r.site, site) == 0) {
            if (out != NULL) {
                *out = r;
            }
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

/* Copy the vault to a temp file, replacing (replacement != NULL) or dropping
 * (replacement == NULL) this owner's record for `site`.  Other lines, including
 * other users' records, are copied through untouched.  The temp file then
 * replaces the vault in one rename(), so a crash can't leave a half-written
 * vault, and a backup is taken first.
 * Returns 1 = changed, 0 = not found, -1 = error. */
static int rewrite_vault(const char *owner, const char *site,
                         const struct record *replacement)
{
    char line[VAULT_LINE_LEN];
    char name[64], tmp_name[72];
    struct record r;
    int found = 0;

    if (vault_name(owner, name, sizeof(name), 0) != 0 ||
        vault_name(owner, tmp_name, sizeof(tmp_name), 1) != 0) {
        return -1;
    }

    backup_file(name);

    FILE *in = data_fopen(name, "r");
    if (in == NULL) {
        return 0;
    }
    FILE *out = data_fopen(tmp_name, "w");
    if (out == NULL) {
        fclose(in);
        return -1;
    }

    while (fgets(line, sizeof(line), in) != NULL) {
        if (parse_line(line, &r) && strcmp(r.site, site) == 0) {
            found = 1;
            if (replacement != NULL) {
                write_record(out, replacement);
            }
        } else {
            fputs(line, out);
        }
    }
    fclose(in);

    if (fflush(out) != 0 || ferror(out)) {
        fclose(out);
        data_remove(tmp_name);
        return -1;
    }
    fsync(fileno(out));
    fclose(out);

    if (!found) {
        data_remove(tmp_name);
        return 0;
    }
    if (data_rename(tmp_name, name) != 0) {
        data_remove(tmp_name);
        return -1;
    }
    return 1;
}

static int prompt_site(const char *prompt, char *site, size_t size)
{
    printf("%s", prompt);
    if (read_line(site, size) != 0 || !is_valid_site(site)) {
        printf("\n\nInvalid site name (1-64 characters: letters, digits, '.', '_' or '-').\n\n");
        return 0;
    }
    return 1;
}

static int prompt_credential(char *user, size_t usize, char *pw, size_t psize)
{
    printf("Username: ");
    if (read_line(user, usize) != 0 || !is_valid_text(user, 1, MAX_FIELD)) {
        printf("\n\nInvalid username (1-%d printable characters).\n\n", MAX_FIELD);
        return 0;
    }

    printf("Password: ");
    if (read_password(pw, psize) != 0 || !is_valid_text(pw, 1, MAX_FIELD)) {
        secure_zero(user, usize);
        secure_zero(pw, psize);
        printf("\n\nInvalid password (1-%d printable characters).\n\n", MAX_FIELD);
        return 0;
    }
    return 1;
}

/* Ask for the master password again before a high-risk action (revealing or
 * changing a stored password).  Wrong attempts count toward the same lockout
 * as login, otherwise someone at an unattended terminal could guess the master
 * password here without limit.  Returns 1 if confirmed. */
static int reauthenticate(const char *owner)
{
    char master[100];

    printf("Re-enter master password: ");
    int rc = read_password(master, sizeof(master));
    int result = (rc == 0) ? auth_check_password(owner, master) : AUTH_FAILED;
    secure_zero(master, sizeof(master));

    if (result == AUTH_OK) {
        return 1;
    }

    log_event("REAUTH_FAILED", owner, NULL);

    if (result == AUTH_LOCKED) {
        printf("\n\nToo many failed attempts. Logging out.\n\n");
        force_logout = 1;
    } else {
        printf("\n\nAuthentication failed.\n\n");
    }
    return 0;
}

static void add_credential(const char *owner, const unsigned char *key)
{
    char site[100];
    char user[MAX_FIELD + 1];
    char pw[MAX_FIELD + 1];
    char name[64];
    struct record r;
    FILE *f;

    if (!prompt_site("Site: ", site, sizeof(site))) {
        return;
    }
    if (!prompt_credential(user, sizeof(user), pw, sizeof(pw))) {
        return;
    }

    if (vault_name(owner, name, sizeof(name), 0) != 0) {
        printf("\n\nError saving credential.\n\n");
    } else if (find_record(owner, site, NULL)) {
        printf("\n\nThat site already has a credential. Use Update instead.\n\n");
    } else if (!seal_record(key, owner, site, user, pw, &r)) {
        printf("\n\nError saving credential.\n\n");
    } else {
        backup_file(name);
        f = data_fopen(name, "a");
        if (f == NULL) {
            printf("\n\nError saving credential.\n\n");
        } else {
            write_record(f, &r);
            fclose(f);
            printf("\n\nCredential saved.\n\n");
            log_event("ADD_CREDENTIAL", owner, site);
        }
    }

    /* plaintext leaves memory as soon as it has been encrypted */
    secure_zero(user, sizeof(user));
    secure_zero(pw, sizeof(pw));
}

static void view_credentials(const char *owner, const unsigned char *key)
{
    char line[VAULT_LINE_LEN];
    char aad[256];
    char user[MAX_FIELD + 1];
    char name[64];
    struct record r;
    int count = 0;

    printf("\nStored credentials:\n");

    FILE *f = (vault_name(owner, name, sizeof(name), 0) == 0)
                  ? data_fopen(name, "r") : NULL;
    if (f != NULL) {
        while (fgets(line, sizeof(line), f) != NULL) {
            if (!parse_line(line, &r)) {
                continue;
            }
            make_aad(aad, sizeof(aad), owner, r.site, "username");
            if (crypto_decrypt(key, aad, r.enc_user, user, sizeof(user)) == 0) {
                printf("Site: %s | Username: %s | Password: ********\n", r.site, user);
            } else {
                printf("Site: %s | (entry could not be read)\n", r.site);
            }
            secure_zero(user, sizeof(user));
            count++;
        }
        fclose(f);
    }

    if (count == 0) {
        printf("(none)\n");
    }
}

static void reveal_credential(const char *owner, const unsigned char *key)
{
    char site[65];
    char aad[256];
    char user[MAX_FIELD + 1];
    char pw[MAX_FIELD + 1];
    char shown[2 * MAX_FIELD + 64];
    struct record r;

    if (!prompt_site("Site to reveal: ", site, sizeof(site))) {
        return;
    }
    if (!find_record(owner, site, &r)) {
        printf("\n\nCredential not found.\n\n");
        return;
    }

    /* Showing a password is the riskiest action, so ask for the master
     * password again even though the user is already logged in. */
    if (!reauthenticate(owner)) {
        return;
    }

    make_aad(aad, sizeof(aad), owner, site, "username");
    int ok_u = (crypto_decrypt(key, aad, r.enc_user, user, sizeof(user)) == 0);
    make_aad(aad, sizeof(aad), owner, site, "password");
    int ok_p = (crypto_decrypt(key, aad, r.enc_pw, pw, sizeof(pw)) == 0);

    if (!ok_u || !ok_p) {
        printf("\n\nCould not read credential.\n\n");
    } else {
        /* Written straight to the terminal from a local buffer that is wiped
         * right after, so no copy stays behind in stdio's output buffer. */
        int len = snprintf(shown, sizeof(shown),
                           "\nUsername: %s\nPassword: %s\n", user, pw);
        fflush(stdout);
        if (len > 0) {
            ssize_t w = write(STDOUT_FILENO, shown, (size_t)len);
            (void)w;
        }
        secure_zero(shown, sizeof(shown));

        printf("(hidden again in %d seconds)\n", REVEAL_SECONDS);
        fflush(stdout);
        sleep(REVEAL_SECONDS);
        /* move up 3 lines and erase them */
        printf("\033[3A\033[J");
        printf("Credential hidden.\n\n");

        log_event("REVEAL_CREDENTIAL", owner, site);
    }

    secure_zero(user, sizeof(user));
    secure_zero(pw, sizeof(pw));
}

static void update_credential(const char *owner, const unsigned char *key)
{
    char site[65];
    char user[MAX_FIELD + 1];
    char pw[MAX_FIELD + 1];
    struct record r;

    if (!prompt_site("Site to update: ", site, sizeof(site))) {
        return;
    }
    if (!find_record(owner, site, NULL)) {
        printf("\n\nCredential not found.\n\n");
        return;
    }
    /* Changing a stored password is high-risk too: re-authenticate first. */
    if (!reauthenticate(owner)) {
        return;
    }

    if (!prompt_credential(user, sizeof(user), pw, sizeof(pw))) {
        return;
    }

    int result = -1;
    if (seal_record(key, owner, site, user, pw, &r)) {
        result = rewrite_vault(owner, site, &r);
    }

    secure_zero(user, sizeof(user));
    secure_zero(pw, sizeof(pw));

    if (result == 1) {
        printf("\n\nCredential updated.\n\n");
        log_event("UPDATE_CREDENTIAL", owner, site);
    } else {
        printf("\n\nError updating credential.\n\n");
    }
}

static void delete_credential(const char *owner)
{
    char site[65];

    if (!prompt_site("Site to delete: ", site, sizeof(site))) {
        return;
    }
    if (!find_record(owner, site, NULL)) {
        printf("\n\nCredential not found.\n\n");
        return;
    }

    /* Deleting cannot be undone from inside the program, so it needs the
     * master password too (a backup is still taken first). */
    if (!reauthenticate(owner)) {
        return;
    }

    int result = rewrite_vault(owner, site, NULL);

    if (result == 1) {
        printf("\n\nCredential deleted.\n\n");
        log_event("DELETE_CREDENTIAL", owner, site);
    } else if (result == 0) {
        printf("\n\nCredential not found.\n\n");
    } else {
        printf("\n\nError deleting credential.\n\n");
    }
}

void vault_menu(const char *username, const unsigned char *key) 
{
    char name[64];
    time_t last_active = time(NULL);
    
    force_logout = 0;

    /* One snapshot per session, taken before anything is changed. */
    if (vault_name(username, name, sizeof(name), 0) == 0) {
        backup_file(name);
    }

    while (1) {
        printf("\n=== Vault ===\n");
        printf("1. Add Credential\n");
        printf("2. List Credentials\n");
        printf("3. Reveal Credential\n");
        printf("4. Update Credential\n");
        printf("5. Delete Credential\n");
        printf("6. Logout\n");
        printf("Choice: ");

        int choice = read_choice();

        /* Inactivity logout: a command typed after the allowed idle time is
         * not run; the user must log in again. */
        if (time(NULL) - last_active > SESSION_TIMEOUT_SECONDS) {
            printf("\n\nSession expired after inactivity. Please log in again.\n\n");
            log_event("SESSION_TIMEOUT", username, NULL);
            return;
        }

        switch (choice) {
            case 1:
                add_credential(username, key);
                break;
            case 2:
                view_credentials(username, key);
                break;
            case 3:
                reveal_credential(username, key);
                break;
            case 4:
                update_credential(username, key);
                break;
            case 5:
                delete_credential(username);
                break;
            case 6:
            case -2: /* EOF: treat as logout */
                printf("\n\nLogged out.\n\n");
                return;
            default:
                printf("\n\nInvalid option.\n\n");
        }

        if (force_logout) {
            return;
        }
        last_active = time(NULL);
    }
}