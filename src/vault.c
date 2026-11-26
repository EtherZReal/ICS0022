#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "auth.h"
#include "vault.h"
#include "crypto.h"
#include "logging.h"
#include "utils.h"

#define VAULT_FILE      "vault.txt"
#define VAULT_TMP       "vault.txt.tmp"
#define MAX_FIELD       99                    /* longest username/password */
#define ENC_LEN         CRYPTO_HEX_LEN(MAX_FIELD)
#define VAULT_LINE_LEN  1024

#ifndef REVEAL_SECONDS
#define REVEAL_SECONDS  10
#endif

struct record {
    char owner[50];
    char site[65];
    char enc_user[ENC_LEN];
    char enc_pw[ENC_LEN];
};

_Static_assert(ENC_LEN == 255, "update the %254s widths in parse_line()");

static int parse_line(const char *line, struct record *r)
{
    return sscanf(line, "%49s %64s %254s %254s",
                  r->owner, r->site, r->enc_user, r->enc_pw) == 4;
}

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

    snprintf(r->owner, sizeof(r->owner), "%s", owner);
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
    fprintf(f, "%s %s %s %s\n", r->owner, r->site, r->enc_user, r->enc_pw);
}

static int find_record(const char *owner, const char *site, struct record *out)
{
    char line[VAULT_LINE_LEN];
    struct record r;
    int found = 0;

    FILE *f = fopen(VAULT_FILE, "r");
    if (f == NULL) {
        return 0;
    }
    while (fgets(line, sizeof(line), f) != NULL) {
        if (parse_line(line, &r) &&
            strcmp(r.owner, owner) == 0 && strcmp(r.site, site) == 0) {
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

static int rewrite_vault(const char *owner, const char *site,
                         const struct record *replacement)
{
    char line[VAULT_LINE_LEN];
    struct record r;
    int found = 0;

    FILE *in = fopen(VAULT_FILE, "r");
    if (in == NULL) {
        return 0;
    }
    FILE *out = fopen(VAULT_TMP, "w");
    if (out == NULL) {
        fclose(in);
        return -1;
    }

    while (fgets(line, sizeof(line), in) != NULL) {
        if (parse_line(line, &r) &&
            strcmp(r.owner, owner) == 0 && strcmp(r.site, site) == 0) {
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
        remove(VAULT_TMP);
        return -1;
    }
    fsync(fileno(out));
    fclose(out);

    if (!found) {
        remove(VAULT_TMP);
        return 0;
    }
    if (rename(VAULT_TMP, VAULT_FILE) != 0) {
        remove(VAULT_TMP);
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

static void add_credential(const char *owner, const unsigned char *key)
{
    char site[100];
    char user[MAX_FIELD + 1];
    char pw[MAX_FIELD + 1];
    char log_message[256];
    struct record r;
    FILE *f;

    if (!prompt_site("Site: ", site, sizeof(site))) {
        return;
    }
    if (!prompt_credential(user, sizeof(user), pw, sizeof(pw))) {
        return;
    }

    if (find_record(owner, site, NULL)) {
        printf("\n\nThat site already has a credential. Use Update instead.\n\n");
    } else if (!seal_record(key, owner, site, user, pw, &r) ||
               (f = fopen(VAULT_FILE, "a")) == NULL) {
        printf("\n\nError saving credential.\n\n");
    } else {
        write_record(f, &r);
        fclose(f);
        printf("\n\nCredential saved.\n\n");
        snprintf(log_message, sizeof(log_message), "ADD_CREDENTIAL %s %s", owner, site);
        log_event(log_message);
    }

    secure_zero(user, sizeof(user));
    secure_zero(pw, sizeof(pw));
}

static void view_credentials(const char *owner, const unsigned char *key)
{
    char line[VAULT_LINE_LEN];
    char aad[256];
    char user[MAX_FIELD + 1];
    struct record r;
    int count = 0;

    FILE *f = fopen(VAULT_FILE, "r");
    if (f == NULL) {
        printf("\n\nVault is empty.\n\n");
        return;
    }

    printf("\nStored credentials:\n");

    while (fgets(line, sizeof(line), f) != NULL) {
        if (!parse_line(line, &r) || strcmp(r.owner, owner) != 0) {
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

    if (count == 0) {
        printf("(none)\n");
    }
}

static void reveal_credential(const char *owner, const unsigned char *key)
{
    char site[65];
    char master[100];
    char aad[256];
    char user[MAX_FIELD + 1];
    char pw[MAX_FIELD + 1];
    char log_message[256];
    struct record r;

    if (!prompt_site("Site to reveal: ", site, sizeof(site))) {
        return;
    }
    if (!find_record(owner, site, &r)) {
        printf("\n\nCredential not found.\n\n");
        return;
    }

    printf("Re-enter master password: ");
    int rc = read_password(master, sizeof(master));
    int ok = (rc == 0 && auth_verify_password(owner, master));
    secure_zero(master, sizeof(master));

    if (!ok) {
        printf("\n\nAuthentication failed.\n\n");
        snprintf(log_message, sizeof(log_message), "REAUTH_FAILED %s", owner);
        log_event(log_message);
        return;
    }

    make_aad(aad, sizeof(aad), owner, site, "username");
    int ok_u = (crypto_decrypt(key, aad, r.enc_user, user, sizeof(user)) == 0);
    make_aad(aad, sizeof(aad), owner, site, "password");
    int ok_p = (crypto_decrypt(key, aad, r.enc_pw, pw, sizeof(pw)) == 0);

    if (!ok_u || !ok_p) {
        printf("\n\nCould not read credential.\n\n");
    } else {
        printf("\nUsername: %s\n", user);
        printf("Password: %s\n", pw);
        printf("(hidden again in %d seconds)\n", REVEAL_SECONDS);
        fflush(stdout);
        sleep(REVEAL_SECONDS);
        printf("\033[3A\033[J");
        printf("Credential hidden.\n\n");

        snprintf(log_message, sizeof(log_message), "REVEAL_CREDENTIAL %s %s", owner, site);
        log_event(log_message);
    }

    secure_zero(user, sizeof(user));
    secure_zero(pw, sizeof(pw));
}

static void update_credential(const char *owner, const unsigned char *key)
{
    char site[65];
    char user[MAX_FIELD + 1];
    char pw[MAX_FIELD + 1];
    char log_message[256];
    struct record r;

    if (!prompt_site("Site to update: ", site, sizeof(site))) {
        return;
    }
    if (!find_record(owner, site, NULL)) {
        printf("\n\nCredential not found.\n\n");
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
        snprintf(log_message, sizeof(log_message), "UPDATE_CREDENTIAL %s %s", owner, site);
        log_event(log_message);
    } else {
        printf("\n\nError updating credential.\n\n");
    }
}

static void delete_credential(const char *owner)
{
    char site[65];
    char log_message[256];

    if (!prompt_site("Site to delete: ", site, sizeof(site))) {
        return;
    }

    int result = rewrite_vault(owner, site, NULL);

    if (result == 1) {
        printf("\n\nCredential deleted.\n\n");
        snprintf(log_message, sizeof(log_message), "DELETE_CREDENTIAL %s %s", owner, site);
        log_event(log_message);
    } else if (result == 0) {
        printf("\n\nCredential not found.\n\n");
    } else {
        printf("\n\nError deleting credential.\n\n");
    }
}

void vault_menu(const char *username, const unsigned char *key) 
{
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
            case -2:
                printf("\n\nLogged out.\n\n");
                return;
            default:
                printf("\n\nInvalid option.\n\n");
        }
    }
}