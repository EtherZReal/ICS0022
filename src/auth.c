#include <stdio.h>
#include <string.h>

#include "auth.h"
#include "backup.h"
#include "vault.h"
#include "crypto.h"
#include "lockout.h"
#include "logging.h"
#include "paths.h"
#include "utils.h"

#define USERS_FILE       "users.txt"
#define MIN_PASSWORD_LEN 8

/* users.txt line format:  username bcrypt_hash kdf_salt_hex
 * Returns 1 and fills hash_out / salt_out (either may be NULL) if the
 * user exists, 0 otherwise. */
static int find_user(const char *username, char *hash_out, char *salt_out)
{
    char u[50];
    char h[CRYPTO_BCRYPT_HASH_LEN];
    char s[CRYPTO_SALT_HEX_LEN];
    int found = 0;

    FILE *file = data_fopen(USERS_FILE, "r");
    if (file == NULL) {
        return 0;
    }

    while (fscanf(file, "%49s %60s %32s", u, h, s) == 3) {
        if (strcmp(u, username) == 0) {
            if (hash_out != NULL) {
                snprintf(hash_out, CRYPTO_BCRYPT_HASH_LEN, "%s", h);
            }
            if (salt_out != NULL) {
                snprintf(salt_out, CRYPTO_SALT_HEX_LEN, "%s", s);
            }
            found = 1;
            break;
        }
    }

    fclose(file);
    return found;
}

int auth_check_password(const char *username, const char *password)
{
    char hash[CRYPTO_BCRYPT_HASH_LEN];

    if (lockout_is_locked(username, NULL)) {
        return AUTH_LOCKED;
    }

    if (find_user(username, hash, NULL) &&
        crypto_verify_password(password, hash)) {
        lockout_clear(username);
        return AUTH_OK;
    }

    lockout_record_failure(username);
    if (lockout_is_locked(username, NULL)) {
        log_event("ACCOUNT_LOCKED", username, NULL);
        return AUTH_LOCKED;
    }
    return AUTH_FAILED;
}

int create_user() {
    char username[50];
    char password[100];
    char confirm[100];
    char hash[CRYPTO_BCRYPT_HASH_LEN];
    unsigned char salt[CRYPTO_SALT_LEN];
    char salt_hex[CRYPTO_SALT_HEX_LEN];

    printf("Username: ");
    if (read_line(username, sizeof(username)) != 0 ||
        !is_valid_account_name(username)) {
        printf("\n\nUsername must be 3-32 characters: letters, digits, '.', '_' or '-'.\n\n");
        return 1;
    }

    if (find_user(username, NULL, NULL)) {
        printf("\n\nUsername already exists.\n\n");
        return 1;
    }

    printf("Master password: ");
    int rc1 = read_password(password, sizeof(password));
    printf("Confirm password: ");
    int rc2 = read_password(confirm, sizeof(confirm));

    if (rc1 != 0 ||
        !is_valid_text(password, MIN_PASSWORD_LEN, CRYPTO_MAX_PASSWORD_LEN)) {
        secure_zero(password, sizeof(password));
        secure_zero(confirm, sizeof(confirm));
        printf("\n\nPassword must be %d-%d characters.\n\n",
               MIN_PASSWORD_LEN, CRYPTO_MAX_PASSWORD_LEN);
        return 1;
    }

    int same = (rc2 == 0 && strcmp(password, confirm) == 0);
    secure_zero(confirm, sizeof(confirm));
    if (!same) {
        secure_zero(password, sizeof(password));
        printf("\n\nPasswords do not match.\n\n");
        return 1;
    }

    /* Two independent things come from the password:
     *  - a bcrypt hash (stored) that only proves the password is right
     *  - a vault key (never stored) derived later with the separate salt */
    if (crypto_hash_password(password, hash, sizeof(hash)) != 0 ||
        crypto_random_bytes(salt, sizeof(salt)) != 0 ||
        crypto_hex_encode(salt, sizeof(salt), salt_hex, sizeof(salt_hex)) != 0) {
        secure_zero(password, sizeof(password));
        printf("\n\nCould not create user.\n\n");
        return 1;
    }
    secure_zero(password, sizeof(password));

    backup_file(USERS_FILE);

    FILE *file = data_fopen(USERS_FILE, "a");
    if (file == NULL) {
        printf("\n\nError opening file.\n\n");
        return 1;
    }

    fprintf(file, "%s %s %s\n", username, hash, salt_hex);
    fclose(file);

    printf("\n\nUser created successfully.\n\n");
    log_event("USER_CREATED", username, NULL);

    return 0;
}

int login_user() {
    char username[50];
    char password[100];
    char stored_hash[CRYPTO_BCRYPT_HASH_LEN];
    char stored_salt[CRYPTO_SALT_HEX_LEN];
    unsigned char salt[CRYPTO_SALT_LEN];
    unsigned char key[CRYPTO_KEY_LEN];
    size_t salt_len = 0;
    long seconds_left = 0;
    int ok = 0;

    printf("Username: ");
    if (read_line(username, sizeof(username)) != 0) {
        printf("\n\nLogin failed.\n\n");
        return 1;
    }

    /* Only names that pass validation are ever looked up or logged, so odd
     * input (spaces, escape codes) can't forge log lines. */
    int valid_name = is_valid_account_name(username);

    /* Rate limiting: after 3 failures the account is locked for 30 minutes.
     * Names that don't exist are tracked the same way, so this message
     * doesn't reveal which usernames are real. */
    if (valid_name && lockout_is_locked(username, &seconds_left)) {
        printf("\n\nToo many failed attempts. Try again in %ld minutes.\n\n",
               (seconds_left + 59) / 60);
        log_event("LOGIN_BLOCKED", username, NULL);
        return 1;
    }

    printf("Password: ");
    read_password(password, sizeof(password));

    if (valid_name && find_user(username, stored_hash, stored_salt)) {
        if (crypto_verify_password(password, stored_hash)) {
            /* Password is right: now derive the vault key from it. */
            if (crypto_hex_decode(stored_salt, salt, sizeof(salt), &salt_len) == 0 &&
                salt_len == sizeof(salt)) {
                secure_lock(key, sizeof(key));   /* keep the key out of swap */
                if (crypto_derive_key(password, salt, key) == 0) {
                    ok = 1;
                } else {
                    crypto_wipe(key, sizeof(key));
                    secure_unlock(key, sizeof(key));
                }
            }
        }
    } else {
        /* Unknown user: burn the same time as a real check so response
         * time doesn't reveal whether the username exists. */
        char dummy[CRYPTO_BCRYPT_HASH_LEN];
        crypto_hash_password(password, dummy, sizeof(dummy));
    }

    secure_zero(password, sizeof(password));
    
    if (ok) {
        lockout_clear(username);
        printf("\n\nLogin successful!\n\n");
        log_event("LOGIN_SUCCESS", username, NULL);

        vault_menu(username, key);

        crypto_wipe(key, sizeof(key)); /* logout: key leaves memory */
        secure_unlock(key, sizeof(key));
        return 0;
    }

    if (valid_name) {
        lockout_record_failure(username);
        if (lockout_is_locked(username, NULL)) {
            log_event("ACCOUNT_LOCKED", username, NULL);
        }
    }

    printf("\n\nLogin failed.\n\n");
    log_event("LOGIN_FAILED", username, NULL);

    return 1;
}