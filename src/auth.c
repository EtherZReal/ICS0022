#include <stdio.h>
#include <string.h>
#include "auth.h"
#include "vault.h"
#include "crypto.h"
#include "logging.h"
#include "utils.h"

#define MIN_PASSWORD_LEN 8

static int find_user(const char *username, char *hash_out, char *salt_out)
{
    char u[50];
    char h[CRYPTO_BCRYPT_HASH_LEN];
    char s[CRYPTO_SALT_HEX_LEN];
    int found = 0;

    FILE *file = fopen("users.txt", "r");
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

int create_user() {
    char username[50];
    char password[100];
    char hash[CRYPTO_BCRYPT_HASH_LEN];
    unsigned char salt[CRYPTO_SALT_LEN];
    char salt_hex[CRYPTO_SALT_HEX_LEN];

    printf("Username: ");
    if (scanf("%49s", username) != 1) {
        return 1;
    }

    if (find_user(username, NULL, NULL)) {
        printf("\n\nUsername already exists.\n\n");
        return 1;
    }

    printf("Master password: ");
    read_password(password);

    size_t len = strlen(password);
    if (len < MIN_PASSWORD_LEN || len > CRYPTO_MAX_PASSWORD_LEN) {
        secure_zero(password, sizeof(password));
        printf("\n\nPassword must be %d-%d characters.\n\n",
               MIN_PASSWORD_LEN, CRYPTO_MAX_PASSWORD_LEN);
        return 1;
    }

    if (crypto_hash_password(password, hash, sizeof(hash)) != 0 ||
        crypto_random_bytes(salt, sizeof(salt)) != 0 ||
        crypto_hex_encode(salt, sizeof(salt), salt_hex, sizeof(salt_hex)) != 0) {
        secure_zero(password, sizeof(password));
        printf("\n\nCould not create user.\n\n");
        return 1;
    }
    secure_zero(password, sizeof(password));

    FILE *file = fopen("users.txt", "a");

    if (file == NULL) {
        secure_zero(hash, sizeof(hash));
        printf("\n\nError opening file.\n\n");
        return 1;
    }

    fprintf(file, "%s %s %s\n", username, hash, salt_hex);
    fclose(file);

    printf("\n\nUser created successfully.\n\n");

    char log_message[256];

    snprintf(log_message,
         sizeof(log_message),
         "USER_CREATED %s",
         username);

    log_event(log_message);

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
    int ok = 0;

    printf("Username: ");
    if (scanf("%49s", username) != 1) {
        return 1;
    }

    printf("Password: ");
    read_password(password);

    if (find_user(username, stored_hash, stored_salt)) {
        if (crypto_verify_password(password, stored_hash)) {
            /* Password is right: now derive the vault key from it. */
            if (crypto_hex_decode(stored_salt, salt, sizeof(salt), &salt_len) == 0 &&
                salt_len == sizeof(salt) &&
                crypto_derive_key(password, salt, key) == 0) {
                ok = 1;
            }
        }
    } else {
        char dummy[CRYPTO_BCRYPT_HASH_LEN];
        crypto_hash_password(password, dummy, sizeof(dummy));
    }
    secure_zero(password, sizeof(password));
    
    if (ok) {
        printf("\n\nLogin successful!\n\n");

        char log_message[256];
        snprintf(log_message, sizeof(log_message), "LOGIN_SUCCESS %s", username);
        log_event(log_message);

        vault_menu(username, key);

        crypto_wipe(key, sizeof(key)); 
        return 0;
    }

    printf("\n\nLogin failed.\n\n");

    char log_message[256];
    snprintf(log_message, sizeof(log_message), "LOGIN_FAILED %s", username);
    log_event(log_message);

    return 1;
}