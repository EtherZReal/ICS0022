#include <stdio.h>
#include <string.h>
#include "auth.h"
#include "vault.h"
#include "crypto.h"
#include "logging.h"
#include "utils.h"

int create_user() {
    char username[50];
    char password[100];
    char hash[100];

    char stored_username[50];
    char stored_hash[100];

    printf("Username: ");
    if (scanf("%49s", username) != 1) {
        return 1;
    }

    FILE *file = fopen("users.txt", "r");

    if (file != NULL) {

        while (fscanf(file,
                      "%49s %99s",
                      stored_username,
                      stored_hash) == 2) {

            if (strcmp(username, stored_username) == 0) {

                fclose(file);
                secure_zero(stored_hash, sizeof(stored_hash));

                printf("\n\nUsername already exists.\n\n");

                return 1;
            }
        }

        fclose(file);
        secure_zero(stored_hash, sizeof(stored_hash));
    }

    printf("Master password: ");
    read_password(password);

    hash_password(password, hash);
    secure_zero(password, sizeof(password));

    file = fopen("users.txt", "a");

    if (file == NULL) {
        secure_zero(hash, sizeof(hash));
        printf("\n\nError opening file.\n\n");
        return 1;
    }

    fprintf(file, "%s %s\n", username, hash);
    fclose(file);
    secure_zero(hash, sizeof(hash));

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
    char hash[100];

    char stored_username[50];
    char stored_hash[100];

    printf("Username: ");
    if (scanf("%49s", username) != 1) {
        return 1;
    }

    printf("Password: ");
    read_password(password);

    hash_password(password, hash);
    secure_zero(password, sizeof(password));
    
    FILE *file = fopen("users.txt", "r");

    if (file == NULL) {
        secure_zero(hash, sizeof(hash));
        printf("\n\nNo users found.\n\n");
        return 1;
    }

    while (fscanf(file, "%49s %99s",
                  stored_username,
                  stored_hash) == 2) {

        if (strcmp(username, stored_username) == 0 &&
            strcmp(hash, stored_hash) == 0) {

            fclose(file);
            secure_zero(hash, sizeof(hash));
            secure_zero(stored_hash, sizeof(stored_hash));

            printf("\n\nLogin successful!\n\n");

            char log_message[256];

            snprintf(log_message,
                sizeof(log_message),
                "LOGIN_SUCCESS %s",
                username);

            log_event(log_message);

            vault_menu(username);
            return 0;
        }
    }

    fclose(file);
    secure_zero(hash, sizeof(hash));
    secure_zero(stored_hash, sizeof(stored_hash));

    printf("\n\nLogin failed.\n\n");

    char log_message[256];

    snprintf(log_message,
         sizeof(log_message),
         "LOGIN_FAILED %s",
         username);

    log_event(log_message);

    return 1;
}