#include <stdio.h>
#include <string.h>
#include "vault.h"
#include "logging.h"
#include "utils.h"

void add_credential(const char *username) {
    char site[100];
    char vault_user[100];
    char password[100];

    printf("Site: ");
    scanf("%99s", site);

    printf("Username: ");
    scanf("%99s", vault_user);

    printf("Password: ");
    read_password(password);

    FILE *file = fopen("vault.txt", "a");

    if (file == NULL) {
        printf("Error opening vault.\n\n");
        return;
    }

    fprintf(file, "%s %s %s %s\n", username, site, vault_user, password);

    fclose(file);

    printf("\n\nCredential saved.\n\n");

    char log_message[256];

    snprintf(log_message,
         sizeof(log_message),
         "ADD_CREDENTIAL %s",
         username);

    log_event(log_message);
}

void view_credentials(const char *username) {
    char owner[100];
    char site[100];
    char stored_user[100];
    char password[100];

    FILE *file = fopen("vault.txt", "r");

    if (file == NULL) {
        printf("\n\nVault is empty.\n\n");
        return;
    }

    printf("\nStored credentials:\n");

    while (fscanf(file, "%99s %99s %99s %99s",
                  owner,
                  site,
                  stored_user,
                  password) == 4) {

         if (strcmp(owner, username) == 0) {
            printf("Site: %s | Username: %s\n",
                   site,
                   stored_user);
        }
    }

    fclose(file);
}

void update_credential(const char *username) {

    char owner[100];
    char site[100];
    char stored_user[100];
    char password[100];

    char target_site[100];
    char new_user[100];
    char new_password[100];

    int found = 0;

    printf("Site to update: ");
    scanf("%99s", target_site);

    printf("New username: ");
    scanf("%99s", new_user);

    printf("New password: ");
    read_password(new_password);

    FILE *file = fopen("vault.txt", "r");
    FILE *temp = fopen("temp.txt", "w");

    if (file == NULL || temp == NULL) {
        printf("\n\nError accessing vault.\n\n");
        return;
    }

    while (fscanf(file,
                  "%99s %99s %99s %99s",
                  owner,
                  site,
                  stored_user,
                  password) == 4) {

        if (strcmp(owner, username) == 0 &&
            strcmp(site, target_site) == 0) {

            fprintf(temp,
                    "%s %s %s %s\n",
                    owner,
                    site,
                    new_user,
                    new_password);

            found = 1;
        }
        else {

            fprintf(temp,
                    "%s %s %s %s\n",
                    owner,
                    site,
                    stored_user,
                    password);
        }
    }
    fclose(file);
    fclose(temp);

    remove("vault.txt");
    rename("temp.txt", "vault.txt");

    if (found){
        printf("\n\nCredential updated.\n\n");
        char log_message[256];

        snprintf(log_message,
             sizeof(log_message),
             "UPDATE_CREDENTIAL %s %s",
             username,
             target_site);

        log_event(log_message);
        }
    else
        printf("\n\nCredential not found.\n\n");
}

    void delete_credential(const char *username) {
    char owner[100];
    char site[100];
    char stored_user[100];
    char password[100];

    char target_site[100];

    int found = 0;

    printf("Site to delete: ");
    scanf("%99s", target_site);

    FILE *file = fopen("vault.txt", "r");
    FILE *temp = fopen("temp.txt", "w");

    if (file == NULL || temp == NULL) {
        printf("\n\nError accessing vault.\n\n");
        return;
    }

    while (fscanf(file,
                  "%99s %99s %99s %99s",
                  owner,
                  site,
                  stored_user,
                  password) == 4) {

        if (strcmp(owner, username) == 0 &&
            strcmp(site, target_site) == 0) {

            found = 1;
        }
        else {

            fprintf(temp,
                    "%s %s %s %s\n",
                    owner,
                    site,
                    stored_user,
                    password);
        }
    }

    fclose(file);
    fclose(temp);

    remove("vault.txt");
    rename("temp.txt", "vault.txt");

    if (found){
        printf("\n\nCredential deleted.\n\n");

        char log_message[256];

        snprintf(log_message,
             sizeof(log_message),
             "DELETE_CREDENTIAL %s %s",
             username,
             target_site);

        log_event(log_message);
    }
    else
        printf("\n\nCredential not found.\n\n");
}

void vault_menu(const char *username) {
    int choice;

    while (1) {

        printf("\n=== Vault ===\n");
        printf("1. Add Credential\n");
        printf("2. View Credentials\n");
        printf("3. Update Credential\n");
        printf("4. Delete Credential\n");
        printf("5. Logout\n");
        printf("Choice: ");

        scanf("%d", &choice);

        switch (choice) {

            case 1:
                add_credential(username);
                break;

            case 2:
                view_credentials(username);
                break;

            case 3:
                update_credential(username);
                break;

            case 4:
                delete_credential(username);
                break;

            case 5:
                printf("\n\nLogged out.\n\n");
                return;

            default:
                printf("\n\nInvalid option.\n\n");
        }
    }
}