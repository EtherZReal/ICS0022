#include <stdio.h>
#include <string.h>
#include "vault.h"

void add_credential(const char *username) {
    char site[100];
    char vault_user[100];
    char password[100];

    printf("Site: ");
    scanf("%99s", site);

    printf("Username: ");
    scanf("%99s", vault_user);

    printf("Password: ");
    scanf("%99s", password);

    FILE *file = fopen("vault.txt", "a");

    if (file == NULL) {
        printf("Error opening vault.\n");
        return;
    }

    fprintf(file, "%s %s %s %s\n", username, site, vault_user, password);

    fclose(file);

    printf("Credential saved.\n");
}

void view_credentials(const char *username) {
    char owner[100];
    char site[100];
    char stored_user[100];
    char password[100];

    FILE *file = fopen("vault.txt", "r");

    if (file == NULL) {
        printf("Vault is empty.\n");
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

void vault_menu(const char *username) {
    int choice;

    while (1) {

        printf("\n=== Vault ===\n");
        printf("1. Add Credential\n");
        printf("2. View Credentials\n");
        printf("3. Logout\n");
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
                printf("Logged out.\n");
                return;

            default:
                printf("Invalid option.\n");
        }
    }
}