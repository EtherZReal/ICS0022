#include <stdio.h>
#include <string.h>
#include "auth.h"
#include "vault.h"

int create_user() {
    char username[50];
    char password[100];

    printf("Username: ");
    scanf("%49s", username);

    printf("Master password: ");
    scanf("%99s", password);

    FILE *file = fopen("users.txt", "a");

    if (file == NULL) {
        printf("Error opening file.\n");
        return 1;
    }

    fprintf(file, "%s %s\n", username, password);
    fclose(file);

    printf("User created successfully.\n");
    return 0;
}

int login_user() {
    char username[50];
    char password[100];

    char stored_username[50];
    char stored_password[100];

    printf("Username: ");
    scanf("%49s", username);

    printf("Password: ");
    scanf("%99s", password);

    FILE *file = fopen("users.txt", "r");

    if (file == NULL) {
        printf("No users found.\n");
        return 1;
    }

    while (fscanf(file, "%49s %99s",
                  stored_username,
                  stored_password) == 2) {

        if (strcmp(username, stored_username) == 0 &&
            strcmp(password, stored_password) == 0) {

            fclose(file);
            printf("Login successful!\n");
            vault_menu(username);
            return 0;
        }
    }

    fclose(file);
    printf("Login failed.\n");
    return 1;
}