#include <stdio.h>
#include "auth.h"

int main() {
    int choice;

    while (1) {
    printf("=== Password Manager ===\n");
    printf("1. Register\n");
    printf("2. Login\n");
    printf("3. Exit\n");
    printf("Choice: ");

    scanf("%d", &choice);

            switch (choice) {
            case 1:
                create_user();
                break;

            case 2:
                login_user();
                break;

            case 3:
                printf("Goodbye.\n");
                return 0;

            default:
                printf("Invalid option.\n");
        }
    }

    return 0;
}