#include <stdio.h>
#include "auth.h"

int main() {
    int choice;

    while (1) {
    printf("\n=== Password Manager ===\n");
    printf("1. Register\n");
    printf("2. Login\n");
    printf("3. Exit\n");
    printf("Choice: ");

        int result = scanf("%d", &choice);
        if (result == EOF) {
            printf("\n\nGoodbye.\n");
            return 0;
        }
        if (result != 1) {
            int ch;
            while ((ch = getchar()) != '\n' && ch != EOF) {
            }
            printf("\n\nInvalid option.\n");
            continue;
        }

    switch (choice) {
        case 1:
            create_user();
                break;

            case 2:
                login_user();
                break;

            case 3:
                printf("\n\nGoodbye.\n");
                return 0;

            default:
                printf("\n\nInvalid option.\n");
        }
    }
}