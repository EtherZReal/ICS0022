#include <stdio.h>
#include <sys/stat.h>
#include "auth.h"
#include "utils.h"

int main(void) {
    umask(077);

    while (1) {
    printf("\n=== Password Manager ===\n");
    printf("1. Register\n");
    printf("2. Login\n");
    printf("3. Exit\n");
    printf("Choice: ");

        int choice = read_choice();

        if (choice == -2) {
            printf("\n\nGoodbye.\n");
            return 0;
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
                printf("\n\nInvalid option.\n\n");
        }
    }
}