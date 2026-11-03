#include <stdio.h>
#include "auth.h"

int main() {
    printf("=== Password Manager ===\n");
    create_master_password();
    return 0;
}

/*
int main() {
    int choice;

    printf("=== Password Manager ===\n");
    printf("1. Login\n");
    printf("2. Exit\n");
    printf("Choice: ");

    scanf("%d", &choice);

    if (choice == 1) {
        printf("Login selected\n");
    } else {
        printf("Goodbye\n");
    }

    return 0;
} */