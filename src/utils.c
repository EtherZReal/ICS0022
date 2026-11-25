#include <stdio.h>
#include <termios.h>
#include <unistd.h>
#include "utils.h"

void read_password(char *password)
{
    struct termios oldt, newt;
    int ch;

    while ((ch = getchar()) != '\n' && ch != EOF) {
    }

    tcgetattr(STDIN_FILENO, &oldt);

    newt = oldt;
    newt.c_lflag &= ~ECHO;

    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    if (fgets(password, 100, stdin) != NULL) {
        size_t len = strlen(password);
        if (len > 0 && password[len - 1] == '\n') {
            password[len - 1] = '\0';
        }
    } else {
        password[0] = '\0';
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    printf("\n");
}

void secure_zero(void *ptr, size_t len) {
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) {
        *p++ = 0;
    }
}