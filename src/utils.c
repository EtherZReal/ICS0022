#include <stdio.h>
#include <termios.h>
#include <unistd.h>
#include "utils.h"

void read_password(char *password)
{
    struct termios oldt, newt;

    tcgetattr(STDIN_FILENO, &oldt);

    newt = oldt;
    newt.c_lflag &= ~ECHO;

    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    scanf("%99s", password);

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

    printf("\n");
}