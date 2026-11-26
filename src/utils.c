#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include "utils.h"

void secure_zero(void *ptr, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

int read_line(char *buf, size_t size)
{
    if (size == 0) {
        return -1;
    }
    if (fgets(buf, (int)size, stdin) == NULL) {
        buf[0] = '\0';
        return -1;
    }

    size_t n = strlen(buf);
    if (n > 0 && buf[n - 1] == '\n') {
        buf[n - 1] = '\0';
        return 0;
    }

    int c, overflow = 0;
    while ((c = getchar()) != '\n' && c != EOF) {
        overflow = 1;
    }
    if (overflow) {
        secure_zero(buf, size);
        return -2;
    }
    return 0;
}

int read_choice(void)
{
    char line[16];
    int rc = read_line(line, sizeof(line));

    if (rc == -1) {
        return -2;
    }
    if (rc != 0 || line[0] == '\0') {
        return -1;
    }

    char *end = NULL;
    long v = strtol(line, &end, 10);
    if (*end != '\0' || v < 1 || v > 99) {
        return -1;
    }
    return (int)v;
}

int read_password(char *buf, size_t size)
{
    struct termios oldt, newt;
    int have_tty = isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &oldt) == 0;

    if (have_tty) {
        newt = oldt;
        newt.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    }

    int rc = read_line(buf, size);

    if (have_tty) {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    }
    printf("\n");
    return rc;
}

static int name_ok(const char *s, size_t min, size_t max)
{
    size_t n = strlen(s);
    if (n < min || n > max) {
        return 0;
    }
    for (; *s; s++) {
        char c = *s;
        int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                 (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        if (!ok) {
            return 0;
        }
    }
    return 1;
}

int is_valid_account_name(const char *s) { return name_ok(s, 3, 32); }
int is_valid_site(const char *s)         { return name_ok(s, 1, 64); }

int is_valid_text(const char *s, size_t min, size_t max)
{
    size_t n = strlen(s);
    if (n < min || n > max) {
        return 0;
    }
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c < 0x20 || c == 0x7f) {
            return 0;
        }
    }
    return 1;
}