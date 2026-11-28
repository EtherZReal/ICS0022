#include <stdio.h>
#include <time.h>

#include "logging.h"
#include "paths.h"

static void clean(const char *in, char *out, size_t size)
{
    size_t i = 0;

    for (; in[i] != '\0' && i + 1 < size; i++) {
        char c = in[i];
        int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                 (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        out[i] = ok ? c : '?';
    }
    out[i] = '\0';
}

void log_event(const char *event, const char *user, const char *target)
{
    char e[64], u[64], t[96];
    char stamp[32] = "unknown";

    FILE *file = data_fopen("password_manager.log", "a");
    if (file == NULL) {
        return;
    }

    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);
    if (tm_info != NULL) {
        strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%SZ", tm_info);
    }
    
    clean(event, e, sizeof(e));
    fprintf(file, "time=%s event=%s", stamp, e);
    if (user != NULL) {
        clean(user, u, sizeof(u));
        fprintf(file, " user=%s", u);
    }
    if (target != NULL) {
        clean(target, t, sizeof(t));
        fprintf(file, " target=%s", t);
    }
    fputc('\n', file);
    fclose(file);
}