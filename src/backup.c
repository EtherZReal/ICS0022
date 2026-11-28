#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "backup.h"
#include "logging.h"
#include "paths.h"

#define MAX_LISTED 256
#define NAME_LEN   96
#define STAMP_LEN  15            /* YYYYMMDD-HHMMSS */

static int cmp_names(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

/* True if s is exactly "YYYYMMDD-HHMMSS.bak". */
static int is_stamp_bak(const char *s)
{
    if (strlen(s) != STAMP_LEN + 4 || strcmp(s + STAMP_LEN, ".bak") != 0) {
        return 0;
    }
    for (int i = 0; i < STAMP_LEN; i++) {
        if (i == 8) {
            if (s[i] != '-') return 0;
        } else if (s[i] < '0' || s[i] > '9') {
            return 0;
        }
    }
    return 1;
}

/* Keep only the newest BACKUP_KEEP snapshots of `name`.  The timestamp is
 * YYYYMMDD-HHMMSS in UTC, so sorting names alphabetically sorts them by age. */
static void rotate(const char *name)
{
    static char names[MAX_LISTED][NAME_LEN];
    char prefix[96];
    int count = 0;

    snprintf(prefix, sizeof(prefix), "%s.", name);
    size_t plen = strlen(prefix);

    DIR *dir = opendir(backup_dir());
    if (dir == NULL) {
        return;
    }
    struct dirent *e;
    while ((e = readdir(dir)) != NULL && count < MAX_LISTED) {
        size_t n = strlen(e->d_name);
        if (n >= NAME_LEN || n < plen + 4) {
            continue;
        }
        if (strncmp(e->d_name, prefix, plen) != 0 ||
            !is_stamp_bak(e->d_name + plen)) {
            continue;
        }
        memcpy(names[count++], e->d_name, n + 1);
    }
    closedir(dir);

    qsort(names, (size_t)count, NAME_LEN, cmp_names);
    for (int i = 0; i < count - BACKUP_KEEP; i++) {
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", backup_dir(), names[i]);
        remove(path);
    }
}

int backup_file(const char *name)
{
    char src_path[512], dst_path[640], stamp[32], buf[4096];

    if (data_path(src_path, sizeof(src_path), name) != 0) {
        return -1;
    }
    FILE *in = fopen(src_path, "rb");
    if (in == NULL) {
        return 0; 
    }

    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);
    if (tm_info == NULL ||
        strftime(stamp, sizeof(stamp), "%Y%m%d-%H%M%S", tm_info) == 0) {
        fclose(in);
        return -1;
    }
    snprintf(dst_path, sizeof(dst_path), "%s/%s.%s.bak", backup_dir(), name, stamp);

    if (access(dst_path, F_OK) == 0) {
        fclose(in);
        return 0;
    }

    FILE *out = fopen(dst_path, "wb");
    if (out == NULL) {
        fclose(in);
        log_event("BACKUP_FAILED", NULL, name);
        return -1;
    }

    int ok = 1;
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) {
            ok = 0;
            break;
        }
    }
    if (ferror(in)) {
        ok = 0;
    }
    fclose(in);
    if (fflush(out) != 0) {
        ok = 0;
    } else {
        fsync(fileno(out));
    }
    fclose(out);

    if (!ok) {
        remove(dst_path);
        log_event("BACKUP_FAILED", NULL, name);
        return -1;
    }

    rotate(name);
    return 0;
}