#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "paths.h"

#define DEFAULT_DATA_DIR "data"
#define MAX_DIR_LEN      400

const char *data_dir(void)
{
    const char *d = getenv("PM_DATA_DIR");
    if (d == NULL || d[0] == '\0') {
        return DEFAULT_DATA_DIR;
    }
    return d;
}

const char *backup_dir(void)
{
    static char buf[MAX_DIR_LEN + 32];
    const char *b = getenv("PM_BACKUP_DIR");

    if (b != NULL && b[0] != '\0') {
        snprintf(buf, sizeof(buf), "%s", b);
    } else {
        snprintf(buf, sizeof(buf), "%s/backups", data_dir());
    }
    return buf;
}

static int ensure_dir(const char *path)
{
    if (mkdir(path, 0700) == 0 || errno == EEXIST) {
        return 0;
    }
    return -1;
}

int init_data_dirs(void)
{
    if (strlen(data_dir()) > MAX_DIR_LEN || strlen(backup_dir()) > MAX_DIR_LEN) {
        return -1;
    }
    if (ensure_dir(data_dir()) != 0) {
        return -1;
    }
    return ensure_dir(backup_dir());
}

int data_path(char *out, size_t size, const char *name)
{
    int n = snprintf(out, size, "%s/%s", data_dir(), name);
    return (n < 0 || (size_t)n >= size) ? -1 : 0;
}

FILE *data_fopen(const char *name, const char *mode)
{
    char path[512];
    if (data_path(path, sizeof(path), name) != 0) {
        return NULL;
    }
    return fopen(path, mode);
}

int data_rename(const char *from, const char *to)
{
    char a[512], b[512];
    if (data_path(a, sizeof(a), from) != 0 || data_path(b, sizeof(b), to) != 0) {
        return -1;
    }
    return rename(a, b);
}

int data_remove(const char *name)
{
    char path[512];
    if (data_path(path, sizeof(path), name) != 0) {
        return -1;
    }
    return remove(path);
}