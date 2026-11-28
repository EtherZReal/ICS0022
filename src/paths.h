#ifndef PATHS_H
#define PATHS_H

#include <stddef.h>
#include <stdio.h>

/* All persistent files live in one data directory:
 *   PM_DATA_DIR   (default "data")
 * Backups go to:
 *   PM_BACKUP_DIR (default "<data dir>/backups")
 * Pointing PM_BACKUP_DIR at a different disk or Docker volume means a lost
 * data directory does not take the backups with it. */

const char *data_dir(void);
const char *backup_dir(void);

/* Create both directories (mode 0700) if missing. 0 = ok, -1 = failure. */
int init_data_dirs(void);

/* Build "<data dir>/<name>". 0 = ok, -1 = too long. */
int data_path(char *out, size_t size, const char *name);

FILE *data_fopen(const char *name, const char *mode);
int   data_rename(const char *from, const char *to);
int   data_remove(const char *name);

#endif