#ifndef BACKUP_H
#define BACKUP_H

/* How many snapshots of each file to keep (oldest are deleted first). */
#define BACKUP_KEEP 20

/* Copy <data dir>/<name> to <backup dir>/<name>.<UTC timestamp>.bak.
 * Backups hold the same encrypted data as the original, so they are no more
 * sensitive than the file itself; they are created with mode 0600.
 * Returns 0 if a backup was made or there was nothing to back up (or one
 * already exists for this second), -1 on failure (also logged). */
int backup_file(const char *name);

#endif