#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "lockout.h"
#include "paths.h"

#define LOCK_FILE  "lockout.txt"
#define LOCK_TMP   "lockout.txt.tmp"
#define LINE_LEN   256

/* lockout.txt line:  username failures last_failure_epoch locked_until_epoch */
struct entry {
    char      name[50];
    int       failures;
    long long last;
    long long until;
};

enum { OP_FAIL, OP_CLEAR };

static int parse(const char *line, struct entry *e)
{
    return sscanf(line, "%49s %d %lld %lld",
                  e->name, &e->failures, &e->last, &e->until) == 4;
}

static int find_entry(const char *username, struct entry *out)
{
    char line[LINE_LEN];
    struct entry e;
    int found = 0;

    FILE *f = data_fopen(LOCK_FILE, "r");
    if (f == NULL) {
        return 0;
    }
    while (fgets(line, sizeof(line), f) != NULL) {
        if (parse(line, &e) && strcmp(e.name, username) == 0) {
            if (out != NULL) {
                *out = e;
            }
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

int lockout_is_locked(const char *username, long *seconds_left)
{
    struct entry e;
    long long now = (long long)time(NULL);

    if (find_entry(username, &e) && e.until > now) {
        if (seconds_left != NULL) {
            *seconds_left = (long)(e.until - now);
        }
        return 1;
    }
    return 0;
}

static void apply_failure(struct entry *e, long long now)
{
    /* Failures older than the window no longer count. */
    if (e->failures > 0 && now - e->last >= LOCKOUT_SECONDS) {
        e->failures = 0;
    }
    e->failures++;
    e->last = now;
    if (e->until <= now && e->failures >= LOCKOUT_MAX_FAILURES) {
        e->until = now + LOCKOUT_SECONDS;
    }
}

static void write_entry(FILE *out, const struct entry *e)
{
    fprintf(out, "%s %d %lld %lld\n", e->name, e->failures, e->last, e->until);
}

/* Rewrite lockout.txt through a temp file + rename.  Expired entries of other
 * names are dropped on the way, so the file stays small. */
static void rewrite(const char *username, int op)
{
    char line[LINE_LEN];
    struct entry e;
    int seen = 0;
    long long now = (long long)time(NULL);

    FILE *in  = data_fopen(LOCK_FILE, "r");        /* may not exist yet */
    FILE *out = data_fopen(LOCK_TMP, "w");
    if (out == NULL) {
        if (in != NULL) {
            fclose(in);
        }
        return;
    }

    while (in != NULL && fgets(line, sizeof(line), in) != NULL) {
        if (!parse(line, &e)) {
            continue;                              /* drop malformed lines */
        }
        if (strcmp(e.name, username) == 0) {
            seen = 1;
            if (op == OP_CLEAR) {
                continue;
            }
            apply_failure(&e, now);
        } else if (e.until <= now && now - e.last >= LOCKOUT_SECONDS) {
            continue;                              /* expired */
        }
        write_entry(out, &e);
    }
    if (in != NULL) {
        fclose(in);
    }

    if (op == OP_FAIL && !seen) {
        memset(&e, 0, sizeof(e));
        snprintf(e.name, sizeof(e.name), "%s", username);
        apply_failure(&e, now);
        write_entry(out, &e);
    }

    if (fflush(out) != 0) {
        fclose(out);
        data_remove(LOCK_TMP);
        return;
    }
    fsync(fileno(out));
    fclose(out);
    data_rename(LOCK_TMP, LOCK_FILE);
}

void lockout_record_failure(const char *username)
{
    rewrite(username, OP_FAIL);
}

void lockout_clear(const char *username)
{
    if (find_entry(username, NULL)) {              /* avoid a rewrite per login */
        rewrite(username, OP_CLEAR);
    }
}