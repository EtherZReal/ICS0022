#ifndef LOCKOUT_H
#define LOCKOUT_H

#define LOCKOUT_MAX_FAILURES 3      /* consecutive failures before a lock   */
#define LOCKOUT_SECONDS      1800   /* 30 minutes, also the counting window */

/* All three take a username that has already passed is_valid_account_name().
 * Unknown usernames are tracked exactly like real ones, so the lock behaviour
 * cannot be used to find out which accounts exist. */

/* Returns 1 if locked (and sets *seconds_left if non-NULL), else 0. */
int  lockout_is_locked(const char *username, long *seconds_left);

/* Count one failed attempt; the third consecutive failure starts the lock. */
void lockout_record_failure(const char *username);

/* Forget the failures after a successful authentication. */
void lockout_clear(const char *username);

#endif