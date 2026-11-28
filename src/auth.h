#ifndef AUTH_H
#define AUTH_H

int create_user();
int login_user();

#define AUTH_OK       1
#define AUTH_FAILED   0
#define AUTH_LOCKED  -1

/* Re-check the master password of an already logged-in user (used before
 * revealing or updating a credential).  Failures count toward the same
 * lockout as login attempts, so the re-prompt can't be used to guess the
 * password without limit.
 * Returns AUTH_OK, AUTH_FAILED, or AUTH_LOCKED (too many failures: the caller
 * must end the session). */
int auth_check_password(const char *username, const char *password);

#endif