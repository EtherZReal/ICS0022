#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>

/* Read one line from stdin into buf (newline removed).
 * Returns  0 on success,
 *         -1 on EOF / error,
 *         -2 if the line was longer than size-1 (rest of line is discarded
 *            and buf is wiped). */
int read_line(char *buf, size_t size);

/* Read a menu number. Returns the number (1-99), -1 for invalid input,
 * -2 on EOF. */
int read_choice(void);

/* Like read_line but with terminal echo turned off. Same return codes. */
int read_password(char *buf, size_t size);

void secure_zero(void *ptr, size_t len);

/* Ask the OS to keep a buffer out of swap (best effort: returns 0 if locked,
 * -1 if the OS refused, which is not fatal). */
int  secure_lock(void *ptr, size_t len);
void secure_unlock(void *ptr, size_t len);

/* Input validation (allowlists, not blocklists). */
int is_valid_account_name(const char *s); /* 3-32 of [A-Za-z0-9._-] */
int is_valid_site(const char *s); /* 1-64 of [A-Za-z0-9._-] */
int is_valid_text(const char *s, size_t min, size_t max); /* length in range, no control chars */

#endif