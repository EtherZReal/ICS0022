#ifndef VAULT_H
#define VAULT_H

/* Runs the vault menu for an authenticated user.  `key` is the vault key
 * derived at login; the caller wipes it after this returns. */
void vault_menu(const char *username, const unsigned char *key);

#endif