#ifndef VAULT_H
#define VAULT_H

void vault_menu(const char *username, const unsigned char *key);

void add_credential(const char *username);
void view_credentials(const char *username);
void update_credential(const char *username);
void delete_credential(const char *username);

#endif