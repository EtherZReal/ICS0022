#ifndef AUTH_H
#define AUTH_H

int create_user();
int login_user();

int auth_verify_password(const char *username, const char *password);

#endif