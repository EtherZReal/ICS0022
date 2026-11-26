#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>

int read_line(char *buf, size_t size);

int read_choice(void);

int read_password(char *buf, size_t size);

void secure_zero(void *ptr, size_t len);

int is_valid_account_name(const char *s);
int is_valid_site(const char *s); 
int is_valid_text(const char *s, size_t min, size_t max);

#endif