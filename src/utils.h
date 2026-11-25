#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>

void read_password(char *password);

void secure_zero(void *ptr, size_t len);

#endif