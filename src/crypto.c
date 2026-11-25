#include <stdio.h>
#include "crypto.h"

void hash_password(const char *password, char *hash)
{
    unsigned long result = 5381;

    while (*password) {
        result = ((result << 5) + result) + *password;
        password++;
    }

    sprintf(hash, "%lu", result);
}