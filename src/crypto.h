#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>

#define CRYPTO_KEY_LEN          32 
#define CRYPTO_SALT_LEN         16 
#define CRYPTO_SALT_HEX_LEN     (CRYPTO_SALT_LEN * 2 + 1)
#define CRYPTO_BCRYPT_HASH_LEN  61
#define CRYPTO_MAX_PASSWORD_LEN 72
#define CRYPTO_MAX_FIELD_LEN    255

#define CRYPTO_HEX_LEN(n)       (2 * (12 + 16 + (n)) + 1)

int crypto_hash_password(const char *password, char *out, size_t out_size);

int crypto_verify_password(const char *password, const char *stored_hash);

int crypto_derive_key(const char *password,
                      const unsigned char salt[CRYPTO_SALT_LEN],
                      unsigned char key[CRYPTO_KEY_LEN]);

int  crypto_random_bytes(unsigned char *buf, size_t len);
void crypto_wipe(void *ptr, size_t len);

int crypto_encrypt(const unsigned char key[CRYPTO_KEY_LEN],
                   const char *aad,
                   const char *plaintext,
                   char *out_hex, size_t out_size);

int crypto_decrypt(const unsigned char key[CRYPTO_KEY_LEN],
                   const char *aad,
                   const char *in_hex,
                   char *out, size_t out_size);

int crypto_hex_encode(const unsigned char *in, size_t in_len,
                      char *out, size_t out_size);
int crypto_hex_decode(const char *in, unsigned char *out,
                      size_t out_size, size_t *out_len);

#endif