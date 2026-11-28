#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>

/* ---- Sizes ---- */
#define CRYPTO_KEY_LEN          32  /* AES-256 key */
#define CRYPTO_SALT_LEN         16  /* KDF salt (random, per user) */
#define CRYPTO_SALT_HEX_LEN     (CRYPTO_SALT_LEN * 2 + 1)
#define CRYPTO_BCRYPT_HASH_LEN  61  /* 60 chars + NUL */
#define CRYPTO_MAX_PASSWORD_LEN 72  /* bcrypt ignores bytes past 72 */
#define CRYPTO_MAX_FIELD_LEN    255 /* longest plaintext field we encrypt */

/* Size of the hex string crypto_encrypt() produces for a plaintext of n bytes
 * (12-byte IV + 16-byte GCM tag + n bytes ciphertext, hex encoded, + NUL). */
#define CRYPTO_HEX_LEN(n)       (2 * (12 + 16 + (n)) + 1)

/* ---- Master password: verification only (bcrypt, cost 12) ---- */
/* Writes a 60-char "$2b$12$..." string to out (out_size >= 61). 0 = ok.*/
int crypto_hash_password(const char *password, char *out, size_t out_size);

/* Returns 1 if password matches stored_hash, 0 otherwise (also on any error).
 * The comparison is constant-time. */
int crypto_verify_password(const char *password, const char *stored_hash);

/* ---- Vault key: derived from the master password, never stored ---- */
/* PBKDF2-HMAC-SHA256, 600k iterations, with a salt that is SEPARATE from the
 * bcrypt salt.  Fills key[CRYPTO_KEY_LEN].  0 = ok. */
int crypto_derive_key(const char *password,
                      const unsigned char salt[CRYPTO_SALT_LEN],
                      unsigned char key[CRYPTO_KEY_LEN]);

int  crypto_random_bytes(unsigned char *buf, size_t len); /* 0 = ok */
void crypto_wipe(void *ptr, size_t len); /* never optimised away */

/* ---- Field encryption: AES-256-GCM ---- */
/* Output is hex(IV | TAG | CIPHERTEXT) with a fresh random IV every call.
 * `aad` is authenticated but not encrypted: pass something like
 * "owner|service|password" so a record can't be moved to another user,
 * service, or field without decryption failing.  0 = ok, -1 = failure.*/
int crypto_encrypt(const unsigned char key[CRYPTO_KEY_LEN],
                   const char *aad,
                   const char *plaintext,
                   char *out_hex, size_t out_size);

/* Fails (-1) on wrong key, wrong aad, tampered data, or malformed input.
 * out receives a NUL-terminated string; wipe it with crypto_wipe() after use. */                   
int crypto_decrypt(const unsigned char key[CRYPTO_KEY_LEN],
                   const char *aad,
                   const char *in_hex,
                   char *out, size_t out_size);

int crypto_hex_encode(const unsigned char *in, size_t in_len, 
                      char *out, size_t out_size);        /* 0 = ok */
int crypto_hex_decode(const char *in, unsigned char *out,
                      size_t out_size, size_t *out_len);  /* 0 = ok */

#endif