#include <stdio.h>
#include <string.h>
#include "crypto.h"

static int failures = 0;
#define CHECK(cond) do { \
    if (cond) printf("  ok    %s\n", #cond); \
    else { printf("  FAIL  %s  (line %d)\n", #cond, __LINE__); failures++; } \
} while (0)

int main(void)
{
    char h1[CRYPTO_BCRYPT_HASH_LEN], h2[CRYPTO_BCRYPT_HASH_LEN];
    unsigned char salt[CRYPTO_SALT_LEN], k1[CRYPTO_KEY_LEN], k2[CRYPTO_KEY_LEN];
    char enc[CRYPTO_HEX_LEN(CRYPTO_MAX_FIELD_LEN)], enc2[CRYPTO_HEX_LEN(CRYPTO_MAX_FIELD_LEN)];
    char dec[CRYPTO_MAX_FIELD_LEN + 1];

    puts("bcrypt");
    CHECK(crypto_hash_password("correct horse", h1, sizeof(h1)) == 0);
    CHECK(crypto_hash_password("correct horse", h2, sizeof(h2)) == 0);
    CHECK(strncmp(h1, "$2b$12$", 7) == 0);
    CHECK(strcmp(h1, h2) != 0);
    CHECK(crypto_verify_password("correct horse", h1) == 1);
    CHECK(crypto_verify_password("correct horsf", h1) == 0);
    CHECK(crypto_verify_password("", h1) == 0);
    CHECK(crypto_verify_password("correct horse", "garbage") == 0);
    CHECK(crypto_verify_password("correct horse", "") == 0);

    char longpw[100];
    memset(longpw, 'a', 99); longpw[99] = '\0';
    CHECK(crypto_hash_password(longpw, h1, sizeof(h1)) == -1);
    CHECK(crypto_hash_password("x", h1, 10) == -1);

    puts("key derivation");
    CHECK(crypto_random_bytes(salt, sizeof(salt)) == 0);
    CHECK(crypto_derive_key("pw", salt, k1) == 0);
    CHECK(crypto_derive_key("pw", salt, k2) == 0);
    CHECK(memcmp(k1, k2, sizeof(k1)) == 0);
    CHECK(crypto_derive_key("pW", salt, k2) == 0);
    CHECK(memcmp(k1, k2, sizeof(k1)) != 0);
    salt[0] ^= 1;
    CHECK(crypto_derive_key("pw", salt, k2) == 0);
    CHECK(memcmp(k1, k2, sizeof(k1)) != 0);
    salt[0] ^= 1;

    puts("AES-256-GCM");
    const char *aad = "alice|github|password";
    CHECK(crypto_encrypt(k1, aad, "s3cret pass!", enc, sizeof(enc)) == 0);
    CHECK(crypto_encrypt(k1, aad, "s3cret pass!", enc2, sizeof(enc2)) == 0);
    CHECK(strcmp(enc, enc2) != 0);
    CHECK(strstr(enc, "s3cret") == NULL);
    CHECK(crypto_decrypt(k1, aad, enc, dec, sizeof(dec)) == 0);
    CHECK(strcmp(dec, "s3cret pass!") == 0);

    CHECK(crypto_decrypt(k2, aad, enc, dec, sizeof(dec)) == -1);
    CHECK(dec[0] == '\0');
    CHECK(crypto_decrypt(k1, "bob|github|password", enc, dec, sizeof(dec)) == -1);

    char tampered[sizeof(enc)];
    strcpy(tampered, enc);
    tampered[strlen(tampered) - 1] = (tampered[strlen(tampered) - 1] == '0') ? '1' : '0';
    CHECK(crypto_decrypt(k1, aad, tampered, dec, sizeof(dec)) == -1);
    CHECK(crypto_decrypt(k1, aad, "zz", dec, sizeof(dec)) == -1);
    CHECK(crypto_decrypt(k1, aad, "abcd", dec, sizeof(dec)) == -1);
    CHECK(crypto_decrypt(k1, aad, enc, dec, 3) == -1);

    CHECK(crypto_encrypt(k1, aad, "", enc, sizeof(enc)) == 0);         /* empty field */
    CHECK(crypto_decrypt(k1, aad, enc, dec, sizeof(dec)) == 0 && dec[0] == '\0');

    puts("hex");
    unsigned char back[CRYPTO_SALT_LEN]; size_t n = 0; char hex[CRYPTO_SALT_HEX_LEN];
    CHECK(crypto_hex_encode(salt, sizeof(salt), hex, sizeof(hex)) == 0);
    CHECK(crypto_hex_decode(hex, back, sizeof(back), &n) == 0 && n == sizeof(salt));
    CHECK(memcmp(salt, back, sizeof(salt)) == 0);

    crypto_wipe(k1, sizeof(k1));
    CHECK(k1[0] == 0 && k1[31] == 0);

    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "ALL PASSED",
           failures, failures == 1 ? "" : "s");
    return failures != 0;
}