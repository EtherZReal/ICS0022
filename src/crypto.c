#include "crypto.h"

#include <crypt.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define BCRYPT_COST   12
#define PBKDF2_ITERS  600000
#define GCM_IV_LEN    12
#define GCM_TAG_LEN   16

void crypto_wipe(void *ptr, size_t len)
{
    if (ptr != NULL && len > 0) {
        OPENSSL_cleanse(ptr, len);
    }
}

int crypto_random_bytes(unsigned char *buf, size_t len)
{
    return RAND_bytes(buf, (int)len) == 1 ? 0 : -1;
}

int crypto_hex_encode(const unsigned char *in, size_t in_len,
                      char *out, size_t out_size)
{
    static const char digits[] = "0123456789abcdef";

    if (out_size < in_len * 2 + 1) {
        return -1;
    }
    for (size_t i = 0; i < in_len; i++) {
        out[2 * i]     = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 0x0f];
    }
    out[in_len * 2] = '\0';
    return 0;
}

static int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int crypto_hex_decode(const char *in, unsigned char *out,
                      size_t out_size, size_t *out_len)
{
    size_t n = strlen(in);

    if (n % 2 != 0 || n / 2 > out_size) {
        return -1;
    }
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hex_val(in[2 * i]);
        int lo = hex_val(in[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return -1;
        }
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    *out_len = n / 2;
    return 0;
}

int crypto_hash_password(const char *password, char *out, size_t out_size)
{
    unsigned char rnd[16];
    char setting[CRYPT_GENSALT_OUTPUT_SIZE];
    struct crypt_data *data = NULL;
    int rc = -1;

    if (password == NULL || out == NULL || out_size < CRYPTO_BCRYPT_HASH_LEN) {
        return -1;
    }
    
    if (strlen(password) > CRYPTO_MAX_PASSWORD_LEN) {
        return -1;
    }
    if (crypto_random_bytes(rnd, sizeof(rnd)) != 0) {
        return -1;
    }
    if (crypt_gensalt_rn("$2b$", BCRYPT_COST, (const char *)rnd, sizeof(rnd),
                         setting, sizeof(setting)) == NULL) {
        goto done;
    }

    data = calloc(1, sizeof(*data));
    if (data == NULL) {
        goto done;
    }

    const char *hash = crypt_r(password, setting, data);
    if (hash == NULL || hash[0] != '$' || strlen(hash) != 60 ||
        strncmp(hash, "$2b$", 4) != 0) {
        goto done;
    }
    memcpy(out, hash, 61);
    rc = 0;

done:
    crypto_wipe(rnd, sizeof(rnd));
    if (data != NULL) {
        crypto_wipe(data, sizeof(*data));
        free(data);
    }
    return rc;
}

int crypto_verify_password(const char *password, const char *stored_hash)
{
    struct crypt_data *data;
    int ok = 0;

    if (password == NULL || stored_hash == NULL ||
        strlen(stored_hash) != 60 || strncmp(stored_hash, "$2b$", 4) != 0 ||
        strlen(password) > CRYPTO_MAX_PASSWORD_LEN) {
        return 0;
    }

    data = calloc(1, sizeof(*data));
    if (data == NULL) {
        return 0;
    }

    const char *computed = crypt_r(password, stored_hash, data);
    if (computed != NULL && strlen(computed) == 60 &&
        CRYPTO_memcmp(computed, stored_hash, 60) == 0) {
        ok = 1;
    }

    crypto_wipe(data, sizeof(*data));
    free(data);
    return ok;
}

int crypto_derive_key(const char *password,
                      const unsigned char salt[CRYPTO_SALT_LEN],
                      unsigned char key[CRYPTO_KEY_LEN])
{
    if (password == NULL || salt == NULL || key == NULL) {
        return -1;
    }
    if (PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                          salt, CRYPTO_SALT_LEN, PBKDF2_ITERS,
                          EVP_sha256(), CRYPTO_KEY_LEN, key) != 1) {
        crypto_wipe(key, CRYPTO_KEY_LEN);
        return -1;
    }
    return 0;
}

int crypto_encrypt(const unsigned char key[CRYPTO_KEY_LEN],
                   const char *aad,
                   const char *plaintext,
                   char *out_hex, size_t out_size)
{
    unsigned char blob[GCM_IV_LEN + GCM_TAG_LEN + CRYPTO_MAX_FIELD_LEN];
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, flen = 0, rc = -1;

    if (key == NULL || aad == NULL || plaintext == NULL || out_hex == NULL) {
        return -1;
    }
    size_t pt_len  = strlen(plaintext);
    size_t aad_len = strlen(aad);
    if (pt_len > CRYPTO_MAX_FIELD_LEN ||
        out_size < CRYPTO_HEX_LEN(pt_len)) {
        return -1;
    }

    unsigned char *iv  = blob;
    unsigned char *tag = blob + GCM_IV_LEN;
    unsigned char *ct  = blob + GCM_IV_LEN + GCM_TAG_LEN;

    if (crypto_random_bytes(iv, GCM_IV_LEN) != 0) {
        return -1;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -1;
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1 ||
        EVP_EncryptUpdate(ctx, NULL, &len, (const unsigned char *)aad,
                          (int)aad_len) != 1 ||
        EVP_EncryptUpdate(ctx, ct, &len, (const unsigned char *)plaintext,
                          (int)pt_len) != 1) {
        goto done;
    }
    if (EVP_EncryptFinal_ex(ctx, ct + len, &flen) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag) != 1) {
        goto done;
    }

    rc = crypto_hex_encode(blob, GCM_IV_LEN + GCM_TAG_LEN + pt_len,
                           out_hex, out_size);

done:
    EVP_CIPHER_CTX_free(ctx);
    crypto_wipe(blob, sizeof(blob));
    return rc;
}

int crypto_decrypt(const unsigned char key[CRYPTO_KEY_LEN],
                   const char *aad,
                   const char *in_hex,
                   char *out, size_t out_size)
{
    unsigned char blob[GCM_IV_LEN + GCM_TAG_LEN + CRYPTO_MAX_FIELD_LEN];
    EVP_CIPHER_CTX *ctx = NULL;
    size_t blob_len = 0;
    int len = 0, flen = 0, rc = -1;

    if (key == NULL || aad == NULL || in_hex == NULL || out == NULL ||
        out_size == 0) {
        return -1;
    }
    out[0] = '\0';

    if (crypto_hex_decode(in_hex, blob, sizeof(blob), &blob_len) != 0 ||
        blob_len < GCM_IV_LEN + GCM_TAG_LEN) {
        return -1;
    }
    size_t pt_len = blob_len - GCM_IV_LEN - GCM_TAG_LEN;
    if (out_size < pt_len + 1) {
        crypto_wipe(blob, sizeof(blob));
        return -1;
    }

    unsigned char *iv  = blob;
    unsigned char *tag = blob + GCM_IV_LEN;
    unsigned char *ct  = blob + GCM_IV_LEN + GCM_TAG_LEN;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        crypto_wipe(blob, sizeof(blob));
        return -1;
    }
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1 ||
        EVP_DecryptUpdate(ctx, NULL, &len, (const unsigned char *)aad,
                          (int)strlen(aad)) != 1 ||
        EVP_DecryptUpdate(ctx, (unsigned char *)out, &len, ct,
                          (int)pt_len) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag) != 1) {
        goto done;
    }
    
    if (EVP_DecryptFinal_ex(ctx, (unsigned char *)out + len, &flen) <= 0) {
        goto done;
    }

    out[pt_len] = '\0';
    rc = 0;

done:
    if (rc != 0) {
        crypto_wipe(out, out_size);
    }
    EVP_CIPHER_CTX_free(ctx);
    crypto_wipe(blob, sizeof(blob));
    return rc;
}