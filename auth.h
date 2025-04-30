// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#ifndef AUTH_H
#define AUTH_H

#include <openssl/evp.h>
#include <stdint.h>

#define BASE64_LEN(len) ((len / 3 + 1) * 4 + 4)

size_t base64_encode(const unsigned char *in, size_t len, char **encoded);
int base64_decode(const unsigned char *in, int len, unsigned char **decoded);

// make this an enum that also covers b64 and then have one hmac func
enum hex_type {
        HEX_UPPER,
        HEX_LOWER,
};

#define HMAC_SHA512_B64_LEN BASE64_LEN(64)
#define HMAC_SHA256_B64_LEN BASE64_LEN(32)
#define HMAC_SHA384_HEX_LEN (96 + 1)
#define HMAC_SHA256_HEX_LEN (64 + 1)

#define HMAC_TEXT_LEN_MAX HMAC_SHA384_HEX_LEN

struct hmac_ctx {
        EVP_MAC *mac;
        EVP_MAC_CTX *ctx;
};

int hmac_ctx_alloc(struct hmac_ctx *ctx, const char *digest);
int hmac_ctx_setkey(struct hmac_ctx *ctx, const unsigned char *key,
                    size_t keylen);
void hmac_ctx_free(struct hmac_ctx *ctx);

int hmac_ctx_hex(struct hmac_ctx *ctx, const unsigned char *msg, size_t len,
                 char *hmac_hex, size_t *hmac_hex_len, enum hex_type htype);
int hmac_ctx_b64(struct hmac_ctx *ctx, const unsigned char *msg, size_t len,
                 char *hmac_b64, size_t *hmac_b64_len);

#endif
