// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#include <glib.h>
#include <glib/gi18n.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <stdio.h>
#include <stdlib.h>

#include "auth.h"
#include "compiler.h"

int hmac_ctx_alloc(struct hmac_ctx *h, const char *digest)
{
        EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
        if (!mac) {
                fprintf(stderr, "failed fetching \"HMAC\" EVP_MAC\n");
                ERR_print_errors_fp(stderr);
                return -1;
        }
        EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
        if (!ctx) {
                fprintf(stderr, "EVP_MAC_CTX_new() failed\n");
                ERR_print_errors_fp(stderr);
                EVP_MAC_free(mac);
                return -1;
        }

        OSSL_PARAM params[2];
        params[0] =
            OSSL_PARAM_construct_utf8_string("digest", (char *)digest, 0);
        params[1] = OSSL_PARAM_construct_end();

        if (!EVP_MAC_CTX_set_params(ctx, params)) {
                fprintf(stderr, "EVP_MAC_CTX_set_params() failed\n");
                ERR_print_errors_fp(stderr);
                EVP_MAC_free(mac);
                EVP_MAC_CTX_free(ctx);
                return -1;
        }

        h->mac = mac;
        h->ctx = ctx;
        return 0;
}

int hmac_ctx_setkey(struct hmac_ctx *ctx, const unsigned char *key,
                    size_t keylen)
{
        if (!EVP_MAC_init(ctx->ctx, key, keylen, NULL)) {
                fprintf(stderr, "EVP_MAC_init() with keylen %zu failed\n",
                        keylen);
                ERR_print_errors_fp(stderr);
                return -1;
        }
        return 0;
}

void hmac_ctx_free(struct hmac_ctx *ctx)
{
        EVP_MAC_free(ctx->mac);
        EVP_MAC_CTX_free(ctx->ctx);
}

// TODO: why is base64 stuff in auth.c?

static size_t __base64_encode(char *dst, const unsigned char *in, int len)
{
        int state = 0, save = 0;
        size_t outlen =
            g_base64_encode_step(in, len, FALSE, dst, &state, &save);
        outlen += g_base64_encode_close(FALSE, dst + outlen, &state, &save);
        dst[outlen] = 0;
        return outlen;
}

size_t base64_encode(const unsigned char *in, size_t len, char **dst)
{
        char *buf = malloc(BASE64_LEN(len));
        if (!buf) {
                fprintf(stderr, "%s: OOM\n", __func__);
                return -1;
        }
        *dst = buf;
        return __base64_encode(buf, in, len);
}

int base64_decode(const unsigned char *in, int len, unsigned char **decoded)
{
        unsigned char *c = malloc((len / 4) * 3 + 3);
        if (!c) {
                fprintf(stderr, "%s: OOM\n", __func__);
                return -1;
        }
        int state = 0;
        unsigned int save = 0;
        len = g_base64_decode_step((char *)in, len, c, &state, &save);
        if (len == 0) {
                free(c);
                fprintf(stderr, "base64_decode failure\n");
                return -1;
        }
        *decoded = c;
        return len;
}

static size_t write_hex(char *dst, size_t dst_len, const unsigned char *p,
                        size_t len, enum hex_type htype)
{
        const char *fmt = htype == HEX_UPPER ? "%02X" : "%02x";
        size_t hex_len = 0;
        for (int i = 0; i < len; i++) {
                int n = snprintf(dst + hex_len, dst_len - hex_len, fmt, p[i]);
                if (unlikely(hex_len + n >= dst_len)) {
                        fprintf(stderr, "%s: buffer length %zu too small\n",
                                __func__, dst_len);
                        return -1;
                }
                hex_len += n;
        }
        return hex_len;
}

#define MAX_HMAC_LEN 64

static size_t hmac_ctx_mac(struct hmac_ctx *ctx, const unsigned char *msg,
                           size_t len, unsigned char *hmac, size_t *hmac_len,
                           size_t hmac_size)
{
        if (!EVP_MAC_init(ctx->ctx, NULL, 0, NULL)) {
                fprintf(stderr, "EVP_MAC_init() failure\n");
                ERR_print_errors_fp(stderr);
                return -1;
        }
        if (!EVP_MAC_update(ctx->ctx, msg, len)) {
                fprintf(stderr, "EVP_MAC_update() failure\n");
                ERR_print_errors_fp(stderr);
                return -1;
        }
        if (!EVP_MAC_final(ctx->ctx, hmac, hmac_len, hmac_size)) {
                fprintf(stderr, "EVP_MAC_final() failure\n");
                ERR_print_errors_fp(stderr);
                return -1;
        }
        return 0;
}

int hmac_ctx_hex(struct hmac_ctx *ctx, const unsigned char *msg, size_t len,
                 char *hmac_hex, size_t hmac_hex_buf_len, size_t *hmac_hex_len,
                 enum hex_type htype)
{
        unsigned char hmac[MAX_HMAC_LEN];
        size_t hmac_len;
        if (hmac_ctx_mac(ctx, msg, len, hmac, &hmac_len, sizeof(hmac)))
                return -1;
        *hmac_hex_len =
            write_hex(hmac_hex, hmac_hex_buf_len, hmac, hmac_len, htype);
        return 0;
}

int hmac_ctx_b64(struct hmac_ctx *ctx, const unsigned char *msg, size_t len,
                 char *hmac_b64, size_t *hmac_b64_len)
{
        unsigned char hmac[MAX_HMAC_LEN];
        size_t hmac_len;
        if (hmac_ctx_mac(ctx, msg, len, hmac, &hmac_len, sizeof(hmac)))
                return -1;
        *hmac_b64_len = __base64_encode(hmac_b64, hmac, hmac_len);
        return 0;
}
