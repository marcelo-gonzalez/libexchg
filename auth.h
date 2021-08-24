// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#ifndef AUTH_H
#define AUTH_H

#include <stdint.h>
#include <openssl/hmac.h>

#define BASE64_LEN(len) ((len / 3 + 1) * 4 + 4)

int base64_encode(const unsigned char *in, int len, char **encoded);
int base64_decode(const unsigned char *in, int len, unsigned char **decoded);

enum hex_type {
	HEX_UPPER,
	HEX_LOWER,
};

#define HMAC_SHA512_B64_LEN BASE64_LEN(64)
#define HMAC_SHA384_HEX_LEN (96+1)
#define HMAC_SHA256_HEX_LEN (64+1)

#define HMAC_TEXT_LEN_MAX HMAC_SHA512_B64_LEN

int hmac_hex(HMAC_CTX *ctx,
	     const unsigned char *msg, size_t len,
	     char *hmac_hex, enum hex_type htype);

int hmac_b64(HMAC_CTX *ctx,
	     const unsigned char *msg, size_t len,
	     char *hmac_b64);

#endif
