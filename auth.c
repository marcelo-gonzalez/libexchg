#include <glib.h>
#include <glib/gi18n.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>

#include "auth.h"

static int __base64_encode(char *dst, const unsigned char *in, int len) {
	int state = 0, save = 0;
	int outlen = g_base64_encode_step(in, len, FALSE, dst, &state, &save);
	outlen += g_base64_encode_close(FALSE, dst + outlen, &state, &save);
	dst[outlen] = 0;
	return outlen;
}

int base64_encode(const unsigned char *in, int len, char **dst) {
	char *buf = malloc(BASE64_LEN(len));
	if (!buf) {
		fprintf(stderr, "%s: OOM\n", __func__);
		return -1;
	}
	*dst = buf;
	return  __base64_encode(buf, in, len);
}

static int write_hex(char *dst, const unsigned char *p, size_t len,
		     enum hex_type htype) {
	const char *fmt = htype == HEX_UPPER ? "%02X" : "%02x";
	int ret = 0;
	for (int i = 0; i < len; i++) {
		ret += sprintf(dst+2*i, fmt, p[i]);
	}
	return ret;
}

#define MAX_HMAC_LEN 64

static int do_hmac(HMAC_CTX *ctx, const unsigned char *msg, size_t len,
		   unsigned char *hmac) {
	unsigned int hmac_len;

	if (!HMAC_Update(ctx, msg, len))
		goto out_err;
	if (!HMAC_Final(ctx, hmac, &hmac_len))
		goto out_err;
	return hmac_len;

out_err:
	fprintf(stderr, "HMAC computation failure\n");
	return -1;
}

int hmac_hex(HMAC_CTX *ctx,
	     const unsigned char *msg, size_t len,
	     char *hmac_hex, enum hex_type htype) {
	unsigned char hmac[MAX_HMAC_LEN];
	if (!HMAC_Init_ex(ctx, NULL, 0, NULL, NULL)) {
		fprintf(stderr, "HMAC_Init_ex() failure\n");
		return -1;
	}
	int hlen = do_hmac(ctx, msg, len, hmac);
	if (hlen < 0)
		return hlen;
	return write_hex(hmac_hex, hmac, hlen, htype);
}

int hmac_b64(HMAC_CTX *ctx,
	     const unsigned char *msg, size_t len,
	     char *hmac_b64) {
	unsigned char hmac[MAX_HMAC_LEN];
	if (!HMAC_Init_ex(ctx, NULL, 0, NULL, NULL)) {
		fprintf(stderr, "HMAC_Init_ex() failure\n");
		return -1;
	}
	int hlen = do_hmac(ctx, msg, len, hmac);
	if (hlen < 0)
		return hlen;
	return __base64_encode(hmac_b64, hmac, hlen);
}
