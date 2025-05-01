// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Marcelo Diop-Gonzalez

#ifndef B64_H
#define B64_H

#include <glib.h>
#include <stdlib.h>

#define BASE64_LEN(len) ((len / 3 + 1) * 4 + 4)

static inline size_t __base64_encode(char *dst, const unsigned char *in,
                                     int len)
{
        int state = 0, save = 0;
        size_t outlen =
            g_base64_encode_step(in, len, FALSE, dst, &state, &save);
        outlen += g_base64_encode_close(FALSE, dst + outlen, &state, &save);
        dst[outlen] = 0;
        return outlen;
}

static inline size_t base64_encode(const unsigned char *in, size_t len,
                                   char **dst)
{
        char *buf = malloc(BASE64_LEN(len));
        if (!buf) {
                fprintf(stderr, "%s: OOM\n", __func__);
                return -1;
        }
        *dst = buf;
        return __base64_encode(buf, in, len);
}

static inline int base64_decode(const unsigned char *in, int len,
                                unsigned char **decoded)
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

struct b64_state {
        int state;
        int save;
        size_t len;
        size_t cap;
        char *encoding;
};

static inline int b64_init(struct b64_state *state, size_t len)
{
        len = BASE64_LEN(len);
        state->encoding = malloc(len);
        if (!state->encoding) {
                fprintf(stderr, "%s: OOM (size %zu)\n", __func__, len);
                return -1;
        }
        state->state = 0;
        state->save = 0;
        state->len = 0;
        state->cap = len;
        return 0;
}

static inline int b64_ensure_size(struct b64_state *state, size_t added_len)
{
        if (added_len + state->len > state->cap) {
                size_t new_cap = 2 * added_len + state->len;
                char *encoding = realloc(state->encoding, new_cap);
                if (!encoding) {
                        fprintf(stderr, "%s: OOM (size %zu)\n", __func__,
                                new_cap);
                        return -1;
                }
                state->encoding = encoding;
                state->cap = new_cap;
        }
        return 0;
}

static inline int b64_step(struct b64_state *state, const unsigned char *in,
                           size_t len)
{
        if (b64_ensure_size(state, BASE64_LEN(len)))
                return -1;
        size_t outlen =
            g_base64_encode_step(in, len, FALSE, &state->encoding[state->len],
                                 &state->state, &state->save);
        state->len += outlen;
        return 0;
}

static inline int b64url_step(struct b64_state *state, const unsigned char *in,
                              size_t len)
{
        size_t start_len = state->len;
        if (b64_step(state, in, len))
                return -1;
        for (size_t p = start_len; p < state->len; p++) {
                if (state->encoding[p] == '+')
                        state->encoding[p] = '-';
                else if (state->encoding[p] == '/')
                        state->encoding[p] = '_';
        }
        return 0;
}

static inline int b64_close(struct b64_state *state)
{
        if (b64_ensure_size(state, 5))
                return -1;
        size_t outlen = g_base64_encode_close(
            FALSE, &state->encoding[state->len], &state->state, &state->save);
        state->len += outlen;
        state->encoding[state->len] = 0;
        return 0;
}

static inline int b64url_close(struct b64_state *state)
{
        size_t start_len = state->len;
        if (b64_close(state))
                return -1;
        for (size_t p = start_len; p < state->len; p++) {
                if (state->encoding[p] == '=') {
                        state->encoding[p] = 0;
                        state->len = p;
                        return 0;
                }
                if (state->encoding[p] == '+')
                        state->encoding[p] = '-';
                else if (state->encoding[p] == '/')
                        state->encoding[p] = '_';
        }
        return 0;
}

// b64url_close() must have been called first if step() has been called
static inline int b64_putc(struct b64_state *state, char c)
{
        if (b64_ensure_size(state, 1))
                return -1;
        state->encoding[state->len] = c;
        state->len++;
        return 0;
}

// b64url_close() must have been called first if step() has been called
static inline int b64_puts(struct b64_state *state, const char *s)
{
        size_t len = strlen(s);
        if (b64_ensure_size(state, len))
                return -1;
        memcpy(&state->encoding[state->len], s, len);
        state->len += len;
        return 0;
}

#endif
