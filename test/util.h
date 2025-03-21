// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#ifndef TEST_UTIL_H
#define TEST_UTIL_H

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <exchg/exchg.h>

#include "buf.h"

static inline unsigned char *xdupwithnull(const unsigned char *buf, size_t len)
{
        unsigned char *dup = malloc(len + 1);
        if (!dup) {
                fprintf(stderr, "%s: OOM\n", __func__);
                exit(1);
        }
        memcpy(dup, buf, len);
        dup[len] = 0;
        return dup;
}

static inline void *xzalloc(size_t s)
{
        void *p = malloc(s);
        if (!p) {
                fprintf(stderr, "OOM\n");
                exit(1);
        }
        memset(p, 0, s);
        return p;
}

static inline void *xzrealloc(void *p, size_t old_size, size_t new_size)
{
        void *q = realloc(p, new_size);
        if (!q) {
                if (new_size == 0)
                        return q;
                fprintf(stderr, "%s: OOM\n", __func__);
                exit(1);
        }
        if (new_size > old_size)
                memset(q + old_size, 0, new_size - old_size);
        return q;
}

static inline char *xstrdup(const char *s)
{
        char *ret = strdup(s);
        if (!ret) {
                fprintf(stderr, "OOM\n");
                exit(1);
        }
        return ret;
}

static inline void write_prices(char *price_str, char *size_str, char *cost_str,
                                char *fee_str, const decimal_t *price,
                                const decimal_t *size, int fee_bps,
                                int decimals)
{
        decimal_t cost, fee;

        decimal_multiply(&cost, size, price);
        decimal_trunc(&cost, &cost, decimals);
        decimal_inc_bps(&fee, &cost, fee_bps, decimals);
        decimal_subtract(&fee, &fee, &cost);

        decimal_to_str(cost_str, &cost);
        decimal_to_str(fee_str, &fee);
        decimal_to_str(price_str, price);
        decimal_to_str(size_str, size);
}

static inline int buf_read_file(struct buf *buf, const char *filename)
{
        FILE *file = fopen(filename, "r");
        if (!file) {
                exchg_log("could not open %s to send on websocket: %s\n",
                          filename, strerror(errno));
                return -1;
        }

        size_t read_len = 1 << 10;
        while (1) {
                buf_xensure_append_size(buf, read_len);
                size_t n = fread(buf_end(buf), 1, read_len, file);
                if (n < 1) {
                        if (ferror(file)) {
                                exchg_log("reading from %s failed\n", filename);
                                fclose(file);
                                return -1;
                        }
                        break;
                }
                buf->len += n;
        }

        if (fclose(file)) {
                exchg_log("error closing %s to send on websocket: %s\n",
                          filename, strerror(errno));
                return -1;
        }
        return 0;
}

#endif
