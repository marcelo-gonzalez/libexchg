// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#ifndef TEST_UTIL_H
#define TEST_UTIL_H

#include <stdlib.h>
#include <string.h>

#include <exchg/decimal.h>

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

#endif
