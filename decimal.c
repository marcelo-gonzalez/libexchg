// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "exchg/decimal.h"

#include "compiler.h"

#define ARRAY_SIZE(x) sizeof(x) / sizeof(*x)

// TODO: check for overflow more robustly thoughout

const static int64_t tens[] = {
    1LL,
    10LL,
    100LL,
    1000LL,
    10000LL,
    100000LL,
    1000000LL,
    10000000LL,
    100000000LL,
    1000000000LL,
    10000000000LL,
    100000000000LL,
    1000000000000LL,
    10000000000000LL,
    100000000000000LL,
    1000000000000000LL,
    10000000000000000LL,
    100000000000000000LL,
    1000000000000000000LL,
};

static int int64_cmp(const int64_t *a, const int64_t *b)
{
        if (*a < *b)
                return -1;
        if (*a > *b)
                return 1;
        return 0;
}

int decimal_cmp(const decimal_t *a, const decimal_t *b)
{
        if (a->places == b->places)
                return int64_cmp(&a->value, &b->value);
        if (a->places < b->places) {
                int64_t x = a->value * tens[(b->places - a->places)];
                return int64_cmp(&x, &b->value);
        }
        int64_t x = b->value * tens[(a->places - b->places)];
        return int64_cmp(&a->value, &x);
}

void decimal_add(decimal_t *dst, const decimal_t *a, const decimal_t *b)
{
        if (b->places > a->places) {
                dst->value = b->value + a->value * tens[b->places - a->places];
                dst->places = b->places;
        } else {
                dst->value = a->value + b->value * tens[a->places - b->places];
                dst->places = a->places;
        }
}

void decimal_subtract(decimal_t *dst, const decimal_t *a, const decimal_t *b)
{
        if (b->places > a->places) {
                dst->value = a->value * tens[b->places - a->places] - b->value;
                dst->places = b->places;
        } else {
                dst->value = a->value - b->value * tens[a->places - b->places];
                dst->places = a->places;
        }
}

void decimal_subtract_inplace(decimal_t *dst, const decimal_t *sub)
{
        decimal_subtract(dst, dst, sub);
}

void decimal_add_inplace(decimal_t *dst, const decimal_t *inc)
{
        decimal_add(dst, dst, inc);
}

static void decimal_multiply_slow(decimal_t *dst, const decimal_t *a,
                                  const decimal_t *b)
{
        decimal_t x = *a;
        decimal_t y = *b;

        // TODO: kill some precision when zeros can't be removed
        while (x.value % 10 == 0 && x.places > 0) {
                x.value /= 10;
                x.places--;
        }
        while (y.value % 10 == 0 && y.places > 0) {
                y.value /= 10;
                y.places--;
        }
        dst->value = x.value * y.value;
        dst->places = x.places + y.places;
}

// TODO: allow dst == a
void decimal_multiply(decimal_t *dst, const decimal_t *a, const decimal_t *b)
{
        if (a->places + b->places >= 19) {
                char x[30], y[30];
                decimal_to_str(x, a);
                decimal_to_str(y, b);
                fprintf(stderr, "multiplication overflow \"%s\" * \"%s\"\n", x,
                        y);
        }
        dst->value = a->value * b->value;
        // TODO fix
        if (a->value != 0 && dst->value / a->value != b->value)
                return decimal_multiply_slow(dst, a, b);
        dst->places = a->places + b->places;
        while (dst->places > 0 && dst->value % 10 == 0) {
                dst->value /= 10;
                dst->places--;
        }
}

void decimal_divide(decimal_t *dst, const decimal_t *a, const decimal_t *b,
                    int places)
{
        char s[30], t[30];
        int b_places = b->places;
        int64_t b_value = b->value;

        while (b_value % 10 == 0 && b_places > 0) {
                b_places--;
                b_value /= 10;
        }

        int pow = places + b_places - a->places;
        if (pow < 0) {
                b_places -= pow;
                b_value *= tens[-pow];
                pow = 0;
        }
        while (pow >= ARRAY_SIZE(tens) && places > 0) {
                places--;
                pow--;
        }
        if (pow >= ARRAY_SIZE(tens)) {
                // TODO: dec a->places
                goto overflow;
        }

        while (a->value > LLONG_MAX / tens[pow] && pow > 0) {
                if (places == 0)
                        goto overflow;
                pow--;
                places--;
        }
        dst->value = (a->value * tens[pow]) / b_value;
        dst->places = places;
        return;

overflow:
        decimal_to_str(s, a);
        decimal_to_str(t, b);
        fprintf(stderr, "%s: overflow: %s / %s\n", __func__, s, t);
        *dst = *a;
}

int decimal_to_str(char *dst, const decimal_t *number)
{
        int ret = snprintf(dst, 22, "%" PRId64, number->value);
        if (unlikely(ret >= 22)) {
                fprintf(stderr, "%s: snprintf of int64_t returned %d???\n",
                        __func__, ret);
                exit(1);
        }
        int n;
        if (number->value < 0) {
                dst++;
                n = ret - 1;
        } else {
                n = ret;
        }
        if (n <= number->places) {
                memmove(dst + number->places + 2 - n, dst, n + 1);
                dst[0] = '0';
                dst[1] = '.';
                for (int i = 0; i < number->places - n; i++)
                        dst[i + 2] = '0';
                return ret + 2 + number->places - n;
        }
        memmove(dst + n - number->places + 1, dst + n - number->places,
                number->places + 1);
        if (number->places > 0) {
                dst[n - number->places] = '.';
                return ret + 1;
        }
        return ret;
}

int decimal_from_str(decimal_t *dst, const char *str)
{
        char *end;
        int64_t v = strtoll(str, &end, 10);
        if (!*end) {
                dst->places = 0;
                dst->value = v;
                return 0;
        }

        if (end[0] != '.' || end[1] == '-')
                return -1;

        int places = strlen(str) - (end - str + 1);
        if (places >= 19)
                goto out_overflow;
        if (v > LLONG_MAX / tens[places])
                goto out_overflow;

        int64_t rest = strtoll(end + 1, &end, 10);
        if (*end)
                return -1;
        if (v == LLONG_MAX / tens[places] && rest > LLONG_MAX % tens[places])
                goto out_overflow;

        dst->places = places;
        if (*str != '-')
                dst->value = v * tens[places] + rest;
        else
                dst->value = -(-v * tens[places] + rest);
        return 0;

out_overflow:
        fprintf(stderr, "decimal overflow: %s\n", str);
        return -1;
}

int decimal_from_str_n(decimal_t *dst, const char *s, size_t len)
{
        char str[50];
        if (len >= 50) {
                fprintf(stderr, "FIXME: %s(%zu)\n", __func__, len);
                return -1;
        }
        // TODO: consider doing what you gotta do to not copy
        memcpy(str, s, len);
        str[len] = 0;

        return decimal_from_str(dst, str);
}

int64_t decimal_to_fractional(const decimal_t *x, int places)
{
        if (places < x->places)
                return x->value / tens[x->places - places];
        if (places - x->places > ARRAY_SIZE(tens)) {
                fprintf(stderr, "%s: overflow\n", __func__);
                return 0;
        }
        return x->value * tens[places - x->places];
}

static void decimal_mult_int(decimal_t *dst, const decimal_t *d, int x,
                             int x_places, int decimal_places, int round_up)
{
        dst->places = d->places;
        if (x == 0 || d->value == 0) {
                dst->value = 0;
                return;
        }

        int64_t value = d->value;
        while (x % 10 == 0 && x_places > 0) {
                x_places--;
                x /= 10;
        }
        while (value % 10 == 0 && dst->places > 0) {
                dst->places--;
                value /= 10;
        }

        while (value > LLONG_MAX / x) {
                if (dst->places == 0) {
                        char s[30];
                        decimal_to_str(s, d);
                        fprintf(stderr, "%s: overflow: %s x %d\n", __func__, s,
                                x);
                        *dst = *d;
                        return;
                }
                value /= 10;
                dst->places--;
        }

        dst->places += x_places;
        dst->value = value * x;
        if (decimal_places < 0 || dst->places < decimal_places)
                return;

        int diff = dst->places - decimal_places;
        dst->places = decimal_places;
        if (round_up)
                dst->value = (dst->value + tens[diff] - 1) / tens[diff];
        else
                dst->value /= tens[diff];
}

void decimal_inc_bps(decimal_t *dst, const decimal_t *d, int bps, int places)
{
        return decimal_mult_int(dst, d, bps + 10000, 4, places, 1);
}

void decimal_dec_bps(decimal_t *dst, const decimal_t *d, int bps, int places)
{
        return decimal_mult_int(dst, d, 10000 - bps, 4, places, 0);
}

double decimal_to_dbl(const decimal_t *d)
{
        return (double)d->value / (double)tens[d->places];
}

bool decimal_is_zero(const decimal_t *d) { return d->value == 0; }

bool decimal_is_positive(const decimal_t *d) { return d->value > 0; }

bool decimal_is_negative(const decimal_t *d) { return d->value < 0; }

void decimal_zero(decimal_t *d) { memset(d, 0, sizeof(*d)); }

void decimal_trunc(decimal_t *dst, const decimal_t *x, int places)
{
        if (x->places <= places) {
                *dst = *x;
                return;
        }

        int x_places = x->places;

        dst->places = places;
        dst->value = x->value / tens[x_places - places];
}

void decimal_trim(decimal_t *dst, const decimal_t *x, int places)
{
        decimal_t trimmed = *x;

        while (trimmed.places > places && trimmed.value % 10 == 0) {
                trimmed.places--;
                trimmed.value /= 10;
        }
        *dst = trimmed;
}
