// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#ifndef EXCHG_DECIMAL_H
#define EXCHG_DECIMAL_H

// TODO: use a proper decimal library and delete all this

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	int places;
	int64_t value;
} decimal_t;

// must be >= 21 bytes long
int decimal_to_str(char *dst, const decimal_t *number);
int decimal_from_str_n(decimal_t *dst, const char *str, size_t len);
int decimal_from_str(decimal_t *dst, const char *str);
int decimal_cmp(const decimal_t *a, const decimal_t *b);
bool decimal_is_zero(const decimal_t *d);
bool decimal_is_positive(const decimal_t *d);
bool decimal_is_negative(const decimal_t *d);
void decimal_add(decimal_t *dst, const decimal_t *a, const decimal_t *b);
void decimal_subtract(decimal_t *dst, const decimal_t *a, const decimal_t *b);
void decimal_zero(decimal_t *d);

void decimal_trunc(decimal_t *dst, const decimal_t *x, int places);
void decimal_trim(decimal_t *dst, const decimal_t *x, int places);
void decimal_add_inplace(decimal_t *dst, const decimal_t *inc);
void decimal_subtract_inplace(decimal_t *dst, const decimal_t *sub);
void decimal_multiply(decimal_t *dst, const decimal_t *a, const decimal_t *b);
void decimal_divide(decimal_t *dst, const decimal_t *a,
		    const decimal_t *b, int places);
double decimal_to_dbl(const decimal_t *d);

void decimal_inc_bps(decimal_t *dst, const decimal_t *d,
		     int bps, int places);
void decimal_dec_bps(decimal_t *dst, const decimal_t *d,
		     int bps, int places);

// must not be called with places > 18
int64_t decimal_to_fractional(const decimal_t *x, int places);

#ifdef __cplusplus
}
#endif

#endif
