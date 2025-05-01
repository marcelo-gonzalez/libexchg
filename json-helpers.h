// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#ifndef JSON_HELPERS_H
#define JSON_HELPERS_H

#include <errno.h>
#include <jsmn/jsmn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "exchg/currency.h"
#include "exchg/decimal.h"

// NOTE!! the json_get* type functions call strtol,strtoll,etc on a
// presumably non null-terminated string. So this is only safe if the
// input has already been parsed AND the result is not a single JSON
// primitive token (e.g. the whole input string is just "123"), since
// in that case should be impossible for strtol not to terminate by
// the end of the token

static inline bool __json_streq(const char *json, jsmntok_t *tok, const char *s)
{
        if (strncmp(json + tok->start, s, tok->end - tok->start))
                return false;
        return !s[tok->end - tok->start];
}

static inline bool json_streq(const char *json, jsmntok_t *tok, const char *s)
{
        if (tok->type != JSMN_STRING)
                return false;
        return __json_streq(json, tok, s);
}

static inline bool json_tok_streq(const char *json, jsmntok_t *t, jsmntok_t *s)
{
        if (t->type != JSMN_STRING || s->type != JSMN_STRING)
                return false;
        int len = t->end - t->start;
        if (s->end - s->start != len)
                return false;
        return !memcmp(&json[t->start], &json[s->start], len);
}

static inline int json_get_bool(bool *dst, const char *json, jsmntok_t *tok)
{
        if (tok->type != JSMN_PRIMITIVE && tok->type != JSMN_STRING)
                return -1;

        if (__json_streq(json, tok, "true")) {
                *dst = true;
                return 0;
        }
        if (__json_streq(json, tok, "false")) {
                *dst = false;
                return 0;
        }
        return -1;
}

static inline int json_get_int(int *dst, const char *json, jsmntok_t *tok)
{
        if (tok->type != JSMN_PRIMITIVE && tok->type != JSMN_STRING)
                return -1;

        char *end;
        int x = strtol(&json[tok->start], &end, 0);
        if (!*end) {
                *dst = x;
                return 0;
        }
        if (end - &json[tok->start] < tok->end - tok->start)
                return -1;
        *dst = x;
        return 0;
}

static inline int json_get_uint(unsigned int *dst, const char *json,
                                jsmntok_t *tok)
{
        return json_get_int((int *)dst, json, tok);
}

static inline int json_get_int64(int64_t *dst, const char *json, jsmntok_t *tok)
{
        if (tok->type != JSMN_PRIMITIVE && tok->type != JSMN_STRING)
                return -1;

        char *end;
        int64_t x = strtoll(&json[tok->start], &end, 0);
        if (!*end) {
                *dst = x;
                return 0;
        }
        if (end - &json[tok->start] < tok->end - tok->start)
                return -1;
        *dst = x;
        return 0;
}

static inline int json_get_currency(enum exchg_currency *dst, const char *json,
                                    jsmntok_t *tok)
{
        return exchg_strn_to_ccy(dst, &json[tok->start], tok->end - tok->start);
}

static inline int json_get_pair(enum exchg_pair *dst, const char *json,
                                jsmntok_t *tok)
{
        return exchg_strn_to_pair(dst, &json[tok->start],
                                  tok->end - tok->start);
}

static inline int json_get_decimal(decimal_t *dst, const char *json,
                                   jsmntok_t *tok)
{
        if (tok->type != JSMN_PRIMITIVE && tok->type != JSMN_STRING)
                return -1;

        return decimal_from_str_n(dst, &json[tok->start],
                                  tok->end - tok->start);
}

static inline void json_strncpy(char *dst, const char *json, jsmntok_t *tok,
                                size_t len)
{
        size_t sz = tok->end - tok->start;
        if (sz + 1 > len)
                sz = len - 1;
        memcpy(dst, &json[tok->start], sz);
        dst[sz] = 0;
}

static inline int json_strdup(char **dst, const char *json, jsmntok_t *tok)
{
        if (tok->type != JSMN_STRING)
                return -EINVAL;
        size_t len = tok->end - tok->start;
        char *c = malloc(len + 1);
        if (!c)
                return -ENOMEM;
        memcpy(c, &json[tok->start], len);
        c[len] = 0;
        *dst = c;
        return len;
}

static inline int json_fprintln(FILE *f, const char *json, jsmntok_t *tok)
{
        int n = fwrite(&json[tok->start], 1, tok->end - tok->start, f);
        if (n == tok->end - tok->start)
                return n + fputc('\n', f) == EOF ? 0 : 1;
        return n;
}

int json_skip(int num_tokens, jsmntok_t *tokens, int idx);

struct json {
        jsmn_parser parser;
        jsmntok_t *tokens;
        int num_tokens;
        char *buf;
        int buf_size;
        int buf_pos;
};

int json_alloc(struct json *json);
void json_free(struct json *json);

void json_init(struct json *json);

int json_parse(struct json *j, char *in, size_t len, char **json,
               size_t *json_len);

/* static inline int json_sprintf(char *dst, const char *json, ...) { */

/* } */

#endif
