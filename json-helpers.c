// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#include <jsmn/jsmn.h>
#include <openssl/crypto.h>

#include "compiler.h"
#include "json-helpers.h"

int json_skip(int num_tokens, jsmntok_t *tokens, int idx)
{
        int left = idx, right = num_tokens;
        int endpos = tokens[idx].end;

        while (left < idx + 3) {
                left++;
                if (left >= num_tokens || tokens[left].start >= endpos)
                        return left;
        }

        while (left < right) {
                int mid = (left + right) / 2;
                jsmntok_t *tok = &tokens[mid];

                if (tok->start < endpos)
                        left = mid + 1;
                else
                        right = mid;
        }
        return left;
}

void json_init(struct json *json)
{
        jsmn_init(&json->parser);
        json->buf_pos = 0;
}

static int __json_alloc(struct json *json, int num_toks, size_t buf_size)
{
        json->tokens = malloc(sizeof(jsmntok_t) * num_toks);
        if (!json->tokens) {
                fprintf(stderr, "%s: OOM\n", __func__);
                return -1;
        }
        json->num_tokens = num_toks;
        if (buf_size == 0) {
                json->buf = NULL;
        } else {
                json->buf = malloc(buf_size);
                if (!json->buf) {
                        free(json->tokens);
                        fprintf(stderr, "%s: OOM\n", __func__);
                        return -1;
                }
        }
        json->buf_pos = 0;
        json->buf_size = buf_size;
        jsmn_init(&json->parser);
        return 0;
}

int json_alloc(struct json *json) { return __json_alloc(json, 500, 0); }

void json_free(struct json *json)
{
        free(json->buf);
        free(json->tokens);
}

static int json_buf_ensure_append(struct json *json, size_t extra)
{
        if (extra + json->buf_pos <= json->buf_size)
                return 0;
        size_t new_sz = 2 * (extra + json->buf_pos);
        char *buf = realloc(json->buf, new_sz);
        if (!buf) {
                fprintf(stderr, "%s: OOM\n", __func__);
                return -ENOMEM;
        }
        json->buf = buf;
        json->buf_size = new_sz;
        return 0;
}

static int json_buf_add(struct json *json, char *in, size_t len)
{
        int ret = json_buf_ensure_append(json, len);
        if (ret)
                return ret;
        memcpy(json->buf + json->buf_pos, in, len);
        json->buf_pos += len;
        return 0;
}

static int __json_parse(struct json *j, char *data, size_t data_len,
                        int *ret_numtoks)
{
        int numtoks;
        while ((numtoks = jsmn_parse(&j->parser, data, data_len, j->tokens,
                                     j->num_tokens)) == JSMN_ERROR_NOMEM) {
                int n = 2 * j->num_tokens;
                jsmntok_t *toks = realloc(j->tokens, n * sizeof(jsmntok_t));
                if (!toks) {
                        fprintf(stderr, "%s: OOM\n", __func__);
                        return -ENOMEM;
                }
                j->tokens = toks;
                j->num_tokens = n;
        }
        *ret_numtoks = numtoks;
        return 0;
}

int json_parse(struct json *j, char *in, size_t len, char **json,
               size_t *json_len)
{
        char *data = in;
        size_t data_len = len;

        if (j->buf_pos > 0) {
                if (json_buf_add(j, in, len))
                        return -ENOMEM;
                data = j->buf;
                data_len = j->buf_pos;
        }

        int numtoks;
        int ret = __json_parse(j, data, data_len, &numtoks);
        if (ret)
                return ret;

        if (numtoks == JSMN_ERROR_PART) {
                if (j->buf_pos == 0)
                        return json_buf_add(j, in, len);
                return 0;
        }
        *json = data;
        *json_len = data_len;
        if (unlikely(numtoks < 0))
                return -EINVAL;
        json_init(j);
        return numtoks;
}

static void json_read_buf(struct json *json, char **buf, size_t *size)
{
        *buf = &json->buf[json->buf_pos];
        *size = json->buf_size - json->buf_pos;
}

int json_from_file(const char *path, char **ret_json, int *ret_num_toks,
                   jsmntok_t **ret_toks)
{
        const char *problem = "";
        struct json json = {};
        char *buf = NULL;

        FILE *file = fopen(path, "r");
        if (!file) {
                fprintf(stderr, "could not open %s\n", path);
                return -1;
        }

        if (__json_alloc(&json, 5, 1024))
                goto out_err;

        while (1) {
                if (json_buf_ensure_append(&json, 5))
                        goto out_err;

                char *buf;
                size_t buf_len;
                json_read_buf(&json, &buf, &buf_len);
                size_t n = fread(buf, 1, buf_len, file);

                if (n < 1) {
                        if (ferror(file))
                                problem = "fread() error";
                        else
                                problem = "read only incomplete JSON";
                        goto out_err;
                }
                json.buf_pos += n;

                int num_toks;
                if (__json_parse(&json, json.buf, json.buf_pos, &num_toks))
                        return -1;
                if (num_toks > 0) {
                        fclose(file);
                        *ret_json = json.buf;
                        *ret_num_toks = num_toks;
                        *ret_toks = json.tokens;
                        return json.buf_pos;
                } else if (num_toks == JSMN_ERROR_NOMEM) {
                        problem = "internal error";
                        goto out_err;
                } else if (num_toks == JSMN_ERROR_INVAL) {
                        problem = "invalid JSON";
                        goto out_err;
                }
        }

out_err:
        fprintf(stderr, "Failed parsing JSON from %s: %s\n", path, problem);
        fclose(file);
        free(buf);
        if (json.buf_pos > 0)
                OPENSSL_cleanse(json.buf, json.buf_pos);
        json_free(&json);
        return -1;
}
