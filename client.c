// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#include <glib.h>
#include <jsmn/jsmn.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/queue.h>

#include "auth.h"
#include "buf.h"
#include "client.h"
#include "compiler.h"
#include "exchg/currency.h"
#include "exchg/exchg.h"
#include "net-backend.h"
#include "order-book.h"
#include "time-helpers.h"

#include "exchanges/bitstamp.h"
#include "exchanges/coinbase.h"
#include "exchanges/gemini.h"
#include "exchanges/kraken.h"

struct json {
        jsmn_parser parser;
        jsmntok_t *tokens;
        int num_tokens;
        char *buf;
        int buf_size;
        int buf_pos;
};

struct retry {
        struct timer *timer;
        struct timespec last_connected;
        int seconds_idx;
};

struct websocket {
        char *host;
        char *path;
        struct json json;
        struct exchg_client *cl;
        struct websocket_conn *conn;
        const struct exchg_websocket_ops *ops;
        bool established;
        bool disconnecting;
        struct retry retry;
        LIST_ENTRY(websocket) list;
        char private[];
};

struct http {
        char *host;
        char *path;
        char *method;
        struct buf body;
        struct json json;
        struct exchg_client *cl;
        struct http_conn *conn;
        const struct exchg_http_ops *ops;
        bool print_data;
        bool want_retry;
        struct retry retry;
        LIST_ENTRY(http) list;
        char private[];
};

bool websocket_disconnecting(struct websocket *w) { return w->disconnecting; }

bool websocket_established(struct websocket *w)
{
        if (!w)
                return false;
        return w->established;
}

const char *websocket_host(struct websocket *w) { return w->host; }

const char *websocket_path(struct websocket *w) { return w->path; }

const char *http_method(struct http *h) { return h->method; }

const char *http_host(struct http *h) { return h->host; }

const char *http_path(struct http *h) { return h->path; }

void for_each_websocket(struct exchg_client *cl,
                        int (*func)(struct websocket *w, void *private),
                        void *private)
{
        struct websocket *w;
        LIST_FOREACH(w, &cl->websocket_list, list)
        {
                if (func(w, private))
                        return;
        }
}

static int websocket_buf_write(struct websocket *ws, const char *fmt,
                               va_list ap, int len)
{
        struct buf b;

        if (buf_alloc(&b, len + 1, _net_write_buf_padding))
                return -1;
        len = buf_vsprintf(&b, fmt, ap);
        if (len < 0) {
                buf_free(&b);
                return len;
        }
        len = ws_conn_write(ws->conn, buf_start(&b), b.len);
        buf_free(&b);
        return len;
}

int websocket_printf(struct websocket *ws, const char *fmt, ...)
{
        va_list a, ap;
        int len;
        char buf[1024];

        va_start(ap, fmt);
        va_copy(a, ap);

        // paranoid...
        if (unlikely(_net_write_buf_padding >= sizeof(buf))) {
                len = websocket_buf_write(ws, fmt, ap, 1024);
                va_end(ap);
                va_end(a);
                return len;
        }

        len = vsnprintf(&buf[_net_write_buf_padding],
                        sizeof(buf) - _net_write_buf_padding, fmt, ap);

        if (len < sizeof(buf) - _net_write_buf_padding)
                len =
                    ws_conn_write(ws->conn, &buf[_net_write_buf_padding], len);
        else
                len = websocket_buf_write(ws, fmt, a, len);

        va_end(ap);
        va_end(a);
        return len;
}

static void conn_offline(struct exchg_context *ctx)
{
        ctx->online = false;
        for (enum exchg_id id = 0; id < EXCHG_ALL_EXCHANGES; id++) {
                struct exchg_client *cl = ctx->clients[id];

                if (cl && (!LIST_EMPTY(&cl->websocket_list) ||
                           !LIST_EMPTY(&cl->http_list))) {
                        ctx->online = true;
                        return;
                }
        }
        if (ctx->running) {
                net_stop(ctx->net_context);
                ctx->running = false;
        }
}

static void json_free(struct json *json)
{
        free(json->buf);
        free(json->tokens);
}

static void __http_free(struct http *h)
{
        if (h->ops->on_free)
                h->ops->on_free(h->cl, h);
        json_free(&h->json);
        free(h->method);
        free(h->host);
        free(h->path);
        buf_free(&h->body);
        free(h);
}

static void http_free(struct http *h)
{
        LIST_REMOVE(h, list);
        conn_offline(h->cl->ctx);
        __http_free(h);
}

static void __websocket_free(struct websocket *w)
{
        json_free(&w->json);
        free(w->host);
        free(w->path);
        free(w);
}

static void websocket_free(struct websocket *w)
{
        LIST_REMOVE(w, list);
        conn_offline(w->cl->ctx);
        __websocket_free(w);
}

void websocket_close(struct websocket *w)
{
        w->disconnecting = true;
        if (w->conn) {
                ws_conn_close(w->conn);
        } else if (w->retry.timer) {
                timer_cancel(w->retry.timer);
                websocket_free(w);
        }
        // else { we're inside the on_l2_disconnect() callback }
}

void http_close(struct http *h)
{
        if (h->conn)
                http_conn_close(h->conn);
        else {
                timer_cancel(h->retry.timer);
                http_free(h);
        }
}

#ifndef LIST_FOREACH_SAFE
#define LIST_FOREACH_SAFE(var, head, field, tmp)                               \
        for ((var) = ((head)->lh_first);                                       \
             (var) && ((tmp) = (var)->field.le_next, 1); (var) = (tmp))
#endif

void exchg_teardown(struct exchg_client *cl)
{
        // TODO: add a callback and call it here,
        // send order cancels, etc. Set a bit and
        // look at that bit in the main callback
        struct websocket *w, *wtmp;
        struct http *h, *htmp;

        LIST_FOREACH_SAFE(w, &cl->websocket_list, list, wtmp)
        websocket_close(w);
        LIST_FOREACH_SAFE(h, &cl->http_list, list, htmp)
        http_close(h);
}

static void put_response(char *in, size_t len)
{
        fwrite(in, 1, len, stderr);
        fputc('\n', stderr);
}

static int json_buf_add(struct json *json, char *in, size_t len)
{
        if (len + json->buf_pos > json->buf_size) {
                size_t new_sz = 2 * (len + json->buf_pos);
                char *buf = realloc(json->buf, new_sz);
                if (!buf) {
                        exchg_log("%s: OOM\n", __func__);
                        return -ENOMEM;
                }
                json->buf = buf;
                json->buf_size = new_sz;
        }
        memcpy(json->buf + json->buf_pos, in, len);
        json->buf_pos += len;
        return 0;
}

static void json_init(struct json *json)
{
        jsmn_init(&json->parser);
        json->buf_pos = 0;
}

static int json_parse(struct json *j, char *in, size_t len, char **json,
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
        while ((numtoks = jsmn_parse(&j->parser, data, data_len, j->tokens,
                                     j->num_tokens)) == JSMN_ERROR_NOMEM) {
                int n = 2 * j->num_tokens;
                jsmntok_t *toks = realloc(j->tokens, n * sizeof(jsmntok_t));
                if (!toks) {
                        exchg_log("%s: OOM\n", __func__);
                        return -ENOMEM;
                }
                j->tokens = toks;
                j->num_tokens = n;
        }

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

static void ws_on_error(void *p)
{
        struct websocket *w = p;

        // TODO: websocket_log() and http_log() helpers
        exchg_log("wss://%s%s error\n", w->host, w->path);
        w->established = false;
        w->disconnecting = true;
        if (w->ops->on_disconnect)
                w->ops->on_disconnect(w->cl, w, -1);
        websocket_free(w);
}

static void ws_on_established(void *p)
{
        struct websocket *w = p;

        exchg_log("wss://%s%s established\n", w->host, w->path);
        w->established = true;
        json_init(&w->json);
        if (w->ops->on_conn_established)
                w->ops->on_conn_established(w->cl, w);
}

static int ws_add_headers(void *p, struct websocket_conn *ws)
{
        struct websocket *w = p;
        if (w->ops->add_headers)
                return w->ops->add_headers(w->cl, w);
        return 0;
}

static int ws_recv(void *p, char *in, size_t len)
{
        struct websocket *w = p;
        char *json;
        size_t json_len;
        int numtoks = json_parse(&w->json, in, len, &json, &json_len);

        if (numtoks < 0) {
                if (numtoks == -EINVAL) {
                        exchg_log(
                            "%s%s sent data that doesn't parse as JSON:\n",
                            w->host, w->path);
                        put_response(json, json_len);
                }
                return -1;
        }
        if (numtoks == 0)
                return 0;

        // TODO: return code that says whether to try reconnecting or not
        if (w->ops->recv(w->cl, w, json, numtoks, w->json.tokens)) {
                w->disconnecting = true;
                return -1;
        }
        return 0;
}

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*x))

static const int _retry_seconds[] = {0, 1, 3, 10, 60, 300};

static int retry_seconds(struct retry *r)
{
        return _retry_seconds[r->seconds_idx];
}

static void time_since(struct timespec *dst, const struct timespec *ts)
{
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);

        time_t carry = now.tv_nsec < ts->tv_nsec ? 1 : 0;
        dst->tv_nsec = now.tv_nsec - ts->tv_nsec;
        if (carry)
                dst->tv_nsec += 1000000000;
        dst->tv_sec = now.tv_sec - ts->tv_sec - carry;
}

static inline void retry_connected(struct retry *r)
{
        int last_idx = ARRAY_SIZE(_retry_seconds) - 1;
        struct timespec since_last_connected;

        time_since(&since_last_connected, &r->last_connected);
        if (since_last_connected.tv_sec > _retry_seconds[last_idx])
                r->seconds_idx = 0;
        else if (r->seconds_idx < last_idx)
                r->seconds_idx++;
        clock_gettime(CLOCK_MONOTONIC, &r->last_connected);
}

static inline int ws_retry_seconds(struct websocket *w)
{
        if (w->disconnecting)
                return -1;

        return retry_seconds(&w->retry);
}

static void ws_reconnect(struct websocket *w);

static void ws_retry_timer(void *p)
{
        struct websocket *w = p;

        w->retry.timer = NULL;
        ws_reconnect(w);
}

static void ws_add_retry_timer(struct websocket *w)
{
        w->retry.timer = timer_new(w->cl->ctx->net_context, ws_retry_timer, w,
                                   retry_seconds(&w->retry));
}

void exchg_data_disconnect(struct exchg_client *cl, struct websocket *w,
                           int num_pairs_gone, enum exchg_pair *pairs_gone)
{
        if (cl->ctx->callbacks.on_l2_disconnect)
                cl->ctx->callbacks.on_l2_disconnect(cl, ws_retry_seconds(w),
                                                    num_pairs_gone, pairs_gone,
                                                    cl->ctx->user);
}

static void ws_reconnect(struct websocket *w)
{
        do {
                retry_connected(&w->retry);
                w->conn = ws_dial(w->cl->ctx->net_context, w->host, w->path, w);
                if (w->conn)
                        return;
        } while (retry_seconds(&w->retry) == 0);

        ws_add_retry_timer(w);
}

static void ws_on_closed(void *p)
{
        struct websocket *w = p;

        w->established = false;
        w->conn = NULL;

        if (w->ops->on_disconnect &&
            w->ops->on_disconnect(w->cl, w, ws_retry_seconds(w)))
                w->disconnecting = true;

        if (!w->disconnecting) {
                if (retry_seconds(&w->retry) == 0) {
                        exchg_log("wss://%s%s closed. Reconnecting now\n",
                                  w->host, w->path);
                        ws_reconnect(w);
                } else {
                        exchg_log(
                            "wss://%s%s closed. Reconnecting in %d second%s\n",
                            w->host, w->path, retry_seconds(&w->retry),
                            retry_seconds(&w->retry) > 1 ? "s" : "");
                        ws_add_retry_timer(w);
                }
        } else {
                exchg_log("wss://%s%s closed\n", w->host, w->path);
                websocket_free(w);
        }
}

int http_add_header(struct http *h, const unsigned char *name,
                    const unsigned char *val, size_t len)
{
        return http_conn_add_header(h->conn, name, val, len);
}

int websocket_add_header(struct websocket *w, const unsigned char *name,
                         const unsigned char *val, size_t len)
{
        return ws_conn_add_header(w->conn, name, val, len);
}

static void http_reconnect(struct http *h);

static void http_retry_timer(void *p)
{
        struct http *h = p;

        h->retry.timer = NULL;
        http_reconnect(h);
}

static void http_add_retry_timer(struct http *h)
{
        h->retry.timer = timer_new(h->cl->ctx->net_context, http_retry_timer, h,
                                   retry_seconds(&h->retry));
}

static void http_reconnect(struct http *h)
{
        do {
                retry_connected(&h->retry);
                h->conn = http_dial(h->cl->ctx->net_context, h->host, h->path,
                                    h->method, h);
                if (h->conn) {
                        if (h->body.len > 0)
                                http_conn_want_write(h->conn);
                        return;
                }
        } while (retry_seconds(&h->retry) == 0);

        http_add_retry_timer(h);
}

void http_retry(struct http *h) { h->want_retry = true; }

static void http_on_error(void *p, const char *err)
{
        struct http *h = p;
        if (h->ops->on_error)
                h->ops->on_error(h->cl, h, err);
        http_free(h);
}

static void http_on_established(void *p, int status)
{
        struct http *h = p;

        if (status != 200)
                exchg_log("https://%s%s established (status %d)\n", h->host,
                          h->path, status);
        else
                exchg_log("https://%s%s established\n", h->host, h->path);
        json_init(&h->json);
        if (h->ops->on_established)
                h->ops->on_established(h->cl, h, status);
}

static int http_add_headers(void *p, struct http_conn *req)
{
        struct http *h = p;
        if (h->ops->add_headers)
                return h->ops->add_headers(h->cl, h);
        return 0;
}

int http_body_vsprintf(struct http *h, const char *fmt, va_list args)
{
        if (!h->body.buf && buf_alloc(&h->body, 200, _net_write_buf_padding))
                return -1;
        int len = buf_vsprintf(&h->body, fmt, args);
        if (len > 0)
                http_conn_want_write(h->conn);
        return len;
}

int http_body_sprintf(struct http *h, const char *fmt, ...)
{
        va_list ap;
        int len;

        va_start(ap, fmt);
        len = http_body_vsprintf(h, fmt, ap);
        va_end(ap);
        return len;
}

char *http_body(struct http *h) { return buf_start(&h->body); }

size_t http_body_len(struct http *h) { return h->body.len; }

void http_body_trunc(struct http *h, size_t len)
{
        if (len < h->body.len)
                h->body.len = len;
}

static int http_recv(void *p, char *in, size_t len)
{
        struct http *h = p;
        char *json;
        size_t json_len;
        int numtoks;

        if (unlikely(h->print_data)) {
                put_response(in, len);
                return 0;
        }

        numtoks = json_parse(&h->json, in, len, &json, &json_len);
        if (numtoks < 0) {
                if (numtoks == -EINVAL) {
                        exchg_log(
                            "%s%s sent data that doesn't parse as JSON:\n",
                            h->host, h->path);
                        put_response(json, json_len);
                        h->print_data = true;
                }
                return -1;
        }
        if (numtoks == 0)
                return 0;

        return h->ops->recv(h->cl, h, http_conn_status(h->conn), json, numtoks,
                            h->json.tokens);
}

static void http_write(void *p, char **buf, size_t *len)
{
        struct http *h = p;

        *buf = buf_start(&h->body);
        *len = h->body.len;
}

static void http_on_closed(void *p)
{
        struct http *h = p;

        exchg_log("https://%s%s closed\n", h->host, h->path);
        if (h->ops->on_closed)
                h->ops->on_closed(h->cl, h);
        h->conn = NULL;

        if (h->want_retry) {
                if (retry_seconds(&h->retry) == 0) {
                        exchg_log("Retrying https://%s%s %s now.\n", h->host,
                                  h->path, h->method);
                        http_reconnect(h);
                } else {
                        exchg_log("Retrying https://%s%s %s in %d seconds.\n",
                                  h->host, h->path, h->method,
                                  retry_seconds(&h->retry));
                        http_add_retry_timer(h);
                }
                h->want_retry = false;
        } else {
                http_free(h);
        }
}

static int json_alloc(struct json *json)
{
        json->tokens = malloc(sizeof(jsmntok_t) * 500);
        if (!json->tokens)
                return -1;
        json->num_tokens = 500;
        json_init(json);
        return 0;
}

static struct http *exchg_http_dial(const char *host, const char *path,
                                    const struct exchg_http_ops *ops,
                                    struct exchg_client *cl, const char *method)
{
        struct http *h = malloc(sizeof(*h) + ops->conn_data_size);
        if (!h) {
                exchg_log("%s: OOM\n", __func__);
                return NULL;
        }
        struct http_conn *conn =
            http_dial(cl->ctx->net_context, host, path, method, h);
        if (!conn) {
                free(h);
                return NULL;
        }
        cl->ctx->online = true;
        memset(h, 0, sizeof(*h) + ops->conn_data_size);
        retry_connected(&h->retry);
        h->ops = ops;
        h->conn = conn;
        LIST_INSERT_HEAD(&cl->http_list, h, list);
        h->cl = cl;
        h->method = strdup(method);
        if (!h->method)
                goto oom;
        h->host = strdup(host);
        if (!h->host)
                goto oom;
        h->path = strdup(path);
        if (!h->path)
                goto oom;
        if (json_alloc(&h->json))
                goto oom;
        return h;

oom:
        // important to note that here conn was at least partially
        // initialized even though it failed, so the eventual call to
        // http_free() will not give nonsense. same goes for
        // exchg_websocket_connect()
        http_conn_close(h->conn);
        return NULL;
}

struct http *exchg_http_get(const char *host, const char *path,
                            const struct exchg_http_ops *ops,
                            struct exchg_client *cl)
{
        return exchg_http_dial(host, path, ops, cl, "GET");
}

struct http *exchg_http_post(const char *host, const char *path,
                             const struct exchg_http_ops *ops,
                             struct exchg_client *cl)
{
        return exchg_http_dial(host, path, ops, cl, "POST");
}

struct http *exchg_http_delete(const char *host, const char *path,
                               const struct exchg_http_ops *ops,
                               struct exchg_client *cl)
{
        return exchg_http_dial(host, path, ops, cl, "DELETE");
}

struct websocket *exchg_websocket_connect(struct exchg_client *cl,
                                          const char *host, const char *path,
                                          const struct exchg_websocket_ops *ops)
{
        struct websocket *w = malloc(sizeof(*w) + ops->conn_data_size);
        if (!w) {
                exchg_log("%s: OOM\n", __func__);
                return NULL;
        }
        struct websocket_conn *conn =
            ws_dial(cl->ctx->net_context, host, path, w);
        if (!conn) {
                free(w);
                return NULL;
        }
        cl->ctx->online = true;
        memset(w, 0, sizeof(*w) + ops->conn_data_size);
        retry_connected(&w->retry);
        w->ops = ops;
        w->conn = conn;
        LIST_INSERT_HEAD(&cl->websocket_list, w, list);
        w->cl = cl;
        w->host = strdup(host);
        if (!w->host)
                goto oom;
        w->path = strdup(path);
        if (!w->path)
                goto oom;
        if (json_alloc(&w->json))
                goto oom;
        return w;

oom:
        ws_conn_close(w->conn);
        return NULL;
}

int exchg_parse_info_on_established(struct exchg_client *cl, struct http *h,
                                    int status)
{
        if (status != 200)
                cl->get_info_error = -1;
        return 0;
}

void exchg_parse_info_on_error(struct exchg_client *cl, struct http *h,
                               const char *err)
{
        cl->get_info_error = -1;
}

void exchg_parse_info_on_closed(struct exchg_client *cl, struct http *h)
{
        cl->getting_info = false;
}

const struct exchg_pair_info *exchg_pair_info(struct exchg_client *cl,
                                              enum exchg_pair pair)
{
        if (!cl->pair_info_current)
                return NULL;
        return &cl->pair_info[pair];
}

bool exchg_pair_info_current(struct exchg_client *cl)
{
        return cl->pair_info_current;
}

int exchg_get_balances(struct exchg_client *cl, void *req_private)
{
        return cl->get_balances(cl, req_private);
}

void *websocket_private(struct websocket *w) { return w->private; }

void *http_private(struct http *h) { return h->private; }

struct order_info *__exchg_new_order(struct exchg_client *cl,
                                     const struct exchg_order *order,
                                     const struct exchg_place_order_opts *opts,
                                     void *req_private, size_t private_size,
                                     int64_t id)
{
        struct order_info *info = malloc(sizeof(*info) + private_size);
        if (!info) {
                exchg_log("%s: OOM\n", __func__);
                return NULL;
        }
        info->req_private = req_private;
        info->info.id = id;
        memcpy(&info->info.order, order, sizeof(*order));
        if (opts)
                memcpy(&info->info.opts, opts, sizeof(info->info.opts));
        else
                memset(&info->info.opts, 0, sizeof(info->info.opts));
        info->info.status = EXCHG_ORDER_UNSUBMITTED;
        info->info.cancelation_failed = false;
        memset(&info->info.filled_size, 0, sizeof(decimal_t));
        memset(&info->info.avg_price, 0, sizeof(decimal_t));
        info->info.err[0] = 0;
        g_hash_table_insert(cl->orders, &info->info.id, info);
        return info;
}

struct order_info *exchg_new_order(struct exchg_client *cl,
                                   const struct exchg_order *order,
                                   const struct exchg_place_order_opts *opts,
                                   void *req_private, size_t private_size)
{
        // TODO: current_micros() is fine for now but a collision is not
        // absolutely out of the question. should fix that
        return __exchg_new_order(cl, order, opts, req_private, private_size,
                                 current_micros());
}

struct order_info *exchg_order_lookup(struct exchg_client *cl, int64_t id)
{
        return g_hash_table_lookup(cl->orders, &id);
}

void order_info_free(struct exchg_client *cl, struct order_info *info)
{
        g_hash_table_remove(cl->orders, &info->info.id);
}

// We get order updates possibly on several channels.
// So only give an order update if it seems that the new
// message has more recent info than what was has been gotten so far
void exchg_order_update(struct exchg_client *cl, struct order_info *oi,
                        const struct order_update *update)
{
        struct exchg_order_info *info = &oi->info;
        bool should_callback = false;

        switch (info->status) {
        case EXCHG_ORDER_FINISHED:
        case EXCHG_ORDER_CANCELED:
        case EXCHG_ORDER_ERROR:
                return;
        case EXCHG_ORDER_UNSUBMITTED:
                should_callback |= update->new_status == EXCHG_ORDER_SUBMITTED;
        case EXCHG_ORDER_SUBMITTED:
                should_callback |= update->new_status == EXCHG_ORDER_PENDING;
        case EXCHG_ORDER_PENDING:
                should_callback |= update->new_status == EXCHG_ORDER_OPEN;
        case EXCHG_ORDER_OPEN:
                should_callback |= update->new_status == EXCHG_ORDER_FINISHED ||
                                   update->new_status == EXCHG_ORDER_CANCELED ||
                                   update->new_status == EXCHG_ORDER_ERROR;
        }

        if (should_callback)
                info->status = update->new_status;

        if (update->filled_size &&
            decimal_cmp(&info->filled_size, update->filled_size) < 0) {
                should_callback = true;
                info->filled_size = *update->filled_size;
                if (update->avg_price)
                        info->avg_price = *update->avg_price;
        }
        if (update->order_price &&
            decimal_cmp(&info->order.price, update->order_price)) {
                should_callback = true;
                info->order.price = *update->order_price;
        }
        if (update->order_size &&
            decimal_cmp(&info->order.size, update->order_size)) {
                should_callback = true;
                info->order.size = *update->order_size;
        }
        if (!info->cancelation_failed && update->cancel_failed) {
                should_callback = true;
                info->cancelation_failed = true;
        }
        if (update->timestamp > info->update_timestamp) {
                should_callback = true;
                info->update_timestamp = update->timestamp;
        }

        if (likely(should_callback && cl->ctx->callbacks.on_order_update))
                cl->ctx->callbacks.on_order_update(cl, info, cl->ctx->user,
                                                   oi->private);
        if (order_status_done(info->status))
                order_info_free(cl, oi);
}

int64_t exchg_place_order(struct exchg_client *cl,
                          const struct exchg_order *order,
                          const struct exchg_place_order_opts *opts, void *priv)
{
        if (unlikely(cl->ctx->opts.dry_run)) {
                const char *action;
                const char *atfor;
                char sz[30], px[30];

                decimal_to_str(sz, &order->size);
                decimal_to_str(px, &order->price);

                if (order->side == EXCHG_SIDE_BUY) {
                        action = "buy";
                        atfor = "for";
                } else {
                        action = "sell";
                        atfor = "at";
                }
                printf("%s %s %s %s %s %s\n", cl->name, action, sz,
                       exchg_pair_to_str(order->pair), atfor, px);
                return 0;
        }
        return cl->place_order(cl, order, opts, priv);
}

int exchg_edit_order(struct exchg_client *cl, int64_t id,
                     const struct exchg_price_size *ps, void *request_private)
{
        if (unlikely(!ps->price && !ps->size)) {
                exchg_log("%s: nothing to do with no new price or size\n",
                          __func__);
                return 0;
        }
        struct order_info *info = exchg_order_lookup(cl, id);
        if (!info) {
                exchg_log("%s: %s: order ID %" PRId64 " not known\n", cl->name,
                          __func__, id);
                return -1;
        }
        // TODO: implement for exchanges other than coinbase
        if (unlikely(!cl->edit_order)) {
                exchg_log("%s: %s not implemented\n", cl->name, __func__);
                return -1;
        }
        return cl->edit_order(cl, info, ps, request_private);
}

int exchg_cancel_order(struct exchg_client *cl, int64_t id)
{
        if (unlikely(cl->ctx->opts.dry_run)) {
                // kind of tough, but what should dry run do? remember
                // the orders placed and remove them here? maybe not worth it...
                printf("CANCEL order\n");
                return 0;
        }

        struct order_info *info = exchg_order_lookup(cl, id);

        if (unlikely(!info)) {
                exchg_log("Can't cancel %s order %" PRId64
                          ". ID not recognized\n",
                          cl->name, id);
                return -1;
        }
        return cl->cancel_order(cl, info);
}

int exchg_realloc_order_bufs(struct exchg_client *cl, int n)
{
        struct exchg_limit_order *bids, *asks;
        bids = realloc(cl->update.bids, n * sizeof(struct exchg_limit_order));
        if (!bids) {
                exchg_log("%s(%d): OOM\n", __func__, n);
                return -1;
        }
        cl->update.bids = bids;
        asks = realloc(cl->update.asks, n * sizeof(struct exchg_limit_order));
        if (!asks) {
                exchg_log("%s(%d): OOM\n", __func__, n);
                return -1;
        }
        cl->update.asks = asks;
        cl->l2_update_size = n;
        return 0;
}

enum exchg_id exchg_id(struct exchg_client *cl) { return cl->id; }

const char *exchg_name(struct exchg_client *cl) { return cl->name; }

struct exchg_client *alloc_exchg_client(struct exchg_context *ctx,
                                        enum exchg_id id,
                                        const char *hmac_digest,
                                        int l2_update_size, size_t private_size)
{
        if (ctx->clients[id]) {
                exchg_log("%s client already allocated\n",
                          exchg_id_to_name(id));
                return NULL;
        }
        struct exchg_client *ret = malloc(sizeof(*ret) + private_size);
        if (!ret) {
                fprintf(stderr, "%s OOM\n", __func__);
                return NULL;
        }
        memset(ret, 0, sizeof(*ret) + private_size);

        if (hmac_ctx_alloc(&ret->hmac_ctx, hmac_digest)) {
                free_exchg_client(ret);
                return NULL;
        }

        ret->id = id;
        ret->ctx = ctx;
        // TODO: only really need this many for the first update. Should shrink
        // the buffers after that.
        ret->l2_update_size = l2_update_size;
        ret->update.exchange_id = id;
        ret->update.bids =
            malloc(l2_update_size * sizeof(struct exchg_limit_order));
        ret->update.asks =
            malloc(l2_update_size * sizeof(struct exchg_limit_order));
        if (!ret->update.bids || !ret->update.asks) {
                exchg_log("%s: OOM\n", __func__);
                free(ret->update.bids);
                free(ret->update.asks);
                hmac_ctx_free(&ret->hmac_ctx);
                free(ret);
                return NULL;
        }
        ret->orders =
            g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, free);
        LIST_INIT(&ret->websocket_list);
        LIST_INIT(&ret->http_list);
        LIST_INIT(&ret->work);
        ctx->clients[id] = ret;
        return ret;
}

void free_exchg_client(struct exchg_client *cl)
{
        struct work *w, *tmp_w;
        struct websocket *ws, *tmp_ws;
        struct http *h, *tmp_h;

        cl->ctx->clients[cl->id] = NULL;
        hmac_ctx_free(&cl->hmac_ctx);
        LIST_FOREACH_SAFE(ws, &cl->websocket_list, list, tmp_ws)
        {
                LIST_REMOVE(ws, list);
                __websocket_free(ws);
        }
        LIST_FOREACH_SAFE(h, &cl->http_list, list, tmp_h)
        {
                LIST_REMOVE(h, list);
                __http_free(h);
        }
        LIST_FOREACH_SAFE(w, &cl->work, list, tmp_w)
        {
                LIST_REMOVE(w, list);
                free(w);
        }
        free(cl->apikey_public);
        OPENSSL_cleanse(cl->password, cl->password_len);
        free(cl->password);
        free(cl->update.bids);
        free(cl->update.asks);
        g_hash_table_destroy(cl->orders);
        free(cl);
}

int exchg_num_bids(struct exchg_context *ctx, enum exchg_pair pair)
{
        struct order_book *book = ctx->books[pair];
        if (!book)
                return 0;
        return order_book_num_bids(book);
}

int exchg_num_asks(struct exchg_context *ctx, enum exchg_pair pair)
{
        struct order_book *book = ctx->books[pair];
        if (!book)
                return 0;
        return order_book_num_offers(book);
}

void exchg_foreach_bid(struct exchg_context *ctx, enum exchg_pair pair,
                       int (*f)(const struct exchg_limit_order *o, void *user),
                       void *user)
{
        struct order_book *book = ctx->books[pair];
        if (book)
                order_book_foreach_bid(book, f, user);
}

void exchg_foreach_ask(struct exchg_context *ctx, enum exchg_pair pair,
                       int (*f)(const struct exchg_limit_order *o, void *user),
                       void *user)
{
        struct order_book *book = ctx->books[pair];
        if (book)
                order_book_foreach_offer(book, f, user);
}

bool exchg_best_bid(struct exchg_limit_order *dst, struct exchg_context *ctx,
                    enum exchg_id id, enum exchg_pair pair)
{
        struct order_book *book = ctx->books[pair];
        if (book) {
                return order_book_best_bid(dst, book, id);
        } else {
                return false;
        }
}

bool exchg_best_ask(struct exchg_limit_order *dst, struct exchg_context *ctx,
                    enum exchg_id id, enum exchg_pair pair)
{
        struct order_book *book = ctx->books[pair];
        if (book) {
                return order_book_best_ask(dst, book, id);
        } else {
                return false;
        }
}

static int alloc_book(struct exchg_context *ctx, enum exchg_pair pair)
{
        if (!ctx->opts.track_book || ctx->books[pair])
                return 0;

        struct order_book_config configs[EXCHG_ALL_EXCHANGES];
        memset(configs, 0, sizeof(configs));
        configs[EXCHG_KRAKEN].max_depth = 1000;
        configs[EXCHG_KRAKEN].check_update_time = true;
        ctx->books[pair] =
            order_book_new(configs, ctx->opts.sort_by_nominal_price);
        if (!ctx->books[pair])
                return ENOMEM;
        return 0;
}

static int call_per_exchange(struct exchg_context *ctx, const char *caller,
                             int (*f)(struct exchg_client *, void *),
                             enum exchg_id id, void *p)
{
        if (0 <= id && id < EXCHG_ALL_EXCHANGES) {
                if (!ctx->clients[id]) {
                        const char *name = exchg_id_to_name(id);
                        exchg_log("%s called with id == %s, but %s "
                                  "client not allocated\n",
                                  caller, name, name);
                        return -1;
                }
                return f(ctx->clients[id], p);
        }
        if (id == EXCHG_ALL_EXCHANGES) {
                int ret = 0;
                bool did_something = false;
                for (enum exchg_id id = 0; id < EXCHG_ALL_EXCHANGES; id++) {
                        struct exchg_client *cl = ctx->clients[id];
                        if (cl) {
                                ret |= f(cl, p);
                                did_something = true;
                        }
                }
                if (!did_something) {
                        exchg_log("%s called with no clients allocated\n",
                                  caller);
                        return -1;
                }
                return ret ? -1 : 0;
        }
        exchg_log("%s: bad exchgange id given: %d\n", caller, id);
        return -1;
}

int get_pair_info(struct exchg_client *cl)
{
        // TODO: delete this part. If this is called again, maybe the
        // user really wants to fetch it again cus it thinks something
        // may have changed
        if (cl->pair_info_current)
                return 0;

        if (cl->get_info_error) {
                exchg_log("%s can't get pair info. Already failed once.",
                          cl->name);
                return -1;
        }

        if (!cl->getting_info) {
                cl->getting_info = true;
                return cl->get_pair_info(cl);
        }
        return 0;
}

static int __get_pair_info(struct exchg_client *cl, void *p)
{
        return get_pair_info(cl);
}

int exchg_get_pair_info(struct exchg_context *ctx, enum exchg_id id)
{
        return call_per_exchange(ctx, __func__, __get_pair_info, id, NULL);
}

static int priv_ws_connect(struct exchg_client *cl, void *p)
{
        return cl->priv_ws_connect(cl);
}

int exchg_private_ws_connect(struct exchg_context *ctx, enum exchg_id id)
{
        return call_per_exchange(ctx, __func__, priv_ws_connect, id, NULL);
}

bool exchg_private_ws_online(struct exchg_client *cl)
{
        return cl->priv_ws_online(cl);
}

static int l2_subscribe(struct exchg_client *cl, void *p)
{
        enum exchg_pair pair = *(enum exchg_pair *)p;
        struct exchg_pair_info *pi = &cl->pair_info[pair];
        // TODO: free if ends up unused cus its not available
        int err = alloc_book(cl->ctx, pair);
        if (err)
                return err;
        err = get_pair_info(cl);
        if (err)
                return err;
        if (cl->get_info_error) {
                exchg_log("%s: Can't subscribe to L2 book data "
                          "due to error getting pair info\n",
                          cl->name);
                return -1;
        }
        if (cl->pair_info_current && !pi->available) {
                exchg_log("pair %s not available on %s\n",
                          exchg_pair_to_str(pair), cl->name);
                return -1;
        }
        return cl->l2_subscribe(cl, pair);
}

int exchg_l2_subscribe(struct exchg_context *ctx, enum exchg_id id,
                       enum exchg_pair pair)
{
        return call_per_exchange(ctx, __func__, l2_subscribe, id, &pair);
}

static struct net_callbacks net_callbacks = {
    {
        .on_error = http_on_error,
        .on_established = http_on_established,
        .add_headers = http_add_headers,
        .recv = http_recv,
        .write = http_write,
        .on_closed = http_on_closed,
    },
    {
        .on_error = ws_on_error,
        .on_established = ws_on_established,
        .add_headers = ws_add_headers,
        .recv = ws_recv,
        .on_closed = ws_on_closed,
    },
};

struct exchg_context *exchg_ctx(struct exchg_client *cl) { return cl->ctx; }

struct exchg_client *exchg_alloc_client(struct exchg_context *ctx,
                                        enum exchg_id id)
{
        switch (id) {
        case EXCHG_BITSTAMP:
                return alloc_bitstamp_client(ctx);
        case EXCHG_GEMINI:
                return alloc_gemini_client(ctx);
        case EXCHG_KRAKEN:
                return alloc_kraken_client(ctx);
        case EXCHG_COINBASE:
                return alloc_coinbase_client(ctx);
        default:
                exchg_log("%s: bad exchange id: %d\n", __func__, id);
                return NULL;
        }
}

struct exchg_context *exchg_new(struct exchg_callbacks *callbacks,
                                const struct exchg_options *opts, void *user)
{
        struct exchg_context *ctx = malloc(sizeof(*ctx));
        if (!ctx) {
                exchg_log("%s OOM\n", __func__);
                return NULL;
        }
        memset(ctx, 0, sizeof(*ctx));
        if (callbacks)
                memcpy(&ctx->callbacks, callbacks, sizeof(ctx->callbacks));
        if (opts)
                memcpy(&ctx->opts, opts, sizeof(*opts));
        ctx->user = user;
        ctx->net_context = net_new(&net_callbacks);
        if (!ctx->net_context) {
                free(ctx);
                return NULL;
        }
        return ctx;
}

void exchg_free(struct exchg_context *ctx)
{
        if (!ctx)
                return;
        net_destroy(ctx->net_context);
        for (int i = 0; i < EXCHG_ALL_EXCHANGES; i++) {
                struct exchg_client *cl = ctx->clients[i];
                if (!cl)
                        continue;
                cl->destroy(cl);
        }
        for (enum exchg_pair pair = 0; pair < EXCHG_NUM_PAIRS; pair++)
                order_book_free(ctx->books[pair]);
        free(ctx);
}

bool exchg_service(struct exchg_context *ctx)
{
        if (unlikely(!ctx->online))
                return false;
        net_service(ctx->net_context);
        return true;
}

void exchg_run(struct exchg_context *ctx)
{
        if (ctx->running) {
                exchg_log("%s called recursively. This is an error.\n",
                          __func__);
                return;
        }
        if (!ctx->online)
                return;
        ctx->running = true;
        net_run(ctx->net_context);
}

void exchg_shutdown(struct exchg_context *ctx)
{
        exchg_log("shutting down...\n");
        for (int i = 0; i < EXCHG_ALL_EXCHANGES; i++) {
                struct exchg_client *cl = ctx->clients[i];
                if (!cl)
                        continue;
                exchg_teardown(cl);
        }
}

void exchg_blocking_shutdown(struct exchg_context *ctx)
{
        if (!ctx->online)
                return;

        exchg_shutdown(ctx);
        exchg_run(ctx);
}

struct exchg_client *exchg_client(struct exchg_context *ctx, enum exchg_id id)
{
        if (id < 0 || id >= EXCHG_ALL_EXCHANGES)
                return NULL;
        return ctx->clients[id];
}

const char *exchg_id_to_name(enum exchg_id id)
{
        switch (id) {
        case EXCHG_BITSTAMP:
                return "Bitstamp";
        case EXCHG_GEMINI:
                return "Gemini";
        case EXCHG_KRAKEN:
                return "Kraken";
        case EXCHG_COINBASE:
                return "Coinbase";
        default:
                return "<Invalid Exchange>";
        }
}

int exchg_set_password(struct exchg_client *cl, size_t len,
                       const char *password)
{
        OPENSSL_cleanse(cl->password, cl->password_len);
        free(cl->password);
        cl->password = malloc(len + 1);
        if (!cl->password) {
                exchg_log("%s: OOM\n", __func__);
                return -1;
        }
        memcpy(cl->password, password, len);
        cl->password[len] = 0;
        cl->password_len = len;
        return 0;
}

int exchg_set_keypair(struct exchg_client *cl, size_t public_len,
                      const unsigned char *public, size_t private_len,
                      const unsigned char *private)
{
        cl->apikey_public = malloc(public_len + 1);
        if (!cl->apikey_public) {
                exchg_log("%s: OOM\n", __func__);
                return -1;
        }
        memcpy(cl->apikey_public, public, public_len);
        cl->apikey_public[public_len] = 0;
        cl->apikey_public_len = public_len;
        if (cl->new_keypair(cl, private, private_len)) {
                free(cl->apikey_public);
                return -1;
        }
        return 0;
}

void exchg_vlog(const char *fmt, va_list ap)
{
        struct timespec now;
        struct tm tm;
        char timestamp[60];
        char buf[1024];

        clock_gettime(CLOCK_REALTIME, &now);
        strftime(timestamp, sizeof(timestamp), "[%Y/%m/%d %T",
                 localtime_r(&now.tv_sec, &tm));
        vsnprintf(buf, sizeof(buf), fmt, ap);
        fprintf(stderr, "%s.%.6ld] %s", timestamp, now.tv_nsec / 1000, buf);
}

void exchg_log(const char *fmt, ...)
{
        va_list ap;

        va_start(ap, fmt);
        exchg_vlog(fmt, ap);
        va_end(ap);
}

int queue_work(struct exchg_client *cl,
               bool (*f)(struct exchg_client *, void *), void *p)
{
        struct work *w = malloc(sizeof(*w));
        if (!w) {
                exchg_log("%s: OOM\n", __func__);
                return -1;
        }
        w->cl = cl;
        w->f = f;
        w->p = p;
        LIST_INSERT_HEAD(&cl->work, w, list);
        return 0;
}

int queue_work_exclusive(struct exchg_client *cl,
                         bool (*f)(struct exchg_client *, void *), void *p)
{
        struct work *w;
        LIST_FOREACH(w, &cl->work, list)
        {
                if (w->f == f && w->p == p)
                        return 0;
        }
        return queue_work(cl, f, p);
}

void exchg_do_work(struct exchg_client *cl)
{
        struct work *w, *tmp;

        LIST_FOREACH_SAFE(w, &cl->work, list, tmp)
        {
                if (w->f(w->cl, w->p)) {
                        LIST_REMOVE(w, list);
                        free(w);
                }
        }
}

void remove_work(struct exchg_client *cl,
                 bool (*f)(struct exchg_client *, void *), void *p)
{
        struct work *w, *tmp;
        LIST_FOREACH_SAFE(w, &cl->work, list, tmp)
        {
                if (w->f == f && w->p == p) {
                        LIST_REMOVE(w, list);
                        free(w);
                }
        }
}
