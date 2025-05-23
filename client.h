// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#ifndef CLIENT_H
#define CLIENT_H

#include <glib.h>
#include <jsmn/jsmn.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/queue.h>

#include "auth.h"
#include "exchg/currency.h"
#include "exchg/decimal.h"
#include "exchg/exchg.h"
#include "json-helpers.h"
#include "net-backend.h"
#include "order-book.h"

struct exchg_context *__exchg_new(struct exchg_callbacks *callbacks,
                                  const struct exchg_options *opts, void *user,
                                  void *net_arg);

struct work {
        struct exchg_client *cl;
        bool (*f)(struct exchg_client *, void *);
        void *p;
        LIST_ENTRY(work) list;
};

void remove_work(struct exchg_client *,
                 bool (*f)(struct exchg_client *, void *), void *p);
int queue_work(struct exchg_client *, bool (*f)(struct exchg_client *, void *),
               void *p);
int queue_work_exclusive(struct exchg_client *,
                         bool (*f)(struct exchg_client *, void *), void *p);
void exchg_do_work(struct exchg_client *cl);

struct websocket;
struct http;

struct order_info {
        struct exchg_order_info info;
        struct exchg_request_options options;
        char private[];
};

static inline void *order_info_private(struct order_info *o)
{
        return o->private;
}

struct exchg_client {
        enum exchg_id id;
        const char *name;
        struct exchg_context *ctx;
        int (*get_pair_info)(struct exchg_client *cl);
        int (*l2_subscribe)(struct exchg_client *cl, enum exchg_pair pair,
                            const struct exchg_websocket_options *options);
        int (*get_balances)(struct exchg_client *cl,
                            const struct exchg_request_options *options);
        int64_t (*place_order)(struct exchg_client *cl,
                               const struct exchg_order *,
                               const struct exchg_place_order_opts *,
                               const struct exchg_request_options *options);
        int (*edit_order)(struct exchg_client *cl, struct order_info *info,
                          const struct exchg_price_size *ps,
                          const struct exchg_request_options *options);
        int (*cancel_order)(struct exchg_client *cl, struct order_info *info,
                            const struct exchg_request_options *options);
        int (*new_keypair)(struct exchg_client *cl, const unsigned char *key,
                           size_t len);
        // cl is responsible for setting ->apikey_public. TODO: should be
        // unified
        int (*new_keypair_from_file)(struct exchg_client *cl, const char *path);
        int (*priv_ws_connect)(struct exchg_client *cl,
                               const struct exchg_websocket_options *options);
        bool (*priv_ws_online)(struct exchg_client *cl);
        void (*destroy)(struct exchg_client *cl);
        LIST_HEAD(websocket_list, websocket) websocket_list;
        LIST_HEAD(http_list, http) http_list;
        // TODO: move to exchange private structs
        struct hmac_ctx hmac_ctx;
        unsigned char *apikey_public;
        size_t apikey_public_len;
        GHashTable *orders;
        bool getting_info;
        int get_info_error;
        bool pair_info_current;
        struct exchg_pair_info pair_info[EXCHG_NUM_PAIRS];
        int l2_update_size;
        struct exchg_l2_update update;
        LIST_HEAD(work_list, work) work;
        char private[];
};

static inline void client_apikey_pub_free(struct exchg_client *cl)
{
        free(cl->apikey_public);
        cl->apikey_public = NULL;
        cl->apikey_public_len = 0;
}

int get_pair_info(struct exchg_client *cl);

static inline void *client_private(struct exchg_client *cl)
{
        return cl->private;
}

static inline void exchg_update_init(struct exchg_client *cl)
{
        cl->update.num_bids = 0;
        cl->update.num_asks = 0;
}

// TODO: use glib Vec
int exchg_realloc_order_bufs(struct exchg_client *cl, int n);

static inline void order_err_cpy(struct exchg_order_info *info,
                                 const char *json, jsmntok_t *tok)
{
        if (tok)
                json_strncpy(info->err, json, tok, EXCHG_ORDER_ERR_SIZE);
        else
                strncpy(info->err, "<unknown>", EXCHG_ORDER_ERR_SIZE);
}

struct order_info *
__exchg_new_order(struct exchg_client *cl, const struct exchg_order *order,
                  const struct exchg_place_order_opts *opts,
                  const struct exchg_request_options *options,
                  size_t private_size, int64_t id);
struct order_info *exchg_new_order(struct exchg_client *cl,
                                   const struct exchg_order *order,
                                   const struct exchg_place_order_opts *opts,
                                   const struct exchg_request_options *options,
                                   size_t private_size);

static inline bool order_status_done(enum exchg_order_status status)
{
        return status == EXCHG_ORDER_FINISHED ||
               status == EXCHG_ORDER_CANCELED || status == EXCHG_ORDER_ERROR;
}

void order_info_free(struct exchg_client *cl, struct order_info *info);

struct order_update {
        int64_t timestamp;
        enum exchg_order_status new_status;
        const decimal_t *order_price;
        const decimal_t *order_size;
        const decimal_t *filled_size;
        const decimal_t *avg_price;
        bool cancel_failed;
};

void exchg_order_update(struct exchg_client *cl, struct order_info *oi,
                        const struct order_update *update);
struct order_info *exchg_order_lookup(struct exchg_client *cl, int64_t id);

__attribute__((format(printf, 3, 4))) static inline void
order_err_update(struct exchg_client *cl, struct order_info *oi,
                 const char *fmt, ...)
{
        va_list ap;
        struct order_update update = {
            .new_status = EXCHG_ORDER_ERROR,
        };

        va_start(ap, fmt);
        vsnprintf(oi->info.err, EXCHG_ORDER_ERR_SIZE, fmt, ap);
        exchg_order_update(cl, oi, &update);
        va_end(ap);
}

struct exchg_context {
        struct exchg_options opts;
        struct exchg_callbacks callbacks;
        void *user;
        struct exchg_client *clients[EXCHG_ALL_EXCHANGES];
        struct order_book *books[EXCHG_NUM_PAIRS];
        struct exchg_net_context *net_context;
        bool running;
        bool online;
};

static inline void exchg_l2_update(struct exchg_client *cl,
                                   enum exchg_pair pair)
{
        struct exchg_context *ctx = cl->ctx;
        struct exchg_l2_update *upd = &cl->update;
        struct order_book *book = ctx->books[pair];

        if (book)
                order_book_add_update(book, upd);
        if (ctx->callbacks.on_l2_update)
                ctx->callbacks.on_l2_update(cl, pair, upd, ctx->user);
        if (book)
                order_book_update_finish(book, upd);
}

void exchg_data_disconnect(struct exchg_client *cl, struct websocket *ws,
                           int num_pairs_gone, enum exchg_pair *pairs_gone);

static inline void exchg_on_balances(struct exchg_client *cl,
                                     const decimal_t balances[EXCHG_NUM_CCYS],
                                     void *req_private)
{
        if (cl->ctx->callbacks.on_balances_recvd)
                cl->ctx->callbacks.on_balances_recvd(
                    cl, balances, cl->ctx->user, req_private);
}

static inline void exchg_on_pair_info(struct exchg_client *cl)
{
        cl->pair_info_current = true;
        cl->get_info_error = 0;
        if (cl->ctx->callbacks.on_pair_info)
                cl->ctx->callbacks.on_pair_info(cl, cl->ctx->user);
}

static inline void exchg_on_event(struct exchg_client *cl, int type)
{
        if (cl->ctx->callbacks.on_event)
                cl->ctx->callbacks.on_event(cl, type, cl->ctx->user);
}

static inline void exchg_book_clear(struct exchg_client *cl,
                                    enum exchg_pair pair)
{
        struct order_book *book = cl->ctx->books[pair];

        if (book)
                order_book_clear(book, cl->id);
}

struct exchg_client *alloc_exchg_client(struct exchg_context *ctx,
                                        enum exchg_id id,
                                        const char *hmac_digest,
                                        int l2_update_size,
                                        size_t private_size);

// complete in progress stuff first
// otherwise you can get a user after free in http_get callback
void free_exchg_client(struct exchg_client *cl);

struct exchg_websocket_ops {
        int (*on_conn_established)(struct exchg_client *, struct websocket *);
        int (*add_headers)(struct exchg_client *, struct websocket *);
        int (*on_disconnect)(struct exchg_client *, struct websocket *,
                             int reconnect_seconds);
        int (*recv)(struct exchg_client *, struct websocket *, char *js,
                    int num_toks, jsmntok_t *toks);
        size_t conn_data_size;
};

static inline bool
ws_options_authenticate(const struct exchg_websocket_options *options)
{
        return options ? options->authenticate : false;
}

// TODO: maybe just allow the changes
void websocket_log_options_discrepancies(
    struct websocket *, const struct exchg_websocket_options *options);

bool websocket_disconnecting(struct websocket *);
bool websocket_established(struct websocket *);

const char *websocket_host(struct websocket *);
const char *websocket_path(struct websocket *);

const char *http_method(struct http *);
const char *http_host(struct http *);
const char *http_path(struct http *);

struct websocket *
exchg_websocket_connect(struct exchg_client *cl, const char *host,
                        const char *path, const struct exchg_websocket_ops *ops,
                        const struct exchg_websocket_options *options);

int websocket_printf(struct websocket *, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

int http_body_vsprintf(struct http *, const char *fmt, va_list args);
int http_body_sprintf(struct http *, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
char *http_body(struct http *http);
size_t http_body_len(struct http *http);
void http_body_trunc(struct http *http, size_t len);

void *websocket_private(struct websocket *);
void *http_private(struct http *);

void for_each_websocket(struct exchg_client *cl,
                        int (*func)(struct websocket *ws, void *private),
                        void *private);

int exchg_parse_info_on_established(struct exchg_client *cl, struct http *,
                                    int status);
void exchg_parse_info_on_error(struct exchg_client *cl, struct http *,
                               const char *err);
void exchg_parse_info_on_closed(struct exchg_client *cl, struct http *);

int http_add_header(struct http *, const unsigned char *name,
                    const unsigned char *val, size_t len);
int websocket_add_header(struct websocket *, const unsigned char *name,
                         const unsigned char *val, size_t len);

struct exchg_http_ops {
        int (*add_headers)(struct exchg_client *, struct http *);
        // TODO: remove status param
        int (*recv)(struct exchg_client *cl, struct http *, int status,
                    char *js, int num_toks, jsmntok_t *toks);
        int (*on_established)(struct exchg_client *cl, struct http *,
                              int status);
        void (*on_closed)(struct exchg_client *cl, struct http *);
        void (*on_error)(struct exchg_client *cl, struct http *,
                         const char *err);
        void (*on_free)(struct exchg_client *cl, struct http *);
        size_t conn_data_size;
};

struct http *exchg_http_get(const char *host, const char *path,
                            const struct exchg_http_ops *ops,
                            struct exchg_client *cl,
                            const struct exchg_request_options *options);
struct http *exchg_http_post(const char *host, const char *path,
                             const struct exchg_http_ops *ops,
                             struct exchg_client *cl,
                             const struct exchg_request_options *options);
struct http *exchg_http_delete(const char *host, const char *path,
                               const struct exchg_http_ops *ops,
                               struct exchg_client *cl,
                               const struct exchg_request_options *options);

void http_retry(struct http *);

void http_close(struct http *);
void websocket_close(struct websocket *);

void exchg_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

#endif
