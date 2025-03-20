// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#ifndef FAKE_NET_H
#define FAKE_NET_H

#include <glib.h>
#include <stdbool.h>
#include <sys/queue.h>
#include <time.h>

#include "auth.h"
#include "buf.h"
#include "exchg/exchg.h"
#include "exchg/test.h"

#ifndef TAILQ_FOREACH_SAFE
#define TAILQ_FOREACH_SAFE(var, head, field, tmp)                              \
        for ((var) = ((head)->tqh_first);                                      \
             (var) && ((tmp) = (var)->field.tqe_next, 1); (var) = (tmp))
#endif

#ifndef LIST_FOREACH_SAFE
#define LIST_FOREACH_SAFE(var, head, field, tmp)                               \
        for ((var) = ((head)->lh_first);                                       \
             (var) && ((tmp) = (var)->field.le_next, 1); (var) = (tmp))
#endif

struct http_conn {
        char *host;
        char *path;
        int status;
        enum exchg_id id;
        void *user;
        struct exchg_net_context *ctx;
        struct exchg_test_event *read_event;
        bool closed;
        void (*read)(struct http_conn *req, struct exchg_test_event *ev,
                     struct buf *buf);
        void (*write)(struct http_conn *req, const char *body, size_t len);
        void (*add_header)(struct http_conn *req, const unsigned char *name,
                           const unsigned char *val, size_t len);
        void (*destroy)(struct http_conn *req);
        void *priv;
        LIST_ENTRY(http_conn) list;
};

struct websocket_conn {
        char *host;
        char *path;
        bool established;
        enum exchg_id id;
        int conn_id;
        bool closed;
        LIST_ENTRY(websocket_conn) list;
        void *user;
        struct exchg_net_context *ctx;
        void (*read)(struct websocket_conn *, struct buf *buf,
                     struct exchg_test_event *);
        void (*write)(struct websocket_conn *, const char *buf, size_t len);
        int (*matches)(struct websocket_conn *, struct exchg_test_event *);
        void (*destroy)(struct websocket_conn *);
        void *priv;
};

struct exchg_test_event *
exchg_fake_queue_ws_event(struct websocket_conn *w,
                          enum exchg_test_event_type type, size_t private_size);

void no_ws_write(struct websocket_conn *, const char *, size_t);

enum auth_status {
        AUTH_UNSET,
        AUTH_GOOD,
        AUTH_BAD,
};

struct auth_check {
        enum auth_status apikey_status;
        enum auth_status hmac_status;
        size_t payload_len;
        unsigned char *payload;
        size_t public_len;
        unsigned char *public;
        int hmac_hex;
        enum hex_type hex_type;
        size_t hmac_len;
        char *hmac;
        struct hmac_ctx hmac_ctx;
};

struct auth_check *
auth_check_alloc(size_t public_len, const unsigned char *public,
                 size_t private_len, const unsigned char *private, int hmac_hex,
                 enum hex_type type, const char *hmac_digest);
void auth_check_free(struct auth_check *);
void auth_check_set_public(struct auth_check *, const unsigned char *c,
                           size_t len);
void auth_check_set_payload(struct auth_check *a, const unsigned char *c,
                            size_t len);
void auth_check_set_hmac(struct auth_check *a, const unsigned char *c,
                         size_t len);

void no_http_write(struct http_conn *req, const char *, size_t);
void no_http_add_header(struct http_conn *req, const unsigned char *name,
                        const unsigned char *val, size_t len);

enum conn_type {
        CONN_TYPE_HTTP,
        CONN_TYPE_WS,
        CONN_TYPE_NONE,
};

struct test_event {
        enum conn_type conn_type;
        union {
                struct http_conn *http;
                struct websocket_conn *ws;
        } conn;
        bool moveable;
        int seq;
        int64_t timestamp;
        struct exchg_test_event event;
        TAILQ_ENTRY(test_event) list;
        char private[];
};

void *test_event_private(struct exchg_test_event *event);

struct test_events {
        GTree *events;
        // These are microseconds since the Epoch. Starts at the current time
        // and then is incremented by some amount on each event.
        // TODO: respect this in l2 update messages for exchanges other than
        // coinbase
        int64_t current_time;
        int64_t next_time;
        int seq;
};

struct test_order {
        struct exchg_order_info info;
        LIST_ENTRY(test_order) list;
        char priv[];
};

static inline void *test_order_private(struct test_order *o) { return o->priv; }

struct exchg_net_context {
        struct net_callbacks *callbacks;
        LIST_HEAD(ws_list, websocket_conn) ws_list;
        LIST_HEAD(http_list, http_conn) http_list;
        struct test_events events;
        bool running;
        struct {
                decimal_t balances[EXCHG_NUM_CCYS];
                LIST_HEAD(order_list, test_order) order_list;
        } servers[EXCHG_ALL_EXCHANGES];
        int next_order_id;
        int next_conn_id;
        struct exchg_test_options options;
        // TODO: char error[100];
};

struct websocket_conn *fake_websocket_alloc(struct exchg_net_context *ctx,
                                            void *user);
void ws_conn_free(struct websocket_conn *);
struct websocket_conn *fake_websocket_get(struct exchg_net_context *ctx,
                                          const char *host, const char *path);

struct http_conn *fake_http_conn_alloc(struct exchg_net_context *ctx,
                                       enum exchg_id exchange,
                                       enum exchg_test_event_type type,
                                       void *private);
void fake_http_conn_free(struct http_conn *);

struct test_order *on_order_placed(struct exchg_net_context *ctx,
                                   enum exchg_id id,
                                   struct exchg_order_info *ack,
                                   size_t private_size);
bool on_order_edited(struct exchg_net_context *ctx, enum exchg_id id,
                     struct test_order *o, const decimal_t *new_price,
                     const decimal_t *new_size);
bool on_order_canceled(struct exchg_net_context *ctx, enum exchg_id id,
                       struct test_order *o);

#endif
