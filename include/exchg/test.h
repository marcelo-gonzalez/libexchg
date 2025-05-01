// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#ifndef EXCHG_TEST_H
#define EXCHG_TEST_H

#ifdef __cplusplus
extern "C" {
#endif

#include "exchg/exchg.h"

#define exchg_test_gemini_public "gemini-public-asdfasdf"
#define exchg_test_gemini_private "gemini-super-secret-asdfasdf"

#define exchg_test_kraken_public "kraken-public-asdfasdf"
#define exchg_test_kraken_private "kraken-super-secret-asdfasdf"

#define exchg_test_bitstamp_public "bitstamp-public-asdfasdf"
#define exchg_test_bitstamp_private "bitstamp-super-secret-asdfasdf"

#define exchg_test_coinbase_public "coinbase-public-asdfasdf"
#define exchg_test_coinbase_private "coinbase-super-secret-asdfasdf"
#define exchg_test_coinbase_password "coinbase-password-asdfasdf"

enum exchg_test_event_type {
        EXCHG_EVENT_HTTP_ESTABLISHED,
        EXCHG_EVENT_WS_ESTABLISHED,
        EXCHG_EVENT_BOOK_UPDATE,
        /* The code under test has just placed an order, with details
        in the event's order_placed field. You can write to
        order_placed.fill_size and order_placed.error to affect
        what will happen immediately to the order */
        EXCHG_EVENT_ORDER_PLACED,
        /* The code under test has just edited an order with details in the
           order_edited field */
        EXCHG_EVENT_ORDER_EDITED,
        /* The code under test has just tried canceling an order, with details
        in the event's order_canceled field. You can write to
        order_canceled.succeed to tell whether the cancelation should succeed */
        EXCHG_EVENT_ORDER_CANCELED,
        EXCHG_EVENT_ORDER_ACK,
        EXCHG_EVENT_ORDER_CANCEL_ACK,
        EXCHG_EVENT_PAIRS_DATA,
        EXCHG_EVENT_BALANCES,
        EXCHG_EVENT_WS_PROTOCOL,
        EXCHG_EVENT_HTTP_PROTOCOL,
        EXCHG_EVENT_WS_CLOSE,
        EXCHG_EVENT_HTTP_CLOSE,
        EXCHG_EVENT_TIMER,
};

struct exchg_test_l2_update {
        decimal_t price;
        decimal_t size;
};

struct exchg_test_websocket_event {
        const char *host;
        const char *path;
        int conn_id;
};

struct exchg_test_l2_updates {
        enum exchg_pair pair;
        int num_bids;
        int num_asks;
        struct exchg_test_l2_update *bids;
        struct exchg_test_l2_update *asks;
        int bid_cap;
        int ask_cap;
};

struct exchg_test_order_placed {
        int id;
        struct exchg_order order;
        struct exchg_place_order_opts opts;
        decimal_t fill_size;
        decimal_t avg_price;
        bool error;
};

struct exchg_test_order_edited {
        int id;
        const decimal_t *new_price;
        const decimal_t *new_size;
        bool error;
};

struct exchg_test_order_canceled {
        struct exchg_order_info info;
        bool succeed;
};

struct exchg_test_event {
        enum exchg_id id;
        enum exchg_test_event_type type;
        union {
                // present in EXCHG_EVENT_BOOK_UPDATE events
                // After calling exchg_test_add_events(), the exchg_net_context
                // will take ownership of book.bids and book.asks and free()
                // them when finished
                struct exchg_test_l2_updates book;
                // present in EXCHG_EVENT_ORDER_ACK events
                struct exchg_order_info order_ack;
                // present in EXCHG_EVENT_ORDER_PLACED events
                // TODO: tighten the API
                struct exchg_test_order_placed order_placed;
                struct exchg_test_order_edited order_edited;
                struct exchg_test_order_canceled order_canceled;
                struct exchg_test_websocket_event ws_established;
                struct exchg_test_websocket_event ws_close;
        } data;
};

int exchg_test_l2_queue_order(struct exchg_test_l2_updates *u, bool is_bid,
                              decimal_t *price, decimal_t *size);

struct exchg_context *exchg_test_new(struct exchg_callbacks *c,
                                     const struct exchg_options *opts,
                                     void *user);

void exchg_test_event_print(struct exchg_test_event *);

struct exchg_net_context;

struct exchg_net_context *exchg_test_net_ctx(struct exchg_context *ctx);

void exchg_test_add_events(struct exchg_net_context *ctx, int n,
                           struct exchg_test_event *msgs);

typedef void (*exchg_test_callback_t)(struct exchg_net_context *,
                                      struct exchg_test_event *, void *);

void exchg_test_set_callback(struct exchg_net_context *ctx,
                             exchg_test_callback_t cb, void *user);

struct exchg_test_str_l2_update {
        const char *price;
        const char *size;
};

struct exchg_test_str_l2_updates {
        enum exchg_id id;
        enum exchg_pair pair;
        // both null terminated
        struct exchg_test_str_l2_update bids[10];
        struct exchg_test_str_l2_update asks[10];
};

// TODO: delete this or put it in a helpers section. keep API small
void exchg_test_add_l2_events(struct exchg_net_context *ctx, int n,
                              struct exchg_test_str_l2_updates *msgs);

// returns a modifiable array of length EXCHG_NUM_CCYS
decimal_t *exchg_test_balances(struct exchg_net_context *ctx, enum exchg_id id);

#ifdef __cplusplus
}
#endif

#endif
