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

#define exchg_test_coinbase_public                                             \
        "organizations/e13400a2-970d-e6a3-f4da-0f95431360db/apiKeys/"          \
        "36949b58-a964-31db-e2b2-b823943b04eb"
#define exchg_test_coinbase_private                                            \
        "-----BEGIN EC PRIVATE KEY-----\n"                                     \
        "MHcCAQEEIDTdR2n7rBB0wgvt3y7jmFipSfQuXHIWZWsgxsaEZTm3oAoGCCqGSM49\n"   \
        "AwEHoUQDQgAEynDT8gm3fQeSA8bBsRVMzfBF0YzFDFFKruDuWzn9iW/VNrmFHhbm\n"   \
        "xDPx2Er1BJeemUBk4XvJ39LQVUozTKYPXg==\n"                               \
        "-----END EC PRIVATE KEY-----"

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
        EXCHG_EVENT_FROM_FILE,
};

enum exchg_test_ws_type {
        EXCHG_WS_TYPE_ANY,
        EXCHG_WS_TYPE_PUBLIC,
        EXCHG_WS_TYPE_PRIVATE,
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

struct exchg_test_from_file {
        enum exchg_test_ws_type ws_type;
        const char *filename;
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
                struct exchg_test_from_file from_file;
                struct exchg_test_websocket_event ws_established;
                struct exchg_test_websocket_event ws_close;
        } data;
};

int exchg_test_l2_queue_order(struct exchg_test_l2_updates *u, bool is_bid,
                              const decimal_t *price, const decimal_t *size);

struct exchg_net_context;

typedef void (*exchg_test_callback_t)(struct exchg_net_context *,
                                      struct exchg_test_event *, void *);

struct exchg_test_options {
        exchg_test_callback_t event_cb;
        void *callback_user;
        // These info_file fields are required for any test that allocates
        // and uses the corresponding client. The files should contain the
        // pair info data obtained with the relevant HTTP requests.
        // Use test/pair-info/get-pair-info.py to download them.
        const char *bitstamp_info_file;
        const char *coinbase_info_file;
        const char *kraken_info_file;
};

struct exchg_context *
exchg_test_new(struct exchg_callbacks *c, const struct exchg_options *opts,
               void *user, const struct exchg_test_options *test_opts);

const char *exchg_test_event_to_str(enum exchg_test_event_type type);

struct exchg_net_context *exchg_test_net_ctx(struct exchg_context *ctx);

void exchg_test_add_events(struct exchg_net_context *ctx, int n,
                           struct exchg_test_event *msgs);

int exchg_test_fill_order(struct exchg_net_context *ctx, enum exchg_id id,
                          int64_t order_id, const decimal_t *total_fill);

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
