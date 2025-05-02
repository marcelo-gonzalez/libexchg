// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#ifndef EXCHG_H
#define EXCHG_H

#include <stdbool.h>

#include "exchg/currency.h"
#include "exchg/decimal.h"
#include "exchg/exchanges.h"
#include "exchg/orders.h"

#ifdef __cplusplus
extern "C" {
#endif

struct exchg_options {
        // Connect to sandbox API endpoints instead of live production
        bool sandbox;
        // Print orders instead of sending them to the exchange
        bool dry_run;
        // Keep an order book accessible by exchg_foreach_bid(),
        // exchg_best_bid(), etc.
        bool track_book;
        // Sort main order book by the listed price, rather than the price after
        // fees
        bool sort_by_nominal_price;
};

struct exchg_client;
struct exchg_context;

struct exchg_callbacks;

struct exchg_context *exchg_new(struct exchg_callbacks *c,
                                const struct exchg_options *opts, void *user);
void exchg_free(struct exchg_context *ctx);

struct exchg_client *exchg_alloc_client(struct exchg_context *ctx,
                                        enum exchg_id id);

// Run one iteration of the event loop, possibly calling one of the
// context's exchg_callbacks. Returns true if there are still events
// expected in the future (i.e. another call to exchg_service is warranted)
bool exchg_service(struct exchg_context *ctx);
// Run until there are no connections left to service
void exchg_run(struct exchg_context *ctx);

// close open connections. If inside exchg_run(), then that function
// will return after all connections have finally been closed and
// there's nothing left to do. Otherwise call exchg_run() or
// exchg_service() in a loop until it returns false.
void exchg_shutdown(struct exchg_context *ctx);
// shorthand for exchg_shutdown(); exchg_run();
// must not be called inside exchg_run() or exchg_service()
void exchg_blocking_shutdown(struct exchg_context *ctx);

enum exchg_side {
        EXCHG_SIDE_BUY,
        EXCHG_SIDE_SELL,
};

struct exchg_order {
        enum exchg_pair pair;
        enum exchg_side side;
        decimal_t size;
        decimal_t price;
};

// TODO: cancel reason enum
enum exchg_order_status {
        EXCHG_ORDER_UNSUBMITTED,
        EXCHG_ORDER_SUBMITTED,
        EXCHG_ORDER_PENDING,
        EXCHG_ORDER_OPEN,
        EXCHG_ORDER_FINISHED,
        EXCHG_ORDER_CANCELED,
        EXCHG_ORDER_ERROR,
};

static inline const char *
exchg_order_status_to_str(enum exchg_order_status status)
{
        switch (status) {
        case EXCHG_ORDER_UNSUBMITTED:
                return "UNSUBMITTED";
        case EXCHG_ORDER_SUBMITTED:
                return "SUBMITTED";
        case EXCHG_ORDER_PENDING:
                return "PENDING";
        case EXCHG_ORDER_OPEN:
                return "OPEN";
        case EXCHG_ORDER_FINISHED:
                return "FINISHED";
        case EXCHG_ORDER_CANCELED:
                return "CANCELED";
        case EXCHG_ORDER_ERROR:
                return "ERROR";
        default:
                return "UNKNOWN_STATUS";
        }
}

// TODO: type enum with more types instead of bool
struct exchg_place_order_opts {
        bool immediate_or_cancel;
};

#define EXCHG_ORDER_ERR_SIZE 127

struct exchg_order_info {
        // TODO: change this ID to be a union over different order ID types
        // specific to each exchange
        int64_t id;
        struct exchg_order order;
        struct exchg_place_order_opts opts;
        enum exchg_order_status status;
        // TODO: clean up the meaning/handling of this field
        bool cancelation_failed;
        decimal_t filled_size;
        // TODO: actually set this or get rid of it
        decimal_t avg_price;
        // TODO: this is only set for coinbase at the moment
        int64_t update_timestamp;
        // Will contain a non-empty string if status is CANCELED or ERROR
        char err[EXCHG_ORDER_ERR_SIZE + 1];
};

enum exchg_event_type {
        EXCHG_PRIVATE_WS_ONLINE,
        // TODO: EXCHG_PRIVATE_WS_OFFLINE
};

// main callbacks. user arg is the same as was passed to exchg_new().
// request_private is the private argument passed to the corresponding function
// triggering the callback, where this applies.
struct exchg_callbacks {
        void (*on_l2_update)(struct exchg_client *, enum exchg_pair pair,
                             struct exchg_l2_update *, void *user);
        // The websocket connection providing l2 data has been closed and
        // the order book (the one accessible via exchg_foreach_bid(), etc)
        // for each pair in pairs_gone has been cleared of this exchange's
        // orders. Reconnection will be attempted after reconnect_seconds unless
        // it's < 0, in which case we won't try again.
        void (*on_l2_disconnect)(struct exchg_client *, int reconnect_seconds,
                                 int num_pairs_gone,
                                 const enum exchg_pair *pairs_gone, void *user);
        void (*on_balances_recvd)(struct exchg_client *,
                                  const decimal_t balances[EXCHG_NUM_CCYS],
                                  void *user, void *request_private);
        void (*on_order_update)(struct exchg_client *,
                                const struct exchg_order_info *info, void *user,
                                void *request_private);
        // We have now successfully fetched pair/symbol info for this client
        void (*on_pair_info)(struct exchg_client *, void *user);
        // Generic "something-has-happened" callback. Currently only used by
        // PRIVATE_WS_ONLINE, but could be used for more stuff later
        void (*on_event)(struct exchg_client *, enum exchg_event_type,
                         void *user);
};

struct exchg_websocket_options {
        bool authenticate;
        bool log_messages;
};

struct exchg_request_options {
        // If true, log any HTTP data sent or received
        bool debug;
        // Will be passed back to the user in callbacks
        void *user;
};

// ---------------- actions -----------------------
// ------------------------------------------------
int exchg_set_keypair(struct exchg_client *cl, size_t public_len,
                      const unsigned char *public_key, size_t private_len,
                      const unsigned char *private_key);

// Only implemented for Coinbase at the moment
int exchg_set_keypair_from_file(struct exchg_client *cl, const char *path);

// Fetch info on available trading pairs. Called automatically by other
// functions that require it. pass EXCHG_ALL_EXCHANGES to fetch info for all
// previously allocated clients
int exchg_get_pair_info(struct exchg_context *ctx, enum exchg_id id);

// Subscribe to L2 order book data to be received in the on_l2_update callback
// pass EXCHG_ALL_EXCHANGES to subscribe on all previously allocated clients
int exchg_l2_subscribe(struct exchg_context *ctx, enum exchg_id id,
                       enum exchg_pair pair,
                       const struct exchg_websocket_options *options);

int exchg_get_balances(struct exchg_client *cl,
                       const struct exchg_request_options *);

// Returns < 0 on error, otherwise an ID that will match the ID in the struct
// order_info passed in the on_order_update() callback.
// Pass NULL options for defaults.
int64_t exchg_place_order(struct exchg_client *cl, const struct exchg_order *,
                          const struct exchg_place_order_opts *,
                          const struct exchg_request_options *);

struct exchg_price_size {
        const decimal_t *price;
        const decimal_t *size;
};

int exchg_edit_order(struct exchg_client *cl, int64_t id,
                     const struct exchg_price_size *,
                     const struct exchg_request_options *);

// `id` must be an id previously returned by a call to exchg_place_order() on
// this struct exchg_client. Returns nonzero on error. If successful, the order
// isn't guaranteed to have been canceled until the on_order_update() callback
// gives EXCHG_ORDER_CANCELED. If we later find that the cancelation was
// not successful, an order update will be given with cancelation_failed=true
// FIXME: For now options->user is ignored
int exchg_cancel_order(struct exchg_client *cl, int64_t id,
                       const struct exchg_request_options *);

// If available, subscribe to private data feed that will give updates
// on our orders in the future.
// pass EXCHG_ALL_EXCHANGES to connect on all previously allocated clients
int exchg_private_ws_connect(struct exchg_context *, enum exchg_id,
                             const struct exchg_websocket_options *options);
// Is the private data feed online? If this doesn't apply for the given
// exchange, this returns true.
bool exchg_private_ws_online(struct exchg_client *);

// --------------------- helpers -------------------
// ------------------------------------------------

const char *exchg_name(struct exchg_client *cl);
enum exchg_id exchg_id(struct exchg_client *cl);

struct exchg_context *exchg_ctx(struct exchg_client *cl);
// Returns previously allocated client, or NULL if none has been allocated
struct exchg_client *exchg_client(struct exchg_context *ctx, enum exchg_id id);

struct exchg_pair_info {
        bool available;
        int base_decimals;
        int price_decimals;
        int fee_bps;
        bool min_size_is_base;
        decimal_t min_size;
};

bool exchg_pair_info_current(struct exchg_client *cl);
// returns NULL if exchg_pair_info_current() is false
const struct exchg_pair_info *exchg_pair_info(struct exchg_client *cl,
                                              enum exchg_pair pair);

int exchg_num_bids(struct exchg_context *ctx, enum exchg_pair pair);
int exchg_num_asks(struct exchg_context *ctx, enum exchg_pair pair);
void exchg_foreach_bid(struct exchg_context *ctx, enum exchg_pair pair,
                       int (*f)(const struct exchg_limit_order *o, void *user),
                       void *user);
void exchg_foreach_ask(struct exchg_context *ctx, enum exchg_pair pair,
                       int (*f)(const struct exchg_limit_order *o, void *user),
                       void *user);

// pass EXCHG_ALL_EXCHANGES in `id` for the best bid/ask across
// all previously allocated clients
bool exchg_best_bid(struct exchg_limit_order *dst, struct exchg_context *ctx,
                    enum exchg_id id, enum exchg_pair pair);
bool exchg_best_ask(struct exchg_limit_order *dst, struct exchg_context *ctx,
                    enum exchg_id id, enum exchg_pair pair);

void exchg_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

// ------------------------------------------------
// ------------------------------------------------

#ifdef __cplusplus
}
#endif

#endif
