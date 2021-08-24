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
	EXCHG_EVENT_HTTP_PREP,
	EXCHG_EVENT_WS_PREP,
	EXCHG_EVENT_BOOK_UPDATE,
	EXCHG_EVENT_ORDER_ACK,
	EXCHG_EVENT_PAIRS_DATA,
	EXCHG_EVENT_BALANCES,
	EXCHG_EVENT_WS_PROTOCOL,
	EXCHG_EVENT_HTTP_PROTOCOL,
	EXCHG_EVENT_WS_CLOSE,
	EXCHG_EVENT_HTTP_CLOSE,
};

#define FAKE_BOOK_UPDATE_SIZE 100

struct exchg_test_l2_update {
	decimal_t price;
	decimal_t size;
};

struct exchg_test_event {
	enum exchg_id id;
	enum exchg_test_event_type type;
	union {
		struct exchg_test_l2_updates {
			enum exchg_pair pair;
			struct exchg_test_l2_update bids[FAKE_BOOK_UPDATE_SIZE];
			struct exchg_test_l2_update asks[FAKE_BOOK_UPDATE_SIZE];
			int num_bids;
			int num_asks;
		} book;
		struct fake_ack {
			bool finished;
			bool err;
			enum exchg_pair pair;
			int64_t id;
			decimal_t price;
			decimal_t size;
			enum exchg_side side;
		} ack;
		void *protocol_private;
	} data;
};

struct exchg_context *exchg_test_new(struct exchg_callbacks *c,
				     const struct exchg_options *opts, void *user);

void exchg_test_event_print(struct exchg_test_event *);

struct exchg_net_context;

struct exchg_net_context *exchg_test_net_ctx(struct exchg_context *ctx);

void exchg_test_add_events(struct exchg_net_context *ctx,
			   int n, struct exchg_test_event *msgs);

typedef void (*exchg_test_callback_t)(struct exchg_net_context *,
				      struct exchg_test_event *, void *);

void exchg_test_set_callback(struct exchg_net_context *ctx,
			     exchg_test_callback_t cb,
			     void *private);

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

void exchg_test_add_l2_events(struct exchg_net_context *ctx,
			      int n, struct exchg_test_str_l2_updates *msgs);

// returns a modifiable array of length EXCHG_NUM_CCYS
decimal_t *exchg_test_balances(struct exchg_net_context *ctx, enum exchg_id id);

#ifdef __cplusplus
}
#endif

#endif
