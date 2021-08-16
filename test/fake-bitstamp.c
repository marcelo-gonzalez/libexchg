// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json-helpers.h"
#include "exchg/exchg.h"
#include "fake-net.h"
#include "fake-bitstamp.h"
#include "util.h"

struct bitstamp_websocket {
	int conn_id_sent;
	struct bitstamp_channel {
		bool diff_subbed;
		bool full_subbed;
		bool full_unsubbed;
	} channels[EXCHG_NUM_PAIRS];
};

static size_t write_orders_side(char *buf, struct fake_book_update *update,
				bool is_bids) {
	char *c = buf;
	struct fake_book_update_single *orders;
	int n;

	if (is_bids) {
		n = update->num_bids;
		orders = &update->bids[0];
	} else {
		n = update->num_asks;
		orders = &update->asks[0];
	}

	if (n < 1)
		return 0;

	c += sprintf(c, "\"%s\": [", is_bids ? "bids" : "asks");
	for (int i = 0; i < n; i++) {
		char size[30], price[30];
		decimal_to_str(size, &orders[i].size);
		decimal_to_str(price, &orders[i].price);
		c += sprintf(c, "[ \"%s\", \"%s\"], ",
			     price, size);
	}
	c += sprintf(c, "], ");
	return c-buf;
}

static size_t write_orders(char *buf, struct fake_book_update *update,
			   bool is_diff) {
	char *c = buf;
	c += sprintf(c, "{ \"data\": {\"timestamp\": \"123\", "
		     "\"microtimestamp\": \"123000\", ");
	c += write_orders_side(c, update, true);
	c += write_orders_side(c, update, false);
	c += sprintf(c, "}, \"channel\": \"%sorder_book_%s\", "
		     "\"event\": \"data\" }", is_diff ? "diff_" : "",
		     exchg_pair_to_str(update->pair));
	return c-buf;
}

enum proto_type {
	NONSENSE_DIFF,
	UNSUB_SUCCEEDED,
};

struct bitstamp_proto {
	enum proto_type type;
	enum exchg_pair pair;
};

static size_t proto_read(char *buf, struct bitstamp_proto *bp) {
	size_t ret = 0;

	if (bp->type == NONSENSE_DIFF) {
		struct fake_book_update u = {
			.pair = bp->pair,
			.num_bids = 1,
			.bids = {{
					{.places = 0, .value = 1},
					{.places = 0, .value = 1},
				}},
			.asks = {{
					{.places = 0, .value = 1},
					{.places = 0, .value = 1},
				}},
		};
		ret = write_orders(buf, &u, true);
	} else if (bp->type == UNSUB_SUCCEEDED) {
		ret = sprintf(buf, "{ \"event\": \""
			      "bts:unsubscription_succeeded\","
			      " \"channel\": \"order_book_%s\""
			      ", \"data\": { } }",
			      exchg_pair_to_str(bp->pair));
	}
	free(bp);
	return ret;
}

static size_t bitstamp_ws_read(struct websocket *ws, char **dst, struct exchg_test_event *msg) {
	char *buf = xzalloc(1<<10);
	struct bitstamp_websocket *b = ws->priv;

	*dst = buf;

	if (msg->type == EXCHG_EVENT_WS_PROTOCOL)
		return proto_read(buf, (struct bitstamp_proto *)
				  msg->data.protocol_private);

	struct fake_book_update *u = &msg->data.book;
	struct bitstamp_channel *c = &b->channels[u->pair];
	return write_orders(buf, u, c->diff_subbed &&
			    (!c->full_subbed || c->full_unsubbed));
}

static int bitstamp_ws_matches(struct websocket *w, enum exchg_pair p) {
	struct bitstamp_websocket *b = w->priv;
	return b->channels[p].diff_subbed || b->channels[p].full_subbed;
}

static int get_channel(char *c, enum exchg_pair *p, bool *is_full) {
	char *quote = c;

	while (*quote && *quote != '\"')
		quote++;
	if (!*quote) {
		fprintf(stderr, "%s: unquoted\n", __func__);
		return -1;
	}
	if (quote - c < 6 + strlen("order_book_")) {
		fprintf(stderr, "%s: too small\n", __func__);
		return -1;
	}
	if (!strncmp(c, "diff_order_book_", strlen("diff_order_book_")))
		*is_full = false;
	else if (!strncmp(c, "order_book_", strlen("order_book_")))
		*is_full = true;
	else {
		fprintf(stderr, "%s: bad channel\n", __func__);
		return -1;
	}
	char pair[7];
	memcpy(pair, quote-6, 6);
	pair[6] = 0;
	if (exchg_str_to_pair(p, pair)) {
		fprintf(stderr, "%s: bad pair\n", __func__);
		return -1;
	}
	return 0;
}

static void bitstamp_ws_write(struct websocket *w, char *buf, size_t len) {
	struct bitstamp_websocket *b = w->priv;
	enum exchg_pair p;
	bool is_full;

	// TODO: actually parse it
	if (!strncmp("{ \"event\": \"bts:subscribe\","
		     "\"data\": { \"channel\": \"", buf,
		     strlen("{ \"event\": \"bts:subscribe\","
			    "\"data\": { \"channel\": \""))) {
		if (get_channel(buf + strlen("{ \"event\": \"bts:subscribe\","
					     "\"data\": { \"channel\": \""),
				&p, &is_full))
			return;
		if (is_full) {
			b->channels[p].full_subbed = true;
		} else {
			b->channels[p].diff_subbed = true;
			struct bitstamp_proto *bp = xzalloc(sizeof(*bp));
			bp->type = NONSENSE_DIFF;
			bp->pair = p;
			exchg_fake_queue_ws_protocol(w, bp);
		}
	} else if (!strncmp("{ \"event\": \"bts:unsubscribe\","
			    "\"data\": { \"channel\": \"", buf,
			    strlen("{ \"event\": \"bts:unsubscribe\","
				   "\"data\": { \"channel\": \""))) {
		if (get_channel(buf + strlen("{ \"event\": \"bts:unsubscribe\","
					     "\"data\": { \"channel\": \""),
				&p, &is_full))
			return;
		if (is_full) {
			struct bitstamp_proto *bp = xzalloc(sizeof(*bp));
			bp->type = UNSUB_SUCCEEDED;
			bp->pair = p;
			exchg_fake_queue_ws_protocol(w, bp);
			b->channels[p].full_unsubbed = true;
	        } else {
			fprintf(stderr, "Bitsamp unsubbed from diff order book?\n");
		}
	}
}

static void bitstamp_ws_destroy(struct websocket *w) {
	free(w->priv);
	free(w);
}

struct websocket *bitstamp_ws_dial(struct exchg_net_context *ctx,
				   const char *path, void *private) {
	struct websocket *s = fake_websocket_alloc(ctx, private);
	s->id = EXCHG_BITSTAMP;
	s->read = bitstamp_ws_read;
	s->write = bitstamp_ws_write;
	s->matches = bitstamp_ws_matches;
	s->destroy = bitstamp_ws_destroy;
	struct bitstamp_websocket *b = xzalloc(sizeof(*b));
	s->priv = b;
	return s;
}

extern char _binary_test_json_bitstamp_pairs_info_json_start[];
extern char _binary_test_json_bitstamp_pairs_info_json_size[];

static size_t bitstamp_pair_info_read(struct http_req *req, struct exchg_test_event *ev,
				      char **dst) {
	size_t size = (size_t)_binary_test_json_bitstamp_pairs_info_json_size;
	char *buf = xzalloc(size);
	memcpy(buf, _binary_test_json_bitstamp_pairs_info_json_start, size);
	*dst = buf;
	return size;
}

static void pair_info_fill_event(struct http_req *req, struct exchg_test_event *ev) {
	ev->type = EXCHG_EVENT_PAIRS_DATA;
}

static struct http_req *asset_pairs_dial(struct exchg_net_context *ctx,
					 const char *path, const char *method,
					 void *private) {
	if (strcmp(method, "GET")) {
		fprintf(stderr, "Bitstamp bad method for %s: %s\n", path, method);
		return NULL;
	}

	struct http_req *req = fake_http_req_alloc(ctx, private);
	req->fill_event = pair_info_fill_event;
	req->read = bitstamp_pair_info_read;
	req->write = no_http_write;
	req->add_header = no_http_add_header;
	req->destroy = fake_http_req_free;
	return req;
}

static size_t bitstamp_balance_read(struct http_req *req, struct exchg_test_event *ev,
				    char **dst) {
	char *buf = xzalloc(1000);
	char *p = buf;

	p += sprintf(p, "{ ");
	for (enum exchg_currency c = 0; c < EXCHG_NUM_CCYS; c++) {
		char s[30];
		decimal_to_str(s, &req->ctx->balances[EXCHG_BITSTAMP][c]);
		p += sprintf(p, "\"%s_available\": \"%s\", ",
			     exchg_ccy_to_str(c), s);
		// TODO: other fields too
	}
	p += sprintf(p, " }");
	*dst = buf;
	return p-buf;
}

static void balance_fill_event(struct http_req *req, struct exchg_test_event *ev) {
	ev->type = EXCHG_EVENT_BALANCES;
}

static struct http_req *balance_dial(struct exchg_net_context *ctx,
				     const char *path, const char *method,
				     void *private) {
	if (strcmp(method, "POST")) {
		fprintf(stderr, "Bitstamp bad method for %s: %s\n", path, method);
		return NULL;
	}

	struct http_req *req = fake_http_req_alloc(ctx, private);
	req->fill_event = balance_fill_event;
	req->read = bitstamp_balance_read;
	req->write = no_http_write;
	// TODO:
	req->add_header = no_http_add_header;
	req->destroy = fake_http_req_free;
	return req;
}

struct http_req *bitstamp_http_dial(struct exchg_net_context *ctx,
				    const char *path, const char *method,
				    void *private) {
	if (!strcmp(path, "/api/v2/trading-pairs-info/")) {
		return asset_pairs_dial(ctx, path, method, private);
	}
	if (!strcmp(path, "/api/v2/balance/")) {
		return balance_dial(ctx, path, method, private);
	}
	fprintf(stderr, "Bitstamp bad path: %s\n", path);
	return NULL;
}
