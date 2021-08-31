// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jsmn/jsmn.h>

#include "json-helpers.h"
#include "exchg/exchg.h"
#include "fake-net.h"
#include "fake-coinbase.h"
#include "util.h"

extern char _binary_test_json_coinbase_products_json_start[];
extern char _binary_test_json_coinbase_products_json_size[];

static void products_read(struct http_req *req, struct exchg_test_event *ev,
			  struct buf *buf) {
	size_t size = (size_t)_binary_test_json_coinbase_products_json_size;
	buf_xcpy(buf, _binary_test_json_coinbase_products_json_start, size);
}

static struct http_req *products_dial(struct exchg_net_context *ctx,
				      const char *path, const char *method,
				      void *private) {
	if (strcmp(method, "GET")) {
		fprintf(stderr, "Coinbase bad method for %s: %s\n", path, method);
		return NULL;
	}

	struct http_req *req = fake_http_req_alloc(ctx, EXCHG_COINBASE,
						   EXCHG_EVENT_PAIRS_DATA, private);
	req->read = products_read;
	req->write = no_http_write;
	req->add_header = no_http_add_header;
	req->destroy = fake_http_req_free;
	return req;
}

static void accounts_read(struct http_req *req, struct exchg_test_event *ev,
			  struct buf *buf) {
	buf_xsprintf(buf, "[");
	for (enum exchg_currency c = 0; c < EXCHG_NUM_CCYS; c++) {
		char s[30];
		decimal_t *balance = &req->ctx->balances[EXCHG_COINBASE][c];
		decimal_to_str(s, balance);
		buf_xsprintf(buf, "{\"id\": \"234-abc-def%d\", \"currency\": \"%s\", "
			     "\"balance\": \"%s\", \"hold\": \"0.00\", \"available\": \"%s\", "
			     "\"profile_id\": \"234-abc-zyx%d\", \"trading_enabled\": true}, ",
			     c, exchg_ccy_to_upper(c), s, s, c);
	}
	buf_xsprintf(buf, "]");
}

static struct http_req *accounts_dial(struct exchg_net_context *ctx,
				      const char *path, const char *method,
				      void *private) {
	if (strcmp(method, "GET")) {
		fprintf(stderr, "Coinbase bad method for %s: %s\n", path, method);
		return NULL;
	}

	struct http_req *req = fake_http_req_alloc(ctx, EXCHG_COINBASE,
						   EXCHG_EVENT_BALANCES, private);
	req->read = accounts_read;
	req->write = no_http_write;
	// TODO: check auth stuff
	req->add_header = no_http_add_header;
	req->destroy = fake_http_req_free;
	return req;
}

struct http_req *coinbase_http_dial(struct exchg_net_context *ctx,
				    const char *path,
				    const char *method, void *private) {
	if (!strcmp(path, "/products"))
		return products_dial(ctx, path, method, private);
	else if (!strcmp(path, "/accounts"))
		return accounts_dial(ctx, path, method, private);
	else {
		exchg_log("Coinbase bad HTTP path: %s\n", path);
		return NULL;
	}
}

struct coinbase_websocket {
	struct coinbase_channel {
		bool subbed;
		bool first_sent;
	} channels[EXCHG_NUM_PAIRS];
	jsmn_parser parser;
	jsmntok_t toks[100];
};

struct coinbase_proto {
	bool new_sub[EXCHG_NUM_PAIRS];
};

static const char *coinbase_exchg_pair_to_str(enum exchg_pair p) {
	switch (p) {
	case EXCHG_PAIR_BTCUSD:
		return "BTC-USD";
	case EXCHG_PAIR_ETHUSD:
		return "ETH-USD";
	case EXCHG_PAIR_ETHBTC:
		return "ETH-BTC";
	case EXCHG_PAIR_ZECUSD:
		return "ZEC-USD";
	case EXCHG_PAIR_ZECBTC:
		return "ZEC-BTC";
	case EXCHG_PAIR_BCHUSD:
		return "BCH-USD";
	case EXCHG_PAIR_BCHBTC:
		return "BCH-BTC";
	case EXCHG_PAIR_LTCUSD:
		return "LTC-USD";
	case EXCHG_PAIR_LTCBTC:
		return "LTC-BTC";
	case EXCHG_PAIR_DAIUSD:
		return "DAI-USD";
	default:
		return NULL;
	}
}

static void proto_read(struct buf *buf, struct coinbase_proto *p) {
	buf_xsprintf(buf, "{\"type\":\"subscriptions\",\"channels\":"
		     "[{\"name\":\"level2\",\"product_ids\":[");
	for (enum exchg_pair pair = 0; pair < EXCHG_NUM_PAIRS; pair++) {
		if (p->new_sub[pair]) {
			const char *str = coinbase_exchg_pair_to_str(pair);
			if (!str) {
				buf_clear(buf);
				buf_xsprintf(buf, "{\"error\": \"bad pair\"}");
				return;
			}
			buf_xsprintf(buf, "\"%s\", ", str);
		}
	}
	buf_xsprintf(buf, "]}]}");
}

static void ws_read(struct websocket *ws, struct buf *buf,
		    struct exchg_test_event *msg) {
	if (msg->type == EXCHG_EVENT_WS_PROTOCOL) {
		proto_read(buf, (struct coinbase_proto *)test_event_private(msg));
		return;
	}
	if (msg->type != EXCHG_EVENT_BOOK_UPDATE)
		return;

	struct coinbase_websocket *cb = ws->priv;
	struct exchg_test_l2_updates *b = &msg->data.book;
	if (b->num_bids < 1 && b->num_asks < 1)
		return;
	const char *id = coinbase_exchg_pair_to_str(b->pair);
	if (!id)
		return;

	buf_xsprintf(buf, "{\"type\": \"%s\", \"product_id\": \"%s\", ",
		     cb->channels[b->pair].first_sent ? "l2update" : "snapshot", id);

	if (!cb->channels[b->pair].first_sent) {
		cb->channels[b->pair].first_sent = true;
		if (b->num_asks > 0)
			buf_xsprintf(buf, "\"asks\":[");
		for (int i = 0; i < b->num_asks; i++) {
			char price[30], size[30];
			decimal_to_str(price, &b->asks[i].price);
			decimal_to_str(size, &b->asks[i].size);
			buf_xsprintf(buf, "[\"%s\",\"%s\"],", price, size);
		}
		if (b->num_asks > 0)
			buf_xsprintf(buf, "], ");
		if (b->num_bids > 0)
			buf_xsprintf(buf, "\"bids\":[");
		for (int i = 0; i < b->num_bids; i++) {
			char price[30], size[30];
			decimal_to_str(price, &b->bids[i].price);
			decimal_to_str(size, &b->bids[i].size);
			buf_xsprintf(buf, "[\"%s\",\"%s\"],", price, size);
		}
		if (b->num_bids > 0)
			buf_xsprintf(buf, "]");
		buf_xsprintf(buf, "}");
	} else {
		buf_xsprintf(buf, "\"changes\":[");
		for (int i = 0; i < b->num_asks; i++) {
			char price[30], size[30];
			decimal_to_str(price, &b->asks[i].price);
			decimal_to_str(size, &b->asks[i].size);
			buf_xsprintf(buf, "[\"sell\",\"%s\",\"%s\"],", price, size);
		}
		for (int i = 0; i < b->num_bids; i++) {
			char price[30], size[30];
			decimal_to_str(price, &b->bids[i].price);
			decimal_to_str(size, &b->bids[i].size);
			buf_xsprintf(buf, "[\"buy\",\"%s\",\"%s\"],", price, size);
		}
		buf_xsprintf(buf, "], \"time\": \"2021-08-02T13:18:40.348975Z\"}");
	}
}

static int coinbase_str_to_pair(enum exchg_pair *dst, const char *json,
				jsmntok_t *tok) {
	if (json_streq(json, tok, "LTC-BTC")) {
		*dst = EXCHG_PAIR_LTCBTC;
		return 0;
	} else if (json_streq(json, tok, "BCH-BTC")) {
		*dst = EXCHG_PAIR_BCHBTC;
		return 0;
	} else if (json_streq(json, tok, "DAI-USD")) {
		*dst = EXCHG_PAIR_DAIUSD;
		return 0;
	} else if (json_streq(json, tok, "LTC-USD")) {
		*dst = EXCHG_PAIR_LTCUSD;
		return 0;
	} else if (json_streq(json, tok, "BTC-USD")) {
		*dst = EXCHG_PAIR_BTCUSD;
		return 0;
	} else if (json_streq(json, tok, "ZEC-BTC")) {
		*dst = EXCHG_PAIR_ZECBTC;
		return 0;
	} else if (json_streq(json, tok, "ETH-USD")) {
		*dst = EXCHG_PAIR_ETHUSD;
		return 0;
	} else if (json_streq(json, tok, "ZEC-USD")) {
		*dst = EXCHG_PAIR_ZECUSD;
		return 0;
	} else if (json_streq(json, tok, "BCH-USD")) {
		*dst = EXCHG_PAIR_BCHUSD;
		return 0;
	} else
		return -1;
}

static void ws_write(struct websocket *w, char *json, size_t len) {
	struct coinbase_websocket *c = w->priv;
	const char *problem = "";

	jsmn_init(&c->parser);
	int r = jsmn_parse(&c->parser, json, len, c->toks, 100);
	if (r < 0) {
		problem = "could not parse JSON";
		goto bad;
	}
	if (c->toks[0].type != JSMN_OBJECT) {
		problem = "non-object JSON message";
		goto bad;
	}

	bool subbed = false;
	bool new_sub[EXCHG_NUM_PAIRS];
	memset(new_sub, 0, sizeof(new_sub));

	int key_idx = 1;
	for (int i = 0; i < c->toks[0].size; i++) {
		jsmntok_t *key = &c->toks[key_idx];
		jsmntok_t *value = key + 1;

		if (json_streq(json, key, "type")) {
			if (!json_streq(json, value, "subscribe")) {
				problem = "bad \"type\" field";
				goto bad;
			}
		} else if (json_streq(json, key, "product_ids")) {
			// TODO: accept inside channels field too
			if (value->type != JSMN_ARRAY) {
				problem = "non array product_ids";
				goto bad;
			}
			jsmntok_t *product = value + 1;
			for (int j = 0; j < value->size; j++, product++) {
				enum exchg_pair pair;
				if (coinbase_str_to_pair(&pair, json, product)) {
					problem = "bad product_ids";
					json_fprintln(stdout, json, product);
					goto bad;
				}
				struct coinbase_channel *ch = &c->channels[pair];
				if (!ch->subbed) {
					subbed = true;
					ch->subbed = true;
					new_sub[pair] = true;
				}
			}
		}
		// TODO: check channels
		key_idx = json_skip(r, c->toks, key_idx+1);
	}
	if (subbed) {
		struct coinbase_proto *cp = test_event_private(
			exchg_fake_queue_ws_event(w, EXCHG_EVENT_WS_PROTOCOL,
						  sizeof(struct coinbase_proto)));
		memcpy(cp->new_sub, new_sub, sizeof(new_sub));
	}
	return;

bad:
	fprintf(stderr, "%s: %s:\n", __func__, problem);
	fwrite(json, 1, len, stderr);
	fputc('\n', stderr);
}

static int ws_matches(struct websocket *w, enum exchg_pair p) {
	struct coinbase_websocket *c = w->priv;
	return c->channels[p].subbed;
}

static void ws_destroy(struct websocket *w) {
	free(w->priv);
	free(w);
}

struct websocket *coinbase_ws_dial(struct exchg_net_context *ctx,
				   const char *path, void *private) {
	struct websocket *s = fake_websocket_alloc(ctx, private);
	s->id = EXCHG_COINBASE;
	s->read = ws_read;
	s->write = ws_write;
	s->matches = ws_matches;
	s->destroy = ws_destroy;
	struct coinbase_websocket *cb = xzalloc(sizeof(*cb));
	s->priv = cb;
	return s;
}
