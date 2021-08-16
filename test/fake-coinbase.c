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

static size_t products_read(struct http_req *req, struct exchg_test_event *ev,
			    char **dst) {
	size_t size = (size_t)_binary_test_json_coinbase_products_json_size;
	char *buf = xzalloc(size);
	memcpy(buf, _binary_test_json_coinbase_products_json_start, size);
	*dst = buf;
	return size;
}

static void products_fill_event(struct http_req *req, struct exchg_test_event *ev) {
	ev->type = EXCHG_EVENT_PAIRS_DATA;
}

static struct http_req *products_dial(struct exchg_net_context *ctx,
				      const char *path, const char *method,
				      void *private) {
	if (strcmp(method, "GET")) {
		fprintf(stderr, "Coinbase bad method for %s: %s\n", path, method);
		return NULL;
	}

	struct http_req *req = fake_http_req_alloc(ctx, private);
	req->fill_event = products_fill_event;
	req->read = products_read;
	req->write = no_http_write;
	req->add_header = no_http_add_header;
	req->destroy = fake_http_req_free;
	return req;
}

struct http_req *coinbase_http_dial(struct exchg_net_context *ctx,
				    const char *path,
				    const char *method, void *private) {
	if (!strcmp(path, "/products"))
		return products_dial(ctx, path, method, private);
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

static size_t proto_read(char *buf, struct coinbase_proto *p) {
	char *c = buf;
	c += sprintf(c, "{\"type\":\"subscriptions\",\"channels\":"
		     "[{\"name\":\"level2\",\"product_ids\":[");
	for (enum exchg_pair pair = 0; pair < EXCHG_NUM_PAIRS; pair++) {
		if (p->new_sub[pair]) {
			const char *str = coinbase_exchg_pair_to_str(pair);
			if (!str) {
				return sprintf(buf, "{\"error\": \"bad pair\"}");
			}
			c += sprintf(c, "\"%s\", ", str);
		}
	}
	c += sprintf(c, "]}]}");
	free(p);
	return c-buf;
}

static size_t ws_read(struct websocket *ws, char **dst,
		      struct exchg_test_event *msg) {
	char *buf = xzalloc(1<<12);
	*dst = buf;

	if (msg->type == EXCHG_EVENT_WS_PROTOCOL)
		return proto_read(buf, (struct coinbase_proto *)
				  msg->data.protocol_private);
	if (msg->type != EXCHG_EVENT_BOOK_UPDATE)
		return 0;

	struct coinbase_websocket *cb = ws->priv;
	struct fake_book_update *b = &msg->data.book;
	if (b->num_bids < 1 && b->num_asks < 1)
		return 0;
	const char *id = coinbase_exchg_pair_to_str(b->pair);
	if (!id)
		return 0;

	char *c = buf;
	c += sprintf(c, "{\"type\": \"%s\", \"product_id\": \"%s\", ",
		     cb->channels[b->pair].first_sent ? "l2update" : "snapshot", id);

	if (!cb->channels[b->pair].first_sent) {
		cb->channels[b->pair].first_sent = true;
		if (b->num_asks > 0)
			c += sprintf(c, "\"asks\":[");
		for (int i = 0; i < b->num_asks; i++) {
			char price[30], size[30];
			decimal_to_str(price, &b->asks[i].price);
			decimal_to_str(size, &b->asks[i].size);
			c += sprintf(c, "[\"%s\",\"%s\"],", price, size);
		}
		if (b->num_asks > 0)
			c += sprintf(c, "], ");
		if (b->num_bids > 0)
			c += sprintf(c, "\"bids\":[");
		for (int i = 0; i < b->num_bids; i++) {
			char price[30], size[30];
			decimal_to_str(price, &b->bids[i].price);
			decimal_to_str(size, &b->bids[i].size);
			c += sprintf(c, "[\"%s\",\"%s\"],", price, size);
		}
		if (b->num_bids > 0)
			c += sprintf(c, "]");
		c += sprintf(c, "}");
	} else {
		c += sprintf(c, "\"changes\":[");
		for (int i = 0; i < b->num_asks; i++) {
			char price[30], size[30];
			decimal_to_str(price, &b->asks[i].price);
			decimal_to_str(size, &b->asks[i].size);
			c += sprintf(c, "[\"sell\",\"%s\",\"%s\"],", price, size);
		}
		for (int i = 0; i < b->num_bids; i++) {
			char price[30], size[30];
			decimal_to_str(price, &b->bids[i].price);
			decimal_to_str(size, &b->bids[i].size);
			c += sprintf(c, "[\"buy\",\"%s\",\"%s\"],", price, size);
		}
		c += sprintf(c, "], \"time\": \"2021-08-02T13:18:40.348975Z\"}");
	}
	return c-buf;
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
		struct coinbase_proto *cp = xzalloc(sizeof(*cp));
		memcpy(cp->new_sub, new_sub, sizeof(new_sub));
		exchg_fake_queue_ws_protocol(w, cp);
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
