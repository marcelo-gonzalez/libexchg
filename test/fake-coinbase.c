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

static const char *coinbase_pair_to_str(enum exchg_pair p) {
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
	} else if (json_streq(json, tok, "ETH-BTC")) {
		*dst = EXCHG_PAIR_ETHBTC;
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

static void orders_read(struct http_req *req, struct exchg_test_event *ev,
			  struct buf *buf) {
	char *order_id = req->priv;
	struct exchg_order_info *ack = &ev->data.ack;
	char cost_str[30], fee_str[30];
	char price_str[30], size_str[30];

	if (!order_id)
		return;

	write_prices(price_str, size_str, cost_str, fee_str,
		     &ack->order.price, &ack->order.size, 26, 6);
	buf_xsprintf(buf, "{\"id\": \"%s\", "
		     "\"price\": \"%s\", \"size\": \"%s\", \"product_id\": \"%s\", "
		     "\"side\": \"%s\", \"stp\": \"dc\", \"type\": \"limit\", "
		     "\"time_in_force\": \"IOC\", \"post_only\": false, "
		     "\"created_at\": \"2016-12-08T20:02:28.53864Z\","
		     "\"fill_fees\": \"0\", \"filled_size\": \"0\", "
		     "\"executed_value\": \"0\", \"status\": \"pending\", "
		     "\"settled\": false }",
		     order_id, price_str, size_str, coinbase_pair_to_str(ack->order.pair),
		     ack->order.side == EXCHG_SIDE_BUY ? "buy" : "sell");
}

enum ack_type {
	ACK_DONE_OR_OPEN,
	ACK_MATCH,
	ACK_RECV,
};

struct ack_msg {
	enum ack_type type;
	char id[37];
	char *client_oid;
};

struct coinbase_websocket {
	struct coinbase_channel {
		bool l2_subbed;
		bool user_subbed;
		bool first_l2_sent;
	} channels[EXCHG_NUM_PAIRS];
	jsmn_parser parser;
	jsmntok_t toks[100];
};

static void generate_order_acks(struct exchg_net_context *ctx, struct http_req *req,
				jsmntok_t *client_oid, char *order_id) {
	struct websocket *ws = fake_websocket_get(ctx, "ws-feed.pro.coinbase.com", NULL);
	if (!ws)
		return;
	struct coinbase_websocket *cb = ws->priv;
	struct exchg_order_info *ack = &req->read_event->data.ack;
	struct exchg_test_event *recvd = exchg_fake_queue_ws_event_before(
		ws, EXCHG_EVENT_ORDER_ACK, sizeof(struct ack_msg), req->read_event);
	struct ack_msg *recv_ack = test_event_private(recvd);

	memcpy(&recvd->data.ack, ack, sizeof(*ack));
	recvd->data.ack.status = EXCHG_ORDER_PENDING;
	decimal_zero(&recvd->data.ack.filled_size);

	recv_ack->type = ACK_RECV;
	if (client_oid && json_strdup(&recv_ack->client_oid, req->body.buf, client_oid)) {
		exchg_log("%s: OOM\n", __func__);
		exit(1);
	}
	strcpy(recv_ack->id, order_id);

	if (!cb->channels[ack->order.pair].user_subbed)
		return;

	struct exchg_test_event *done = exchg_fake_queue_ws_event_after(
		ws, EXCHG_EVENT_ORDER_ACK, sizeof(struct ack_msg), recvd);
	struct ack_msg *done_ack = test_event_private(done);
	memcpy(&done->data.ack, ack, sizeof(*ack));
	done_ack->type = ACK_DONE_OR_OPEN;
	strcpy(done_ack->id, order_id);

	if (decimal_is_positive(&ack->filled_size)) {
		struct exchg_test_event *match = exchg_fake_queue_ws_event_after(
			ws, EXCHG_EVENT_ORDER_ACK, sizeof(struct ack_msg), recvd);
		struct ack_msg *match_ack = test_event_private(match);
		memcpy(&match->data.ack, ack, sizeof(*ack));
		match->data.ack.status = EXCHG_ORDER_PENDING;
		match_ack->type = ACK_MATCH;
		strcpy(match_ack->id, order_id);
	}
}

static void write_oid(char *dst, uint64_t id) {
	char n[17];

	int len = sprintf(n, "%"PRIx64, id);
	dst += sprintf(dst, "00000000-0000-0000-");
	for (int i = 0; i < 4; i++) {
		char c = '0';
		if (len - 16 + i >= 0)
			c = n[len - 16 + i];
		*dst = c;
		dst++;
	}
	*dst = '-';
	dst++;
	int i;
	for (i = 0; i < 12 - len; i++)
		dst += sprintf(dst, "0");
	int twelve_left = 0;
	if (len > 12)
		twelve_left = len - 12;
	memcpy(dst, &n[twelve_left], len - twelve_left);
	dst[len-twelve_left] = 0;
}

static void orders_write(struct http_req *req) {
	const char *problem = "";
	jsmn_parser parser;
	jsmntok_t toks[100];
	struct exchg_order_info *ack = &req->read_event->data.ack;

	if (req->body.len < 1) {
		fprintf(stderr, "no body given with POST to "
			"https://api.pro.coinbase.com/orders\n");
		return;
	}

	jsmn_init(&parser);
	int num_toks = jsmn_parse(&parser, req->body.buf, req->body.len, toks, 100);
	if (num_toks < 0) {
		problem = "could not parse JSON";
		goto bad;
	}
	if (toks[0].type != JSMN_OBJECT) {
		problem = "non-object JSON message";
		goto bad;
	}

	bool got_pair = false;
	bool got_price = false;
	bool got_size = false;
	bool got_side = false;

	jsmntok_t *client_oid = NULL;
	int key_idx = 1;
	for (int i = 0; i < toks[0].size; i++) {
		jsmntok_t *key = &toks[key_idx];
		jsmntok_t *value = key + 1;

		if (json_streq(req->body.buf, key, "price")) {
			if (json_get_decimal(&ack->order.price, req->body.buf, value)) {
				problem = "bad price";
				goto bad;
			}
			got_price = true;
		} else if (json_streq(req->body.buf, key, "size")) {
			if (json_get_decimal(&ack->order.size, req->body.buf, value)) {
				problem = "bad size";
				goto bad;
			}
			got_size = true;
		} else if (json_streq(req->body.buf, key, "side")) {
			if (json_streq(req->body.buf, value, "buy"))
				ack->order.side = EXCHG_SIDE_BUY;
			else if (json_streq(req->body.buf, value, "sell"))
				ack->order.side = EXCHG_SIDE_SELL;
			else {
				problem = "bad side";
				goto bad;
			}
			got_side = true;
		} else if (json_streq(req->body.buf, key, "product_id")) {
			if (coinbase_str_to_pair(&ack->order.pair, req->body.buf, value)) {
				problem = "bad product_id";
				goto bad;
			}
			got_pair = true;
		} else if (json_streq(req->body.buf, key, "client_oid")) {
			if (value->type != JSMN_STRING) {
				problem = "bad client_oid";
				goto bad;
			}
			client_oid = value;
		}

		key_idx = json_skip(num_toks, toks, key_idx + 1);
	}

	if (!got_pair) {
		problem = "missing product_id";
		goto bad;
	}
	if (!got_size) {
		problem = "missing size";
		goto bad;
	}
	if (!got_side) {
		problem = "missing side";
		goto bad;
	}
	if (!got_price) {
		problem = "missing price";
		goto bad;
	}

	on_order_placed(req->ctx, EXCHG_COINBASE, ack);
	char *order_id = xzalloc(37);
	write_oid(order_id, ack->id);
	generate_order_acks(req->ctx, req, client_oid, order_id);
	req->priv = order_id;
	return;

bad:
	fprintf(stderr, "%s: %s:\n", __func__, problem);
	fwrite(req->body.buf, 1, req->body.len, stderr);
	fputc('\n', stderr);
}

static void orders_destroy(struct http_req *req) {
	free(req->priv);
	fake_http_req_free(req);
}

static struct http_req *orders_dial(struct exchg_net_context *ctx,
				      const char *path, const char *method,
				      void *private) {
	if (strcmp(method, "POST")) {
		fprintf(stderr, "Coinbase bad method for %s: %s\n", path, method);
		return NULL;
	}

	struct http_req *req = fake_http_req_alloc(ctx, EXCHG_COINBASE,
						   EXCHG_EVENT_ORDER_ACK, private);
	req->read = orders_read;
	req->write = orders_write;
	// TODO: check auth stuff
	req->add_header = no_http_add_header;
	req->destroy = orders_destroy;
	return req;
}

struct http_req *coinbase_http_dial(struct exchg_net_context *ctx,
				    const char *path,
				    const char *method, void *private) {
	if (!strcmp(path, "/products"))
		return products_dial(ctx, path, method, private);
	else if (!strcmp(path, "/accounts"))
		return accounts_dial(ctx, path, method, private);
	else if (!strcmp(path, "/orders"))
		return orders_dial(ctx, path, method, private);
	else {
		exchg_log("Coinbase bad HTTP path: %s\n", path);
		return NULL;
	}
}

struct coinbase_proto {
	bool new_l2;
	bool new_user;
	bool new_l2_sub[EXCHG_NUM_PAIRS];
	bool new_user_sub[EXCHG_NUM_PAIRS];
};

static void proto_read(struct buf *buf, struct coinbase_proto *p) {
	buf_xsprintf(buf, "{\"type\":\"subscriptions\",\"channels\":[");
	if (p->new_l2) {
		buf_xsprintf(buf, "{\"name\":\"level2\",\"product_ids\":[");
		for (enum exchg_pair pair = 0; pair < EXCHG_NUM_PAIRS; pair++) {
			if (p->new_l2_sub[pair]) {
				buf_xsprintf(buf, "\"%s\", ", coinbase_pair_to_str(pair));
			}
		}
		buf_xsprintf(buf, "]}, ");
	}
	if (p->new_user) {
		buf_xsprintf(buf, "{\"name\":\"user\",\"product_ids\":[");
		for (enum exchg_pair pair = 0; pair < EXCHG_NUM_PAIRS; pair++) {
			if (p->new_user_sub[pair]) {
				buf_xsprintf(buf, "\"%s\", ", coinbase_pair_to_str(pair));
			}
		}
		buf_xsprintf(buf, "]}, ");
	}
	buf_xsprintf(buf, "]}");
}

static void ack_read(struct buf *buf, struct exchg_test_event *msg) {
	struct exchg_order_info *ack = &msg->data.ack;
	struct ack_msg *coinbase_ack = test_event_private(msg);
	const char *type_str;

	switch (coinbase_ack->type) {
	case ACK_DONE_OR_OPEN:
		if (ack->status == EXCHG_ORDER_FINISHED ||
		    ack->status == EXCHG_ORDER_CANCELED)
			type_str = "done";
		else if (ack->status == EXCHG_ORDER_OPEN)
			type_str = "open";
		else {
			exchg_log("Coinbase test: Don't know how to generate order "
				  "ack with status %d\n", ack->status);
			return;
		}
		break;
	case ACK_RECV:
		type_str = "received";
		break;
	case ACK_MATCH:
		type_str = "match";
		break;
	default:
		exchg_log("%s: bad type: %d\n", __func__, coinbase_ack->type);
		exit(1);
	}

	static int sequence;
	char cost_str[30], fee_str[30];
	char price_str[30], size_str[30];

	write_prices(price_str, size_str, cost_str, fee_str,
		     &ack->order.price, &ack->filled_size, 50, 6);

	buf_xsprintf(buf, "{\"type\": \"%s\", \"side\": \"%s\", "
		     "\"product_id\": \"%s\", \"time\": \"2021-08-31T13:13:28.295379Z\", "
		     "\"sequence\": \"%d\", \"profile_id\": \"1234-abc\", \"user_id\": \"5678-def\", "
		     "",
		     type_str, ack->order.side == EXCHG_SIDE_BUY ? "buy" : "sell",
		     coinbase_pair_to_str(ack->order.pair), sequence++);
	if (coinbase_ack->type == ACK_DONE_OR_OPEN || coinbase_ack->type == ACK_RECV) {
		buf_xsprintf(buf, "\"order_id\": \"%s\", ", coinbase_ack->id);
	} else {
		buf_xsprintf(buf, "\"trade_id\": \"%"PRId64"\", "
			     "\"maker_order_id\": \"00000000-abcd-0000-0000-abcdabcdabcd\", "
			     "\"taker_order_id\": \"%s\", ", ack->id, coinbase_ack->id);
	}
	if (coinbase_ack->type == ACK_RECV) {
		buf_xsprintf(buf, "\"order_type\": \"limit\", ");
	}
	if (coinbase_ack->type == ACK_RECV || coinbase_ack->type == ACK_MATCH) {
		buf_xsprintf(buf, "\"size\": \"%s\", ", size_str);
	}
	buf_xsprintf(buf, "\"price\": \"%s\", ", price_str);

	if (coinbase_ack->type == ACK_MATCH) {
		buf_xsprintf(buf, "\"taker_profile_id\": \"1234-abc\", \"taker_user_id\": \"5678-def\", "
			     "\"taker_fee_rate\": \"%s\"", fee_str);
	}
	if (coinbase_ack->type == ACK_DONE_OR_OPEN) {
		if (ack->status == EXCHG_ORDER_FINISHED || ack->status == EXCHG_ORDER_CANCELED) {
			const char *reason;
			if (ack->status == EXCHG_ORDER_FINISHED)
				reason = "filled";
			else
				reason = "canceled";
			buf_xsprintf(buf, "\"reason\": \"%s\", ", reason);
		}
		char rem[30];
		decimal_t remaining;
		decimal_subtract(&remaining, &ack->order.size, &ack->filled_size);
		decimal_to_str(rem, &remaining);
		buf_xsprintf(buf, "\"remaining_size\": \"%s\",", rem);
	}
	if (coinbase_ack->client_oid) {
		buf_xsprintf(buf, "\"client_oid\": \"%s\", ", coinbase_ack->client_oid);
		free(coinbase_ack->client_oid);
	}
	buf_xsprintf(buf, "}");

}

static void ws_read(struct websocket *ws, struct buf *buf,
		    struct exchg_test_event *msg) {
	if (msg->type == EXCHG_EVENT_WS_PROTOCOL) {
		proto_read(buf, (struct coinbase_proto *)test_event_private(msg));
		return;
	}
	if (msg->type == EXCHG_EVENT_ORDER_ACK) {
		ack_read(buf, msg);
		return;
	}
	if (msg->type != EXCHG_EVENT_BOOK_UPDATE)
		return;

	struct coinbase_websocket *cb = ws->priv;
	struct exchg_test_l2_updates *b = &msg->data.book;
	if (b->num_bids < 1 && b->num_asks < 1)
		return;
	const char *id = coinbase_pair_to_str(b->pair);
	if (!id)
		return;

	buf_xsprintf(buf, "{\"type\": \"%s\", \"product_id\": \"%s\", ",
		     cb->channels[b->pair].first_l2_sent ? "l2update" : "snapshot", id);

	if (!cb->channels[b->pair].first_l2_sent) {
		cb->channels[b->pair].first_l2_sent = true;
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

	bool level2_subbed = false;
	bool user_subbed = false;
	bool l2_pair_sub[EXCHG_NUM_PAIRS];
	bool user_pair_sub[EXCHG_NUM_PAIRS];

	memset(l2_pair_sub, 0, sizeof(l2_pair_sub));
	memset(user_pair_sub, 0, sizeof(user_pair_sub));

	int key_idx = 1;
	for (int i = 0; i < c->toks[0].size; i++) {
		jsmntok_t *key = &c->toks[key_idx];
		jsmntok_t *value = key + 1;

		if (json_streq(json, key, "type")) {
			if (!json_streq(json, value, "subscribe")) {
				problem = "bad \"type\" field";
				goto bad;
			}
			key_idx += 2;
		} else if (json_streq(json, key, "product_ids")) {
			if (value->type != JSMN_ARRAY) {
				problem = "non array product_ids";
				goto bad;
			}
			jsmntok_t *product = value + 1;
			for (int j = 0; j < value->size; j++, product++) {
				enum exchg_pair pair;
				if (coinbase_str_to_pair(&pair, json, product)) {
					problem = "bad product_ids";
					goto bad;
				}
				l2_pair_sub[pair] = true;
				user_pair_sub[pair] = true;
			}
			key_idx = json_skip(r, c->toks, key_idx+1);
		} else if (json_streq(json, key, "channels")) {
			if (value->type != JSMN_ARRAY) {
				problem = "non array \"channels\"";
				goto bad;
			}
			key_idx += 2;
			int n = value->size;
			for (int j = 0; j < n; j++) {
				jsmntok_t *channel = &c->toks[key_idx];

				if (channel->type == JSMN_STRING) {
					if (json_streq(json, channel, "level2"))
						level2_subbed = true;
					else if (json_streq(json, channel, "user"))
						user_subbed = true;
					key_idx++;
					continue;
				}
				if (channel->type != JSMN_OBJECT) {
					problem = "non object or string \"channels\" element";
					goto bad;
				}
				bool parsing_level2 = false;
				bool parsing_user = false;
				bool pair_included[EXCHG_NUM_PAIRS];

				memset(pair_included, 0, sizeof(pair_included));
				key_idx++;
				for (int k = 0; k < channel->size; k++) {
					key = &c->toks[key_idx];
					value = key + 1;

					if (json_streq(json, key, "name")) {
						if (json_streq(json, value, "level2")) {
							parsing_level2 = true;
							level2_subbed = true;
						} else if (json_streq(json, value, "user")) {
							parsing_user = true;
							user_subbed = true;
						} else {
							problem = "unknown channel name";
							goto bad;
						}
					} else if (json_streq(json, key, "product_ids")) {
						if (value->type != JSMN_ARRAY) {
							problem = "non array product_ids";
							goto bad;
						}
						jsmntok_t *product = value + 1;
						for (int j = 0; j < value->size; j++, product++) {
							enum exchg_pair pair;
							if (coinbase_str_to_pair(&pair, json, product)) {
								problem = "bad channels:product_ids";
								goto bad;
							}
							pair_included[pair] = true;
						}
					}
					key_idx = json_skip(r, c->toks, key_idx+1);
				}
				for (enum exchg_pair pair = 0; pair < EXCHG_NUM_PAIRS; pair++) {
					if (parsing_level2 && pair_included[pair])
						l2_pair_sub[pair] = true;
					else if (parsing_user && pair_included[pair])
						user_pair_sub[pair] = true;
				}
			}
		} else {
			key_idx = json_skip(r, c->toks, key_idx+1);
		}
	}

	bool new_l2 = false;
	bool new_user = false;
	bool new_l2_sub[EXCHG_NUM_PAIRS];
	bool new_user_sub[EXCHG_NUM_PAIRS];

	memset(new_l2_sub, 0, sizeof(new_l2_sub));
	memset(new_user_sub, 0, sizeof(new_user_sub));

	for (enum exchg_pair pair = 0; pair < EXCHG_NUM_PAIRS; pair++) {
		struct coinbase_channel *chan = &c->channels[pair];
		if (!chan->l2_subbed && l2_pair_sub[pair]) {
			new_l2 = true;
			new_l2_sub[pair] = true;
			chan->l2_subbed = true;
		}
		if (!chan->user_subbed && user_pair_sub[pair]) {
			new_user = true;
			new_user_sub[pair] = true;
			chan->user_subbed = true;
		}
	}
	if (new_l2 || new_user) {
		struct coinbase_proto *cp = test_event_private(
			exchg_fake_queue_ws_event(w, EXCHG_EVENT_WS_PROTOCOL,
						  sizeof(struct coinbase_proto)));
		memcpy(cp->new_l2_sub, new_l2_sub, sizeof(new_l2_sub));
		memcpy(cp->new_user_sub, new_user_sub, sizeof(new_user_sub));
		cp->new_l2 = new_l2;
		cp->new_user = new_user;
	}
	return;

bad:
	fprintf(stderr, "%s: %s:\n", __func__, problem);
	fwrite(json, 1, len, stderr);
	fputc('\n', stderr);
}

static int ws_matches(struct websocket *w, enum exchg_pair p) {
	struct coinbase_websocket *c = w->priv;
	return c->channels[p].l2_subbed;
}

static void ws_destroy(struct websocket *w) {
	free(w->priv);
	ws_free(w);
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
