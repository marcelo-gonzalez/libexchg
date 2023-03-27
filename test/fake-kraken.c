// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#include <glib.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jsmn/jsmn.h>

#include "json-helpers.h"
#include "exchg/exchg.h"
#include "fake-net.h"
#include "fake-kraken.h"
#include "util.h"

struct kraken_websocket {
	struct kraken_channel {
		int subbed;
		int status_sent;
		int first_sent;
	} channels[EXCHG_NUM_PAIRS];
	jsmn_parser parser;
	jsmntok_t toks[100];
};

struct private_ws {
	bool openorders_subbed;
	jsmn_parser parser;
	jsmntok_t toks[100];
};

static void kraken_write_orders(struct buf *buf, struct kraken_websocket *k,
				struct exchg_test_l2_updates *up, enum exchg_side side) {
	struct kraken_channel *chan = &k->channels[up->pair];
	struct exchg_test_l2_update *orders;
	const char *key;
	int n;

	if (side == EXCHG_SIDE_BUY) {
		n = up->num_bids;
		orders = &up->bids[0];
		key = chan->first_sent ? "b" : "bs";
	} else {
		n = up->num_asks;
		orders = &up->asks[0];
		key = chan->first_sent ? "a" : "as";
	}

	if (!orders)
		return;

	buf_xsprintf(buf, "\"%s\": [", key);
	chan->first_sent = 1;

	for (int i = 0; i < n; i++) {
		char price[30], size[30];
		decimal_to_str(price, &orders[i].price);
		decimal_to_str(size, &orders[i].size);
		buf_xsprintf(buf, "[ \"%s\", \"%s\", \"123.456\" ], ",
			     price, size);
	}
	buf_xsprintf(buf, "], ");
}

static const char *wsname(enum exchg_pair p) {
	switch (p) {
	case EXCHG_PAIR_BTCUSD:
		return "XBT/USD";
	case EXCHG_PAIR_ETHUSD:
		return "ETH/USD";
	case EXCHG_PAIR_ETHBTC:
		return "ETH/XBT";
	case EXCHG_PAIR_ZECUSD:
		return "ZEC/USD";
	case EXCHG_PAIR_ZECBTC:
		return "ZEC/XBT";
	case EXCHG_PAIR_ZECETH:
		return NULL;
	case EXCHG_PAIR_ZECBCH:
		return NULL;
	case EXCHG_PAIR_ZECLTC:
		return NULL;
	case EXCHG_PAIR_BCHUSD:
		return "BCH/USD";
	case EXCHG_PAIR_BCHBTC:
		return "BCH/XBT";
	case EXCHG_PAIR_BCHETH:
		return "BCH/ETH";
	case EXCHG_PAIR_LTCUSD:
		return "LTC/USD";
	case EXCHG_PAIR_LTCBTC:
		return "LTC/XBT";
	case EXCHG_PAIR_LTCETH:
		return "LTC/ETH";
	case EXCHG_PAIR_DAIUSD:
		return "DAI/USD";
	case EXCHG_PAIR_NEARUSD:
		return "NEAR/USD";
	case EXCHG_PAIR_LTCBCH:
		return NULL;
	default:
		return NULL;
	}
}

static const char *kraken_ccy_str(enum exchg_currency c) {
	switch (c) {
	case EXCHG_CCY_USD:
		return "ZUSD";
	case EXCHG_CCY_BTC:
		return "XXBT";
	case EXCHG_CCY_ETH:
		return "XETH";
	case EXCHG_CCY_ZEC:
		return "XZEC";
	case EXCHG_CCY_XRP:
		return "XXRP";
	case EXCHG_CCY_LTC:
		return "XLTC";
	case EXCHG_CCY_BCH:
		return "BCH";
	case EXCHG_CCY_DAI:
		return "DAI";
	case EXCHG_CCY_NEAR:
		return "NEAR";
	default:
		return "<bad currency>";
	}
}

static enum exchg_pair wsname_to_pair(const char *json, jsmntok_t *tok) {
	if (json_streq(json, tok, "XBT/USD"))
		return EXCHG_PAIR_BTCUSD;
	else if (json_streq(json, tok, "ETH/USD"))
		return EXCHG_PAIR_ETHUSD;
	else if (json_streq(json, tok, "ETH/XBT"))
		return EXCHG_PAIR_ETHBTC;
	else if (json_streq(json, tok, "ZEC/USD"))
		return EXCHG_PAIR_ZECUSD;
	else if (json_streq(json, tok, "ZEC/XBT"))
		return EXCHG_PAIR_ZECBTC;
	else if (json_streq(json, tok, "BCH/USD"))
		return EXCHG_PAIR_BCHUSD;
	else if (json_streq(json, tok, "BCH/XBT"))
		return EXCHG_PAIR_BCHBTC;
	else if (json_streq(json, tok, "BCH/ETH"))
		return EXCHG_PAIR_BCHETH;
	else if (json_streq(json, tok, "LTC/USD"))
		return EXCHG_PAIR_LTCUSD;
	else if (json_streq(json, tok, "LTC/XBT"))
		return EXCHG_PAIR_LTCBTC;
	else if (json_streq(json, tok, "LTC/ETH"))
		return EXCHG_PAIR_LTCETH;
	else if (json_streq(json, tok, "DAI/USD"))
		return EXCHG_PAIR_LTCETH;
	else if (json_streq(json, tok, "NEAR/USD"))
		return EXCHG_PAIR_NEARUSD;
	else
		return -1;
}

enum kraken_proto_type {
	SYSTEM_STATUS,
	SUB_ACK,
	EMPTY_OPENORDERS,
};

struct kraken_proto {
	enum kraken_proto_type type;
	enum exchg_pair pair;
	struct kraken_websocket *ws;
};

static void proto_read(struct buf *buf, struct kraken_proto *p) {
	if (p->type == SYSTEM_STATUS) {
		buf_xsprintf(buf, "{ \"connectionID\": 12345, \"event\":"
			     " \"systemStatus\", \"status\": \"online\", "
			     " \"version\": \"1.7.2\" }");
	} else if (p->type == SUB_ACK) {
		p->ws->channels[p->pair].status_sent = 1;
		buf_xsprintf(buf, "{ \"channelID\": %d, \"channelName\": "
			     "\"book-1000\", \"event\": \"subscriptionStatus\","
			     " \"pair\": \"%s\", \"status\":"
			     " \"subscribed\", \"subscription\": { \"depth\": "
			     "1000, \"name\": \"book\" } }",
			     p->pair, wsname(p->pair));
	} else if (p->type == EMPTY_OPENORDERS) {
		buf_xsprintf(buf, "[[],\"openOrders\",{\"sequence\":1}]");
	}
}

static void kraken_ws_read(struct websocket_conn *ws, struct buf *buf,
			   struct exchg_test_event *msg) {
	struct exchg_test_l2_updates *up = &msg->data.book;
	struct kraken_websocket *k = ws->priv;

	if (msg->type == EXCHG_EVENT_WS_PROTOCOL) {
		proto_read(buf, (struct kraken_proto *)test_event_private(msg));
		return;
	}

	if (msg->type != EXCHG_EVENT_BOOK_UPDATE)
		return;

	if (!k->channels[up->pair].subbed || !k->channels[up->pair].status_sent) {
		fprintf(stderr, "wtf Kraken cant send event for pair %s yet\n", exchg_pair_to_str(up->pair));
		return;
	}

	buf_xsprintf(buf, "[ %d, { ", up->pair);
	kraken_write_orders(buf, k, up, EXCHG_SIDE_BUY);
	kraken_write_orders(buf, k, up, EXCHG_SIDE_SELL);
	buf_xsprintf(buf, "}, \"book-100\", \"%s\"]", wsname(up->pair));
}

static int kraken_ws_matches(struct websocket_conn *w, enum exchg_pair p) {
	struct kraken_websocket *k = w->priv;
	return k->channels[p].subbed;
}

static void kraken_ws_write(struct websocket_conn *w, const char *buf, size_t len) {
	struct kraken_websocket *k = w->priv;
	const char *problem;

	jsmn_init(&k->parser);
	int r = jsmn_parse(&k->parser, buf, len, k->toks, 100);
	if (r < 0) {
		problem = "could not parse JSON";
		goto bad;
	}
	if (r < 0) {
		problem = "no JSON tokens";
		goto bad;
	}
	if (k->toks[0].type != JSMN_OBJECT) {
		problem = "non-object JSON message";
		goto bad;
	}

	bool got_event = false;
	bool got_pair = false;

	int key_idx = 1;
	for (int i = 0; i < k->toks[0].size; i++) {
		jsmntok_t *key = &k->toks[key_idx];
		jsmntok_t *value = key + 1;

		if (json_streq(buf, key, "pair")) {
			if (value->type != JSMN_ARRAY) {
				problem = "bad pairs field";
				goto bad;
			}
			jsmntok_t *p = value + 1;
			for (int j = 0; j < value->size; j++) {
				enum exchg_pair pair = wsname_to_pair(buf, p);
				if (pair < 0) {
					problem = "bad pairs field";
					goto bad;
				}
				// TODO: be more correct around logic. e.g.
				// what if you sub twice?
				struct kraken_proto *kp = test_event_private(
					exchg_fake_queue_ws_event(w, EXCHG_EVENT_WS_PROTOCOL,
								  sizeof(struct kraken_proto)));
				kp->type = SUB_ACK;
				kp->pair = pair;
				kp->ws = k;
				k->channels[pair].subbed = 1;
			}
			got_pair = true;
		} else if (json_streq(buf, key, "event")) {
			if (!json_streq(buf, value, "subscribe")) {
				problem = "bad event";
				goto bad;
			}
			got_event = true;
		}
		key_idx = json_skip(r, k->toks, key_idx+1);
	}

	if (!got_pair) {
		problem = "no \"pair\" field";
		goto bad;
	}
	if (!got_event) {
		problem = "no \"event\" field";
		goto bad;
	}
	return;
bad:
	fprintf(stderr, "%s: %s:\n", __func__, problem);
	for (int i = 0; i < len; i++)
		fputc(buf[i], stderr);
	fputc('\n', stderr);
}

static void kraken_ws_destroy(struct websocket_conn *w) {
	struct kraken_websocket *k = w->priv;
	free(k);
	ws_conn_free(w);
}

struct websocket_conn *kraken_ws_dial(struct exchg_net_context *ctx,
				      const char *path, void *private) {
	struct websocket_conn *s = fake_websocket_alloc(ctx, private);
	s->read = kraken_ws_read;
	s->write = kraken_ws_write;
	s->matches = kraken_ws_matches;
	s->destroy = kraken_ws_destroy;
	struct kraken_websocket *kkn = xzalloc(sizeof(*kkn));
	s->priv = kkn;
	struct kraken_proto *k = test_event_private(
		exchg_fake_queue_ws_event(s, EXCHG_EVENT_WS_PROTOCOL,
					  sizeof(struct kraken_proto)));
	k->type = SYSTEM_STATUS;
	return s;
}

enum ack_type {
	ACK_ADDORDERSTATUS,
	ACK_OPENORDERS,
};

struct ack_msg {
	enum ack_type type;
	int64_t reqid;
};

struct order_cancel {
	unsigned int reqid;
	char err[100];
};

static void private_ws_read(struct websocket_conn *ws, struct buf *buf,
			    struct exchg_test_event *msg) {
	if (msg->type == EXCHG_EVENT_WS_PROTOCOL) {
		proto_read(buf, (struct kraken_proto *)test_event_private(msg));
		return;
	}
	if (msg->type == EXCHG_EVENT_ORDER_CANCEL_ACK) {
		struct order_cancel *cancel = test_event_private(msg);
		if (cancel->err[0]) {
			buf_xsprintf(buf, "{\"event\": \"cancelOrderStatus\", \"status\": \"error\","
				     "\"errorMessage\": \"%s\"", cancel->err);
			if (cancel->reqid)
				buf_xsprintf(buf, ", \"reqid\": %u", cancel->reqid);
			buf_xsprintf(buf, "}");
		} else {
			buf_xsprintf(buf, "{\"event\": \"cancelOrderStatus\", \"status\": \"ok\"");
			if (cancel->reqid)
				buf_xsprintf(buf, ", \"reqid\": %u", cancel->reqid);
			buf_xsprintf(buf, "}");
		}
		return;
	}
	if (msg->type != EXCHG_EVENT_ORDER_ACK) {
		fprintf(stderr, "%s: don't know what to do with event %d\n",
			__func__, msg->type);
		return;
	}

	const char *status;
	char cost_str[30], fee_str[30];
	char price_str[30], size_str[30];
	struct exchg_order_info *ack = &msg->data.order_ack;
	struct ack_msg *ack_msg = test_event_private(msg);

	switch (ack_msg->type) {
	case ACK_ADDORDERSTATUS:
		buf_xsprintf(buf, "{\"event\": \"addOrderStatus\", "
			     "\"status\": \"%s\", \"txid\": \"asdf\", "
			     "\"reqid\": %"PRId64", "
			     "}", ack->status != EXCHG_ORDER_ERROR ? "ok" : "test-bad-status",
			     ack_msg->reqid);
		break;
	case ACK_OPENORDERS:
		switch (ack->status) {
		case EXCHG_ORDER_PENDING:
			status = "pending";
			break;
		case EXCHG_ORDER_OPEN:
			status = "open";
			break;
		case EXCHG_ORDER_FINISHED:
			status = "closed";
			break;
		case EXCHG_ORDER_CANCELED:
			status = "canceled";
			break;
		default:
			exchg_log("kraken-test: Don't know how to generate an event for order status %d\n", ack->status);
			return;
		}

		write_prices(price_str, size_str, cost_str, fee_str,
			     &ack->order.price, &ack->filled_size, 26, 6);
		buf_xsprintf(buf, "[[{\"OTA3RV-MJC5U-T5FQE2\":{\"status\":\"%s\",\"cost\":\"%s\""
			     ",\"vol_exec\":\"%s\",\"fee\":\"%s\",\"avg_price\":\"%s\","
			     "\"lastupdated\":\"1627305317.892973\",\"userref\":%"PRId64"}"
			     "}],\"openOrders\",{\"sequence\":5}]\n",
			     status, cost_str, size_str, fee_str, price_str, ack_msg->reqid);
		break;
	}
}

static int private_ws_matches(struct websocket_conn *w, enum exchg_pair p) {
	return 0;
}

enum private_ws_event {
	EVENT_SUB,
	EVENT_ADDORDER,
	EVENT_CANCELORDER,
	EVENT_UNKNOWN,
};

enum private_ws_channel {
	CHAN_OPENORDERS,
	CHAN_UNKNOWN,
};

static void queue_ws_order_ack(struct websocket_conn *w, struct exchg_order_info *ack,
			       int64_t reqid) {
	struct exchg_test_event *ev = exchg_fake_queue_ws_event_tail(
		w, EXCHG_EVENT_ORDER_ACK, sizeof(struct ack_msg));
	ev->data.order_ack = *ack;
	struct ack_msg *msg = test_event_private(ev);
	msg->type = ACK_OPENORDERS;
	msg->reqid = reqid;
}

static void cancel_order(struct exchg_net_context *ctx, int64_t userref,
			 struct order_cancel *cancel) {
	struct test_order *o;
	struct websocket_conn *ws = fake_websocket_get(ctx, "ws-auth.kraken.com", NULL);

	LIST_FOREACH(o, &ctx->servers[EXCHG_KRAKEN].order_list, list) {
		int64_t uref = *(int64_t *)test_order_private(o);
		if (uref != userref)
			continue;
		if (decimal_cmp(&o->info.filled_size, &o->info.order.size) >= 0) {
			snprintf(cancel->err, sizeof(cancel->err),
				 "order id %"PRId64" not recognized", userref);
			return;
		}
		bool succeed = on_order_canceled(ctx, EXCHG_KRAKEN, o);
		if (!succeed) {
			snprintf(cancel->err, sizeof(cancel->err), "TestError");
		} else if (ws) {
			queue_ws_order_ack(ws, &o->info, userref);
		}
		return;
	}
	snprintf(cancel->err, sizeof(cancel->err), "order id %"PRId64" not recognized", userref);
}

static void private_ws_write(struct websocket_conn *w, const char *buf, size_t len) {
	struct private_ws *pw = w->priv;
	const char *problem;

	jsmn_init(&pw->parser);
	int r = jsmn_parse(&pw->parser, buf, len, pw->toks, 100);
	if (r < 0) {
		problem = "could not parse JSON";
		goto bad;
	}
	if (r < 1) {
		problem = "no JSON tokens";
		goto bad;
	}
	if (pw->toks[0].type != JSMN_OBJECT) {
		problem = "non-object JSON message";
		goto bad;
	}

	struct exchg_order_info ack = {};
	unsigned int reqid = 0;
	int64_t userref = -1;
	enum private_ws_event event = EVENT_UNKNOWN;
	enum private_ws_channel chan = CHAN_UNKNOWN;
	bool got_id = false, got_price = false;
	bool got_size = false, got_pair = false;
	bool got_side = false;
	int key_idx = 1;
	for (int i = 0; i < pw->toks[0].size; i++) {
		jsmntok_t *key = &pw->toks[key_idx];
		jsmntok_t *value = key + 1;

		if (json_streq(buf, key, "event")) {
			if (json_streq(buf, value, "addOrder")) {
				event = EVENT_ADDORDER;
			} else if (json_streq(buf, value, "subscribe")) {
				event = EVENT_SUB;
			} else if (json_streq(buf, value, "cancelOrder")) {
				event = EVENT_CANCELORDER;
			} else {
				problem = "bad \"event\"";
				goto bad;
			}
		} else if (json_streq(buf, key, "subscription")) {
			if (value->type != JSMN_OBJECT) {
				problem = "non object subscription";
				goto bad;
			}
			int n = value->size;
			int idx = key_idx + 2;
			for (int j = 0; j < n; j++) {
				key = &pw->toks[idx];
				value = key + 1;
				if (!json_streq(buf, key, "name")) {
					idx = json_skip(r, pw->toks, idx+1);
					continue;
				}
				if (json_streq(buf, value, "openOrders"))
					chan = CHAN_OPENORDERS;
				else {
					problem = "unrecognized channel name";
					goto bad;
				}
				idx = json_skip(r, pw->toks, idx+1);
			}
		} else if (json_streq(buf, key, "pair")) {
			ack.order.pair = wsname_to_pair(buf, value);
			if (ack.order.pair < 0) {
				problem = "bad pairs field";
				goto bad;
			}
			got_pair = true;
		} else if (json_streq(buf, key, "price")) {
			if (json_get_decimal(&ack.order.price, buf, value)) {
				problem = "bad price field";
				goto bad;
			}
			got_price = true;
		} else if (json_streq(buf, key, "type")) {
			if (json_streq(buf, value, "buy")) {
				ack.order.side = EXCHG_SIDE_BUY;
				got_side = true;
			} else if (json_streq(buf, value, "sell")) {
				ack.order.side = EXCHG_SIDE_SELL;
				got_side = true;
			} else {
				problem = "bad type field";
				goto bad;
			}
		} else if (json_streq(buf, key, "volume")) {
			if (json_get_decimal(&ack.order.size, buf, value)) {
				problem = "bad size field";
				goto bad;
			}
			got_size = true;
		} else if (json_streq(buf, key, "reqid")) {
			if (json_get_uint(&reqid, buf, value)) {
				problem = "bad reqid field";
				goto bad;
			}
			got_id = true;
		} else if (json_streq(buf, key, "timeinforce")) {
			if (json_streq(buf, value, "IOC"))
				ack.opts.immediate_or_cancel = true;
		} else if (json_streq(buf, key, "txid")) {
			if (value->type != JSMN_ARRAY) {
				problem = "bad txid field";
				goto bad;
			}
			if (value->size != 1) {
				exchg_log("FIXME: kraken test can only cancel one order at a time for now. Got this request:\n");
				json_fprintln(stderr, buf, &pw->toks[0]);
				return;
			}
			if (json_get_int64(&userref, buf, value+1)) {
				problem = "bad txid field";
				goto bad;
			}
		}
		key_idx = json_skip(r, pw->toks, key_idx+1);
	}

	if (event == EVENT_UNKNOWN) {
		problem = "no \"event\" field";
		goto bad;
	}
	if (event == EVENT_ADDORDER) {
		if (!got_pair) {
			problem = "no \"pair\" field";
			goto bad;
		}
		if (!got_size) {
			problem = "no \"volume\" field";
			goto bad;
		}
		if (!got_side) {
			problem = "no \"type\" field";
			goto bad;
		}
		if (!got_price) {
			problem = "no \"price\" field";
			goto bad;
		}
		if (!got_id) {
			problem = "no \"reqid\" field";
			goto bad;
		}
		struct test_order *o = on_order_placed(w->ctx, EXCHG_KRAKEN, &ack, sizeof(int64_t));
		*(int64_t *)test_order_private(o) = reqid;
		struct exchg_test_event *ev = exchg_fake_queue_ws_event_tail(
			w, EXCHG_EVENT_ORDER_ACK, sizeof(struct ack_msg));
		ev->data.order_ack = ack;
		if (ack.status != EXCHG_ORDER_ERROR)
			ev->data.order_ack.status = EXCHG_ORDER_PENDING;
		struct ack_msg *msg = test_event_private(ev);
		msg->type = ACK_ADDORDERSTATUS;
		msg->reqid = reqid;
		if (ack.status != EXCHG_ORDER_ERROR && pw->openorders_subbed) {
			queue_ws_order_ack(w, &ack, reqid);
		}
	} else if (event == EVENT_CANCELORDER) {
		if (userref == -1) {
			problem = "no txids given";
			goto bad;
		}
		struct exchg_test_event *ev = exchg_fake_queue_ws_event_tail(
			w, EXCHG_EVENT_ORDER_CANCEL_ACK, sizeof(struct order_cancel));
		struct order_cancel *cancel = test_event_private(ev);
		cancel->reqid = reqid;
		cancel_order(w->ctx, userref, cancel);
	} else if (event == EVENT_SUB) {
		if (chan == CHAN_UNKNOWN) {
			problem = "missing \"name\"";
			goto bad;
		}
		struct kraken_proto *kp = test_event_private(
			exchg_fake_queue_ws_event(w, EXCHG_EVENT_WS_PROTOCOL,
						  sizeof(struct kraken_proto)));
		kp->type = EMPTY_OPENORDERS;
		pw->openorders_subbed = true;
	}
	return;
bad:
	fprintf(stderr, "%s: %s:\n", __func__, problem);
	for (int i = 0; i < len; i++)
		fputc(buf[i], stderr);
	fputc('\n', stderr);
}

static void private_ws_destroy(struct websocket_conn *w) {
	free(w->priv);
	ws_conn_free(w);
}

struct websocket_conn *kraken_ws_auth_dial(struct exchg_net_context *ctx,
					   const char *path, void *private) {
	struct websocket_conn *s = fake_websocket_alloc(ctx, private);
	s->read = private_ws_read;
	s->write = private_ws_write;
	s->matches = private_ws_matches;
	s->destroy = private_ws_destroy;
	struct private_ws *pw = xzalloc(sizeof(*pw));
	s->priv = pw;
	struct kraken_proto *k = test_event_private(
		exchg_fake_queue_ws_event(s, EXCHG_EVENT_WS_PROTOCOL,
					  sizeof(struct kraken_proto)));
	k->type = SYSTEM_STATUS;
	return s;
}

extern char _binary_test_json_kraken_pair_info_json_start[];
extern char _binary_test_json_kraken_pair_info_json_end[];

static void kraken_pair_info_read(struct http_conn *req, struct exchg_test_event *ev,
				  struct buf *buf) {
	size_t size = _binary_test_json_kraken_pair_info_json_end -
		_binary_test_json_kraken_pair_info_json_start;
	buf_xcpy(buf, _binary_test_json_kraken_pair_info_json_start, size);
}

static struct http_conn *asset_pairs_dial(struct exchg_net_context *ctx,
					  const char *path, const char *method,
					  void *private) {
	if (strcmp(method, "GET")) {
		fprintf(stderr, "Kraken bad method for %s: %s\n", path, method);
		return NULL;
	}

	struct http_conn *req = fake_http_conn_alloc(ctx, EXCHG_KRAKEN,
						     EXCHG_EVENT_PAIRS_DATA, private);
	req->read = kraken_pair_info_read;
	req->write = no_http_write;
	req->add_header = no_http_add_header;
	req->destroy = fake_http_conn_free;
	return req;
}

static void balances_add_header(struct http_conn *req, const unsigned char *name,
				const unsigned char *val, size_t len) {
	// TODO:
}

static void balances_write(struct http_conn *req, const char *body, size_t len) {
	// TODO
}

static void balances_read(struct http_conn *req, struct exchg_test_event *ev,
			  struct buf *buf) {
	buf_xsprintf(buf, "{\"error\": [], \"result\": {");
	for (enum exchg_currency c = 0; c < EXCHG_NUM_CCYS; c++) {
		char s[30];
		decimal_t *balance = &req->ctx->servers[EXCHG_KRAKEN].balances[c];
		if (!decimal_is_positive(balance))
			continue;
		decimal_to_str(s, balance);
		buf_xsprintf(buf, "\"%s\": \"%s\", ", kraken_ccy_str(c), s);
	}
	buf_xsprintf(buf, "}}");
}

static void balances_free(struct http_conn *req) {
	auth_check_free((struct auth_check *)req->priv);
	fake_http_conn_free(req);
}

static struct http_conn *balances_dial(struct exchg_net_context *ctx,
				       const char *path, const char *method,
				       void *private) {
	if (strcmp(method, "POST")) {
		fprintf(stderr, "Kraken bad method for %s: %s\n", path, method);
		return NULL;
	}

	struct http_conn *req = fake_http_conn_alloc(ctx, EXCHG_KRAKEN,
						     EXCHG_EVENT_BALANCES, private);
	req->read = balances_read;
	req->write = balances_write;
	req->add_header = balances_add_header;
	req->destroy = balances_free;

	unsigned char *k = xzalloc((strlen(exchg_test_kraken_private) / 4) * 3 + 3);
	int state = 0;
	unsigned int save = 0;
	int len = g_base64_decode_step(exchg_test_kraken_private, strlen(exchg_test_kraken_private),
				       k, &state, &save);
	if (len == 0) {
		fprintf(stderr, "Kraken test could not base64 decode private apikey\n");
		exit(1);
	}

	req->priv = auth_check_alloc(strlen(exchg_test_kraken_public),
				     (unsigned char *)exchg_test_kraken_public,
				     len, k, 0, 0, EVP_sha512());
	free(k);
	return req;
}

#define FAKE_WS_TOKEN "asdfkrakentokenasdf"

static void token_read(struct http_conn *req, struct exchg_test_event *ev,
		       struct buf *buf) {
	buf_xsprintf(buf, "{\"error\":[],\"result\":{\""
		     "token\":\"" FAKE_WS_TOKEN "\",\"expires\":900}}");
}

static struct http_conn *token_dial(struct exchg_net_context *ctx,
				    const char *path, const char *method,
				    void *private) {
	struct http_conn *req = fake_http_conn_alloc(ctx, EXCHG_KRAKEN,
						     EXCHG_EVENT_HTTP_PROTOCOL, private);
	req->read = token_read;
	req->write = no_http_write;
	req->add_header = no_http_add_header;
	req->destroy = fake_http_conn_free;
	return req;
}

static void add_order_read(struct http_conn *req, struct exchg_test_event *ev,
			   struct buf *buf) {
	buf_xsprintf(buf, "{\"error\":[%s],\"result\":{\""
		     "descr\":\"fake order description\", "
		     "\"txid\": {\"OUF4EM-FRGI2-MQMWZD\"}}}",
		     ev->data.order_ack.status == EXCHG_ORDER_ERROR ?
		     "\"TestErrorBadThingHappened\"" : "");
}

struct add_order_post {
	int64_t userref;
	bool got_side;
	bool got_pair;
	bool got_price;
	bool got_size;
};

static int find_char(const char *buf, int len, int idx, char c) {
	for (; idx < len; idx++) {
		if (buf[idx] == c)
			return idx;
	}
	return -1;
}

static enum exchg_pair asset_name_to_pair(const char *c, int start, int end) {
	if (!strncmp(&c[start], "XXBTZUSD", strlen("XXBTZUSD")))
		return EXCHG_PAIR_BTCUSD;
	else if (!strncmp(&c[start], "XETHZUSD", strlen("XETHZUSD")))
		return EXCHG_PAIR_ETHUSD;
	else if (!strncmp(&c[start], "XETHXXBT", strlen("XETHXXBT")))
		return EXCHG_PAIR_ETHBTC;
	else if (!strncmp(&c[start], "XZECZUSD", strlen("XZECZUSD")))
		return EXCHG_PAIR_ZECUSD;
	else if (!strncmp(&c[start], "XZECXXBT", strlen("XZECXXBT")))
		return EXCHG_PAIR_ZECBTC;
	else if (!strncmp(&c[start], "XZECXETH", strlen("XZECXETH")))
		return EXCHG_PAIR_ZECETH;
	else if (!strncmp(&c[start], "ZECBCH", strlen("ZECBCH")))
		return EXCHG_PAIR_ZECBCH;
	else if (!strncmp(&c[start], "XZECXLTC", strlen("XZECXLTC")))
		return EXCHG_PAIR_ZECLTC;
	else if (!strncmp(&c[start], "BCHUSD", strlen("BCHUSD")))
		return EXCHG_PAIR_BCHUSD;
	else if (!strncmp(&c[start], "BCHXBT", strlen("BCHXBT")))
		return EXCHG_PAIR_BCHBTC;
	else if (!strncmp(&c[start], "BCHETH", strlen("BCHETH")))
		return EXCHG_PAIR_BCHETH;
	else if (!strncmp(&c[start], "XLTCZUSD", strlen("XLTCZUSD")))
		return EXCHG_PAIR_LTCUSD;
	else if (!strncmp(&c[start], "XLTCXXBT", strlen("XLTCXXBT")))
		return EXCHG_PAIR_LTCBTC;
	else if (!strncmp(&c[start], "LTCETH", strlen("LTCETH")))
		return EXCHG_PAIR_LTCETH;
	else if (!strncmp(&c[start], "LTCBCH", strlen("LTCBCH")))
		return EXCHG_PAIR_LTCBCH;
	else if (!strncmp(&c[start], "DAIUSD", strlen("DAIUSD")))
		return EXCHG_PAIR_DAIUSD;
	else if (!strncmp(&c[start], "NEARUSD", strlen("NEARUSD")))
		return EXCHG_PAIR_NEARUSD;
	return -1;
}

static void add_order_write(struct http_conn *req, const char *body, size_t len) {
	const char *problem = "";
	struct add_order_post request = {};
	int key = 0, key_end, val, val_end;
	struct exchg_order_info *ack = &req->read_event->data.order_ack;

	while (1) {
		key_end = find_char(body, len, key, '=');
		if (key_end < 0)
			break;
		val = key_end + 1;
		val_end = find_char(body, len, val, '&');
		if (val_end < 0)
			val_end = len-1;
		if (val == val_end) {
			exchg_log("Kraken test: bad urlencoded HTTP Body:\n");
			fwrite(body, 1, len, stderr);
			fputc('\n', stderr);
			return;
		}
		if (!strncmp(&body[key], "userref", strlen("userref"))) {
			char s[22];
			char *end;
			if (val_end-val > 21) {
				problem = "bad userref";
				goto bad;
			}
			memcpy(s, &body[val], val_end-val);
			s[val_end-val] = 0;
			request.userref = strtoll(s, &end, 10);
			if (*end) {
				problem = "bad userref";
				goto bad;
			}
		} else if (!strncmp(&body[key], "pair", strlen("pair"))) {
			ack->order.pair = asset_name_to_pair(body, val, val_end);
			if (ack->order.pair == -1) {
				problem = "bad pair";
				goto bad;
			}
			request.got_pair = true;
		} else if (!strncmp(&body[key], "price", strlen("price"))) {
			if (decimal_from_str_n(&ack->order.price, &body[val], val_end-val)) {
				problem = "bad price";
				goto bad;
			}
			request.got_price = true;
		} else if (!strncmp(&body[key], "volume", strlen("volume"))) {
			if (decimal_from_str_n(&ack->order.size, &body[val], val_end-val)) {
				problem = "bad size";
				goto bad;
			}
			request.got_size = true;
		} else if (!strncmp(&body[key], "type", strlen("type"))) {
			if (!strncmp(&body[val], "buy", strlen("buy"))) {
				ack->order.side = EXCHG_SIDE_BUY;
			} else if (!strncmp(&body[val], "sell", strlen("sell"))) {
				ack->order.side = EXCHG_SIDE_SELL;
			} else {
				problem = "bad type";
				goto bad;
			}
			request.got_side = true;
		} else if (!strncmp(&body[key], "timeinforce", strlen("timeinforce"))) {
			if (!strncmp(&body[val], "IOC", strlen("IOC")))
				ack->opts.immediate_or_cancel = true;
		}
		key = val_end + 1;
	}

	if (!request.got_side) {
		problem = "no \"type\"";
		goto bad;
	}
	if (!request.got_pair) {
		problem = "no \"pair\"";
		goto bad;
	}
	if (!request.got_price) {
		problem = "no \"price\"";
		goto bad;
	}
	if (!request.got_size) {
		problem = "no \"volume\"";
		goto bad;
	}
	if (!request.userref) {
		exchg_log("FIXME: kraken test expects to get a \"userref\" with orders for now. HTTP POST data:\n");
		fwrite(body, 1, len, stderr);
		fputc('\n', stderr);
		return;
	}

	struct test_order *o = on_order_placed(req->ctx, EXCHG_KRAKEN, ack, sizeof(int64_t));
	*(int64_t *)test_order_private(o) = request.userref;
	struct websocket_conn *ws = fake_websocket_get(req->ctx, "ws-auth.kraken.com", NULL);
	if (!ws)
		return;
	struct private_ws *pw = ws->priv;
	if (ack->status != EXCHG_ORDER_ERROR && pw->openorders_subbed) {
		queue_ws_order_ack(ws, ack, request.userref);
	}
	return;

bad:
	exchg_log("Kraken test: %s%s bad HTTP POST body: %s:\n", req->host, req->path, problem);
	fwrite(body, 1, len, stderr);
	fputc('\n', stderr);
}

static struct http_conn *add_order_dial(struct exchg_net_context *ctx,
					const char *path, const char *method,
					void *private) {
	struct http_conn *req = fake_http_conn_alloc(ctx, EXCHG_KRAKEN,
						     EXCHG_EVENT_ORDER_ACK, private);
	req->read = add_order_read;
	req->write = add_order_write;
	req->add_header = no_http_add_header;
	req->destroy = fake_http_conn_free;
	return req;
}

static void cancel_order_free(struct http_conn *req) {
	free(req->priv);
	fake_http_conn_free(req);
}

static void cancel_order_read(struct http_conn *req, struct exchg_test_event *ev,
			      struct buf *buf) {
	struct order_cancel *cancel = req->priv;
	if (cancel->err[0]) {
		buf_xsprintf(buf, "{\"error\":[\"%s\"],\"result\":{}}", cancel->err);
	} else {
		buf_xsprintf(buf, "{\"error\":[],\"result\":{\"count\": 1}}");
	}
}

static void cancel_order_write(struct http_conn *req, const char *body, size_t len) {
	const char *problem = "";
	int key = 0, key_end, val, val_end;
	unsigned int txid;
	bool got_txid = false;

	while (1) {
		key_end = find_char(body, len, key, '=');
		if (key_end < 0)
			break;
		val = key_end + 1;
		val_end = find_char(body, len, val, '&');
		if (val_end < 0)
			val_end = len-1;
		if (val == val_end) {
			exchg_log("Kraken test: bad urlencoded HTTP Body:\n");
			fwrite(body, 1, len, stderr);
			fputc('\n', stderr);
			return;
		}
		if (!strncmp(&body[key], "txid", strlen("txid"))) {
			char s[22];
			char *end;
			if (val_end-val > 21) {
				problem = "bad txid";
				goto bad;
			}
			memcpy(s, &body[val], val_end-val);
			s[val_end-val] = 0;
			txid = strtol(s, &end, 10);
			if (*end) {
				problem = "bad txid";
				goto bad;
			}
			got_txid = true;
		}
		key = val_end + 1;
	}

	if (!got_txid) {
		problem = "no txid";
		goto bad;
	}
	cancel_order(req->ctx, txid, req->priv);
	return;

bad:
	exchg_log("Kraken test: %s%s bad HTTP POST body: %s:\n", req->host, req->path, problem);
	fwrite(body, 1, len, stderr);
	fputc('\n', stderr);
}

static struct http_conn *cancel_order_dial(struct exchg_net_context *ctx,
					   const char *path, const char *method,
					   void *private) {
	struct http_conn *req = fake_http_conn_alloc(ctx, EXCHG_KRAKEN,
						     EXCHG_EVENT_ORDER_ACK, private);
	req->read = cancel_order_read;
	req->write = cancel_order_write;
	req->add_header = no_http_add_header;
	req->destroy = cancel_order_free;
	req->priv = xzalloc(sizeof(struct order_cancel));
	return req;
}

struct http_conn *kraken_http_dial(struct exchg_net_context *ctx,
				   const char *path, const char *method,
				   void *private) {
	if (!strcmp(path, "/0/public/AssetPairs")) {
		return asset_pairs_dial(ctx, path, method, private);
	} else if (!strcmp(path, "/0/private/Balance")) {
		return balances_dial(ctx, path, method, private);
	} else if (!strcmp(path, "/0/private/GetWebSocketsToken")) {
		return token_dial(ctx, path, method, private);
	} else if (!strcmp(path, "/0/private/AddOrder")) {
		return add_order_dial(ctx, path, method, private);
	} else if (!strcmp(path, "/0/private/CancelOrder")) {
		return cancel_order_dial(ctx, path, method, private);
	} else {
		fprintf(stderr, "Kraken bad http path: %s\n", path);
		return NULL;
	}
}
