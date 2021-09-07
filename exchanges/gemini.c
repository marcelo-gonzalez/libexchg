// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#define _GNU_SOURCE

#include <ctype.h>
#include <inttypes.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <openssl/hmac.h>

#include "exchg/decimal.h"
#include "auth.h"
#include "exchg/currency.h"
#include "client.h"
#include "gemini.h"
#include "json-helpers.h"
#include "time-helpers.h"

struct gemini_client {
	bool order_events_sub_acked;
	bool priv_ws_connected;
};

struct gemini_conn_info {
	enum exchg_pair pair;
	int64_t last_socket_sequence;
	long long last_update_millis;
	struct timespec last_heartbeat;
};

enum msg_type {
	TYPE_INVALID,
	TYPE_UPDATE,
	TYPE_HEARTBEAT,
};

struct gemini_msg {
	enum msg_type type;
	int64_t seq;
	int64_t timestamp;
	bool events_recvd;
};

struct order_data {
	enum exchg_side side;
	bool is_change;
	bool got_price;
	bool got_size;
};

static int parse_events(struct exchg_client *cl, struct gemini_msg *msg,
			enum exchg_pair pair, const char *json, int num_toks,
			jsmntok_t *toks, int data_idx) {
	jsmntok_t *data = &toks[data_idx];
	struct exchg_pair_info *pi = &cl->pair_info[pair];

	if (data->type != JSMN_ARRAY) {
		exchg_log("received non-array update data:\n");
		json_fprintln(stderr, json, &toks[data_idx]);
		return -1;
	}
	if (data->size < 1)
		return 0;

	int idx = data_idx + 1;
	int key_idx;
	for (int i = 0; i < data->size; i++, idx = key_idx) {
		if (toks[idx].type != JSMN_OBJECT) {
			exchg_log("Gemini sent non-object update"
				  " datapoint (number %d):\n", i);
			json_fprintln(stderr, json, &toks[0]);
			return -1;
		}

		decimal_t price, size;
		struct order_data data = {
			.side = -1,
		};
		bool skip = false;

		key_idx = idx + 1;
		for (int j = 0; j < toks[idx].size; j++) {
			jsmntok_t *key = &toks[key_idx];
			jsmntok_t *value = &toks[key_idx+1];

			if (json_streq(json, key, "type")) {
				if (!json_streq(json, value, "change")) {
					key_idx = json_skip(num_toks, toks, idx);
					skip = true;
					break;
				}
				data.is_change = true;
				key_idx += 2;
			} else if (json_streq(json, key, "side")) {
				if (json_streq(json, value, "bid")) {
					data.side = EXCHG_SIDE_BUY;
				} else if (json_streq(json, value, "ask")) {
					data.side = EXCHG_SIDE_SELL;
				} else
					goto out_bad;
				key_idx += 2;
			} else if (json_streq(json, key, "remaining")) {
				if (json_get_decimal(&size, json, value))
					goto out_bad;
				data.got_size = true;
				key_idx += 2;
			} else if (json_streq(json, key, "price")) {
				if (json_get_decimal(&price, json, value))
					goto out_bad;
				data.got_price = true;
				key_idx += 2;
			} else {
				key_idx = json_skip(num_toks, toks, key_idx+1);
			}
		}
		if (skip)
			continue;
		if (data.side == -1 || !data.is_change || !data.got_price ||
		    !data.got_size) {
			exchg_log("gemini sent incomplete order "
				  "update (number %d):\n", i);
			json_fprintln(stderr, json, &toks[0]);
			return -1;
		}

		int *next;
		struct exchg_limit_order *to_fill;
		if (data.side == EXCHG_SIDE_BUY) {
			next = &cl->update.num_bids;
			to_fill = &cl->update.bids[*next];
		} else {
			next = &cl->update.num_asks;
			to_fill = &cl->update.asks[*next];
		}

		if (*next >= cl->l2_update_size &&
		    exchg_realloc_order_bufs(cl, 2 * cl->l2_update_size))
			return -1;

		to_fill->exchange_id = cl->id;
		to_fill->price = price;
		to_fill->size = size;
		to_fill->update_micros = msg->timestamp;
		if (data.side == EXCHG_SIDE_BUY)
			decimal_dec_bps(&to_fill->net_price, &to_fill->price,
					pi->fee_bps, pi->price_decimals);
		else
			decimal_inc_bps(&to_fill->net_price, &to_fill->price,
					pi->fee_bps, pi->price_decimals);
		(*next)++;
		continue;

	out_bad:
		exchg_log("gemini sent bad order update:\n");
		json_fprintln(stderr, json, &toks[idx]);
	}
	msg->events_recvd = true;
	return idx;
}

static int msg_finish(struct exchg_client *cl, struct conn *conn,
		      struct gemini_msg *msg, enum exchg_pair pair) {
	switch (msg->type) {
	case TYPE_INVALID:
		return 0;
	case TYPE_HEARTBEAT:
		if (msg->seq != -1)
			return 1;
		else
			return 0;
	case TYPE_UPDATE:
		if (msg->seq == -1 || !msg->events_recvd || msg->timestamp == -1)
			return 0;
		exchg_l2_update(cl, pair);
		return 1;
	default:
		exchg_log("%s: bad type (%d) ?\n", __func__, msg->type);
		return -1;
	}
}

static int gemini_recv(struct exchg_client *cl, struct conn *conn,
		       char *json, int num_toks, jsmntok_t *toks) {
	char problem[100];
	struct gemini_conn_info *gc = conn_private(conn);
	struct gemini_msg msg = {
		.type = TYPE_INVALID,
		.seq = -1,
		.timestamp = -1,
	};
	bool need_timestamp = false;

	if (num_toks < 3)
		return 0;

	if (toks[0].type != JSMN_OBJECT) {
		sprintf(problem, "not an object");
		goto bad;
	}

	exchg_update_init(cl);

	int key_idx = 1;
	for (int i = 0; i < toks[0].size; i++) {
		jsmntok_t *key = &toks[key_idx];
		jsmntok_t *value = key + 1;

		if (json_streq(json, key, "type")) {
			if (json_streq(json, value, "update")) {
				msg.type = TYPE_UPDATE;
			} else if (json_streq(json, value, "heartbeat")) {
				msg.type = TYPE_HEARTBEAT;
				clock_gettime(CLOCK_MONOTONIC, &gc->last_heartbeat);
			} else {
				sprintf(problem, "bad \"type\" field");
				goto bad;
			}
			key_idx += 2;
		} else if (json_streq(json, key, "socket_sequence")) {
			if (json_get_int64(&msg.seq, json, value)) {
				sprintf(problem, "bad \"socket_sequence\"");
				goto bad;
			}
			if (msg.seq != gc->last_socket_sequence + 1) {
				sprintf(problem, "socket_sequence gap (%"PRId64
					" (got) vs %"PRId64" (expected))",
					msg.seq, gc->last_socket_sequence + 1);
				goto bad;
			}
			gc->last_socket_sequence = msg.seq;
			key_idx += 2;
		} else if (json_streq(json, key, "events")) {
			if (msg.timestamp == -1)
				need_timestamp = true;
			key_idx = parse_events(cl, &msg, gc->pair, json,
					       num_toks, toks, key_idx+1);
			if (key_idx < 0)
				return -1;
		} else if (json_streq(json, key, "timestampms")) {
			if (json_get_int64(&msg.timestamp, json, value)) {
				sprintf(problem, "bad \"timestampms\" field");
				goto bad;
			}
			msg.timestamp *= 1000;
			key_idx += 2;
		} else {
			key_idx = json_skip(num_toks, toks, key_idx + 1);
		}

		int r = msg_finish(cl, conn, &msg, gc->pair);
		if (r < 0)
			return -1;
		if (r)
			return 0;
	}

	if (msg.type != TYPE_UPDATE || msg.seq == -1 ||
	    !msg.events_recvd) {
		sprintf(problem, "incomplete message");
		goto bad;
	}

	if (!need_timestamp)
		return 0;

	if (msg.timestamp == -1)
		msg.timestamp = 0;

	for (int i = 0; i < cl->update.num_bids; i++) {
		cl->update.bids[i].update_micros = msg.timestamp;
	}
	for (int i = 0; i < cl->update.num_asks; i++) {
		cl->update.asks[i].update_micros = msg.timestamp;
	}
	exchg_l2_update(cl, gc->pair);
	return 0;

bad:
	exchg_log("Gemini sent bad order book update: %s:\n", problem);
	json_fprintln(stderr, json, &toks[0]);
	return -1;
}

static int gemini_conn_established(struct exchg_client *cl,
				   struct conn *conn) {
	return 0;
}

static void gemini_on_disconnect(struct exchg_client *cl,
				 struct conn *conn, int reconnect_seconds) {
	struct gemini_conn_info *gc = conn_private(conn);
	exchg_book_clear(cl, gc->pair);
	gc->last_socket_sequence = -1;
	exchg_data_disconnect(cl, conn, 1, &gc->pair);
}

static const struct exchg_websocket_ops websocket_ops = {
	.on_conn_established = gemini_conn_established,
	.on_disconnect = gemini_on_disconnect,
	.recv = gemini_recv,
	.conn_data_size = sizeof(struct gemini_conn_info),
};

static int gemini_connect(struct exchg_client *cl, enum exchg_pair pair) {
	const char *host;
	char path[50];

	sprintf(path, "/v1/marketdata/%s?heartbeat=true", exchg_pair_to_str(pair));
	if (cl->ctx->opts.sandbox)
		host = "api.sandbox.gemini.com";
	else
		host = "api.gemini.com";

	struct conn *c = exchg_websocket_connect(cl, host, path, &websocket_ops);
	if (!c)
		return -1;

	struct gemini_conn_info *gc = conn_private(c);
	gc->last_socket_sequence = -1;
	gc->pair = pair;
	return 0;
}

#define ARRAY_SIZE(x) sizeof(x) / sizeof(*x)

// seems like there's no API to fetch this?
// just lives at https://docs.gemini.com/websocket-api/#symbols-and-minimums
static const struct symbol_info {
	enum exchg_pair pair;
	int min_order;
	int base_decimals;
	int price_decimals;
} symbol_info[] = {
	{ EXCHG_PAIR_BTCUSD, 5, 8, 2},
	{ EXCHG_PAIR_ETHUSD, 3, 6, 2 },
	{ EXCHG_PAIR_ETHBTC, 3, 6, 5 },
	{ EXCHG_PAIR_ZECUSD, 3, 6, 2 },
	{ EXCHG_PAIR_ZECBTC, 3, 6, 5 },
	{ EXCHG_PAIR_ZECETH, 3, 6, 4 },
	{ EXCHG_PAIR_ZECBCH, 3, 6, 4 },
	{ EXCHG_PAIR_ZECLTC, 3, 6, 3 },
	{ EXCHG_PAIR_BCHUSD, 3, 6, 2 },
	{ EXCHG_PAIR_BCHBTC, 3, 6, 5 },
	{ EXCHG_PAIR_BCHETH, 3, 6, 4 },
	{ EXCHG_PAIR_LTCUSD, 2, 5, 2 },
	{ EXCHG_PAIR_LTCBTC, 2, 5, 5 },
	{ EXCHG_PAIR_LTCETH, 2, 5, 4 },
	{ EXCHG_PAIR_LTCBCH, 2, 5, 4 },
	{ EXCHG_PAIR_DAIUSD, 1, 6, 5 },
};

struct find_conn_arg {
	bool found;
	enum exchg_pair pair;
};

int find_conn(struct conn *conn, void *private) {
	struct gemini_conn_info *gc = conn_private(conn);
	struct find_conn_arg *arg = private;

	if (conn_type(conn) == CONN_TYPE_WS &&
	    !conn_disconnecting(conn) && gc->pair == arg->pair) {
		arg->found = true;
		return 1;
	}
	return 0;
}

static int gemini_l2_subscribe(struct exchg_client *cl,
			       enum exchg_pair pair) {
	struct find_conn_arg arg = { .pair = pair };
	for_each_conn(cl, find_conn, &arg);
	if (arg.found)
		return 0;

	return gemini_connect(cl, pair);
}

struct http_data {
	char *payload;
	int payload_len;
	char hmac[HMAC_SHA384_HEX_LEN];
	int hmac_len;
	char private[];
};

static void *http_data_private(struct http_data *d) {
	return d->private;
}

static int http_add_headers(struct exchg_client *cl, struct conn *conn) {
	struct http_data *data = conn_private(conn);

	if (conn_add_header(conn, (unsigned char *)"X-GEMINI-APIKEY:",
			    cl->apikey_public, cl->apikey_public_len))
		return 1;
	if (conn_add_header(conn, (unsigned char *)"X-GEMINI-PAYLOAD:",
			    (unsigned char *)data->payload, data->payload_len))
		return 1;

	return conn_add_header(conn, (unsigned char *)"X-GEMINI-SIGNATURE:",
			       (unsigned char *)data->hmac, data->hmac_len);
}

static void http_on_closed(struct exchg_client *cl, struct conn *conn) {
	struct http_data *data = conn_private(conn);

	free(data->payload);
}

static int gemini_conn_auth(struct http_data *data, HMAC_CTX *hmac_ctx,
			    const char *request, size_t len) {
	data->payload_len = base64_encode((unsigned char *)request, len, &data->payload);
	if (data->payload_len < 0)
		return -1;
	data->hmac_len = hmac_hex(hmac_ctx, (unsigned char *)data->payload,
				  data->payload_len, data->hmac, HEX_LOWER);
	if (data->hmac_len < 0) {
		free(data->payload);
		return -1;
	}
	return 0;
}

struct gemini_order_update {
	int64_t client_oid;
	bool got_is_live;
	bool is_live;
	bool is_cancelled;
	decimal_t size;
	bool got_size;
	jsmntok_t *reason;
	jsmntok_t *message;
};

// We get order updates on the websocket and the HTTP request placing
// the order.  So only give an order update if it seems that the new
// message has more recent info than what was has been gotten so far
static void order_update(struct exchg_client *cl, struct order_info *oi,
			 enum exchg_order_status new_status, decimal_t *new_size,
			 bool cancel_rejected) {
	struct exchg_order_info *info = &oi->info;
	bool update = false;

	if (info->opts.immediate_or_cancel && new_status == EXCHG_ORDER_OPEN)
		new_status = EXCHG_ORDER_PENDING;

	switch (info->status) {
	case EXCHG_ORDER_FINISHED:
	case EXCHG_ORDER_CANCELED:
	case EXCHG_ORDER_ERROR:
		return;
	case EXCHG_ORDER_UNSUBMITTED:
		update |= new_status == EXCHG_ORDER_SUBMITTED;
	case EXCHG_ORDER_SUBMITTED:
		update |= new_status == EXCHG_ORDER_PENDING;
	case EXCHG_ORDER_PENDING:
		update |= new_status == EXCHG_ORDER_OPEN;
	case EXCHG_ORDER_OPEN:
		update |= new_status == EXCHG_ORDER_FINISHED ||
			new_status == EXCHG_ORDER_CANCELED ||
			new_status == EXCHG_ORDER_ERROR;
	}
	if (update)
		info->status = new_status;

	if (decimal_cmp(&info->filled_size, new_size) < 0) {
		update = true;
		info->filled_size = *new_size;
	}
	if (!info->cancelation_failed && cancel_rejected) {
		update = true;
		info->cancelation_failed = true;
	}

	if (update)
		exchg_order_update(cl, oi);
}

static int parse_order_update_field(struct gemini_order_update *msg, const char *json,
				    int num_toks, jsmntok_t *toks, int key_idx,
				    const char **problem) {
	jsmntok_t *key = &toks[key_idx];
	jsmntok_t *value = key + 1;

	if (json_streq(json, key, "client_order_id")) {
		if (json_get_int64(&msg->client_oid, json, value)) {
			*problem = "bad \"client_order_id\"";
			return -1;
		}
		return key_idx + 2;
	} else if (json_streq(json, key, "is_live")) {
		if (json_get_bool(&msg->is_live, json, value)) {
			*problem = "bad \"is_live\"";
			return -1;
		}
		msg->got_is_live = true;
		return key_idx + 2;
	} else if (json_streq(json, key, "is_cancelled")) {
		if (json_get_bool(&msg->is_cancelled, json, value)) {
			*problem = "bad \"is_cancelled\"";
			return -1;
		}
		return key_idx + 2;
	} else if (json_streq(json, key, "executed_amount")) {
		if (json_get_decimal(&msg->size, json, value)) {
			*problem = "bad \"executed_amount\"";
			return -1;
		}
		msg->got_size = true;
		return key_idx + 2;
	} else if (json_streq(json, key, "reason")) {
		msg->reason = value;
	} else if (json_streq(json, key, "message")) {
		msg->message = value;
	}
	return json_skip(num_toks, toks, key_idx+1);
}

static int place_order_recv(struct exchg_client *cl, struct conn *conn,
			    int status, char *json, int num_toks, jsmntok_t *toks) {
	const char *problem;
	struct http_data *data = conn_private(conn);
	int64_t id = *(int64_t *)http_data_private(data);
	struct order_info *oi = exchg_order_lookup(cl, id);
	struct exchg_order_info *info = &oi->info;

	struct gemini_order_update msg = {
		.client_oid = -1,
	};

	if (!oi)
		return 0;

	if (toks[0].type != JSMN_OBJECT) {
		problem = "non-object JSON";
		goto bad;
	}

	int key_idx = 1;
	for (int i = 0; i < toks[0].size; i++) {
		key_idx = parse_order_update_field(&msg, json, num_toks, toks, key_idx, &problem);
		if (key_idx < 0)
			goto bad;
	}

	enum exchg_order_status order_status;
	if (status == 200) {
		if (msg.client_oid == -1) {
			problem = "missing \"client_order_id\"";
			goto bad;
		}
		if (id != msg.client_oid) {
			exchg_log("Gemini sent order update for "
				  "for different client_order_id over POST to %s%s: "
				  "expected: %"PRId64", got: %"PRId64"\n",
				  conn_host(conn), conn_path(conn), id, msg.client_oid);
			return -1;
		}
		if (!msg.got_is_live) {
			problem = "missing \"is_live\"";
			goto bad;
		}
		if (!msg.got_size) {
			problem = "missing \"executed_amount\"";
			goto bad;
		}
		if (msg.is_cancelled) {
			order_status = EXCHG_ORDER_CANCELED;
			order_err_cpy(info, json, msg.reason);
		} else if (!msg.is_live)
			order_status = EXCHG_ORDER_FINISHED;
		else
			order_status = EXCHG_ORDER_OPEN;
	} else {
		order_status = EXCHG_ORDER_ERROR;
		if (!msg.message)
			msg.message = msg.reason;
		order_err_cpy(info, json, msg.message);
	}
	order_update(cl, oi, order_status, &msg.size, false);
	return 0;

bad:
	snprintf(info->err, EXCHG_ORDER_ERR_SIZE, "Gemini sent bad update");
	exchg_log("%s: %s:\n", info->err, problem);
	json_fprintln(stderr, json, &toks[0]);
	info->status = EXCHG_ORDER_ERROR;
	exchg_order_update(cl, oi);
	return 0;
}

static void place_order_on_err(struct exchg_client *cl, struct conn *conn,
			       const char *err) {
	struct http_data *data = conn_private(conn);
	int64_t id = *(int64_t *)http_data_private(data);
	struct order_info *info = exchg_order_lookup(cl, id);

	if (!info)
		return;
	info->info.status = EXCHG_ORDER_ERROR;
	if (err)
		strncpy(info->info.err, err, EXCHG_ORDER_ERR_SIZE);
	else
		strncpy(info->info.err, "<unknown>", EXCHG_ORDER_ERR_SIZE);
	exchg_order_update(cl, info);
}

const static struct exchg_http_ops trade_http_ops = {
	.recv = place_order_recv,
	.add_headers = http_add_headers,
	.on_closed = http_on_closed,
	.on_error = place_order_on_err,
	.conn_data_size = sizeof(struct http_data) + sizeof(int64_t),
};

static int64_t gemini_place_order(struct exchg_client *cl, struct exchg_order *order,
				  struct exchg_place_order_opts *opts, void *private) {
	const char *host;
	if (cl->ctx->opts.sandbox)
		host = "api.sandbox.gemini.com";
	else
		host = "api.gemini.com";
	struct conn *conn = exchg_http_post(host, "/v1/order/new", &trade_http_ops, cl);
	if (!conn)
		return -1;
	struct order_info *oi = exchg_new_order(cl, order, opts, private);
	if (!oi) {
		conn_close(conn);
		return -ENOMEM;
	}
	struct exchg_order_info *info = &oi->info;

	char request[300];
	char size_str[30], price_str[30];
	const char *options = info->opts.immediate_or_cancel ?
		", \"options\": [\"immediate-or-cancel\"]" : "";
	const char *side = info->order.side == EXCHG_SIDE_BUY ? "buy" : "sell";

	decimal_to_str(size_str, &info->order.size);
	decimal_to_str(price_str, &info->order.price);

	int len = sprintf(request,
			  "{ \"nonce\": %lu, \"request\": \"/v1/order/new\", "
			  "\"client_order_id\": \"%" PRId64 "\", \"symbol\": \"%s\", "
			  "\"amount\": \"%s\", \"price\": \"%s\", \"side\": \"%s\", "
			  "\"type\": \"exchange limit\"%s}",
			  current_micros(), info->id, exchg_pair_to_str(info->order.pair),
			  size_str, price_str, side, options);

	struct http_data *data = conn_private(conn);
	if (gemini_conn_auth(data, cl->hmac_ctx, request, len)) {
		conn_close(conn);
		order_info_free(cl, oi);
		return -1;
	}
	*(int64_t *)http_data_private(data) = info->id;
	info->status = EXCHG_ORDER_SUBMITTED;
	return info->id;
}

static int gemini_cancel_order(struct exchg_client *cl, int64_t id) {
	printf("sorry dunno how to cancel %s orders\n", exchg_name(cl));
	return -1;
}

static int gemini_balances_recv(struct exchg_client *cl, struct conn *conn, int status,
				char *json, int num_toks, jsmntok_t *toks) {
	if (num_toks < 1)
		return 0;

	if (status != 200) {
		exchg_log("Gemini error getting balances:\n");
		json_fprintln(stderr, json, &toks[0]);
		return -1;
	}

	if (toks[0].type != JSMN_ARRAY) {
		exchg_log("Gemini sent non-array balance info:\n");
		json_fprintln(stderr, json, &toks[0]);
		return -1;
	}

	decimal_t balances[EXCHG_NUM_CCYS];
	memset(balances, 0, sizeof(balances));

	int data_idx = 1;
	int key_idx;
	for (int i = 0; i < toks[0].size; i++, data_idx = key_idx) {
		if (toks[data_idx].type != JSMN_OBJECT) {
			exchg_log("Gemini sent non-object balance info:\n");
			json_fprintln(stderr, json, &toks[data_idx]);
			return -1;
		}
		enum exchg_currency currency = -1;
		decimal_t amount;
		bool got_amount = false;
		bool got_type = false;

		key_idx = data_idx + 1;
		for (int j = 0; j < toks[data_idx].size; j++) {
			jsmntok_t *key = &toks[key_idx];
			jsmntok_t *value = &toks[key_idx+1];

			if (json_streq(json, key, "type")) {
				if (!json_streq(json, value, "exchange")) {
					exchg_log("Gemini sent balances info "
						  "with unexpected type field:\n");
					json_fprintln(stderr, json, &toks[data_idx]);
					return -1;
				}
				got_type = true;
				key_idx += 2;
			} else if (json_streq(json, key, "currency")) {
				if (json_get_currency(&currency, json, value)) {
					exchg_log("Gemini sent balance info for "
						  "unknown currency:\n");
					json_fprintln(stderr, json, &toks[data_idx]);
					goto skip;
				}
				key_idx += 2;
			} else if (json_streq(json, key, "available")) {
				if (json_get_decimal(&amount, json, value)) {
					exchg_log("Gemini sent bad available "
						  "amount:\n");
					json_fprintln(stderr, json, &toks[data_idx]);
					return -1;
				}
				got_amount = true;
				key_idx += 2;
			} else {
				key_idx = json_skip(num_toks, toks, key_idx+1);
			}
		}
		if (!got_amount || currency == -1 || !got_type) {
			exchg_log("Gemini sent incomplete balance info:\n");
			json_fprintln(stderr, json, &toks[data_idx]);
			return -1;
		}
		balances[currency] = amount;
		continue;
	skip:
		key_idx = json_skip(num_toks, toks, data_idx);
	}

	struct http_data *data = conn_private(conn);
	exchg_on_balances(cl, balances, *(void**)http_data_private(data));
	// TODO: make this a separate BALANCES_OK
	cl->state |= EXCH_MAY_TRADE;
	return 0;
}

static int gemini_get_pair_info(struct exchg_client *cl) { return 0; }

const static struct exchg_http_ops balances_http_ops = {
	.recv = gemini_balances_recv,
	.add_headers = http_add_headers,
	.on_closed = http_on_closed,
	.conn_data_size = sizeof(struct http_data) + sizeof(void *),
};

static int gemini_get_balances(struct exchg_client *cl, void *req_private) {
	const char *host;
	if (cl->ctx->opts.sandbox)
		host = "api.sandbox.gemini.com";
	else
		host = "api.gemini.com";
	struct conn *c = exchg_http_post(host, "/v1/balances", &balances_http_ops, cl);
	if (!c)
		return -1;
	struct http_data *data = conn_private(c);
	char request[100];

	int len = sprintf(request, "{ \"nonce\": %lu, \"request\": \"/v1/balances\" }",
			  current_micros());
	if (gemini_conn_auth(data, cl->hmac_ctx, request, len)) {
		conn_close(c);
		return -1;
	}
	*(void **)http_data_private(data) = req_private;
	return 0;
}

static void gemini_destroy(struct exchg_client *cli) {
	free(cli->priv);
	free_exchg_client(cli);
}

static int parse_event_object(struct exchg_client *cl, struct conn *conn,
			      char *json, int num_toks, jsmntok_t *toks) {
	struct gemini_client *g = cl->priv;
	int key_idx = 1;

	for (int i = 0; i < toks[0].size; i++) {
		jsmntok_t *key = &toks[key_idx];
		jsmntok_t *value = key + 1;

		if (json_streq(json, key, "type")) {
			if (json_streq(json, value, "subscription_ack")) {
				g->order_events_sub_acked = true;
				exchg_on_event(cl, EXCHG_PRIVATE_WS_ONLINE);
				return 0;
			} else if (json_streq(json, value, "heartbeat")) {
				return 0;
			}
		}

		key_idx = json_skip(num_toks, toks, key_idx+1);
	}

	exchg_log("Gemini order events websocket sent unrecognized update:\n");
	json_fprintln(stderr, json, &toks[0]);
	return 0;
}

enum order_event_type {
	ORDER_UNKNOWN,
	ORDER_ACCEPTED,
	ORDER_REJECTED,
	ORDER_BOOKED,
	ORDER_FILL,
	ORDER_CANCELLED,
	ORDER_CANCEL_REJECTED,
	ORDER_CLOSED,
};

struct gemini_order_event {
	enum order_event_type type;
	enum exchg_order_status status;
	struct gemini_order_update update;
};

static int order_events_recv(struct exchg_client *cl, struct conn *conn,
			     char *json, int num_toks, jsmntok_t *toks) {
	const char *problem = "";

	if (toks[0].type == JSMN_OBJECT)
		return parse_event_object(cl, conn, json, num_toks, toks);
	if (toks[0].type != JSMN_ARRAY) {
		problem = "not an object or array";
		goto bad;
	}

	int obj_idx = 1;
	bool warn = false;
	for (int element = 0; element < toks[0].size; element++) {
		if (toks[obj_idx].type != JSMN_OBJECT) {
			warn = true;
			goto skip;
		}
		struct gemini_order_event event = {
			.type = ORDER_UNKNOWN,
			.update = {
				.client_oid = -1,
			},
		};
		int key_idx = obj_idx + 1;

		for (int i = 0; i < toks[obj_idx].size; i++) {
			jsmntok_t *key = &toks[key_idx];
			jsmntok_t *value = key + 1;

			if (json_streq(json, key, "type")) {
				if (json_streq(json, value, "accepted")) {
					event.type = ORDER_ACCEPTED;
				} else if (json_streq(json, value, "rejected")) {
					event.type = ORDER_REJECTED;
				} else if (json_streq(json, value, "booked")) {
					event.type = ORDER_BOOKED;
				} else if (json_streq(json, value, "fill")) {
					event.type = ORDER_FILL;
				} else if (json_streq(json, value, "cancelled")) {
					event.type = ORDER_CANCELLED;
				} else if (json_streq(json, value, "cancel_rejected")) {
					event.type = ORDER_CANCEL_REJECTED;
				} else if (json_streq(json, value, "closed")) {
					event.type = ORDER_CLOSED;
				} else {
					exchg_log("Gemini order events websocket sent unrecognized update type:\n");
					json_fprintln(stderr, json, &toks[obj_idx]);
					goto skip;
				}
				key_idx += 2;
			} else {
				key_idx = parse_order_update_field(&event.update, json, num_toks,
								   toks, key_idx, &problem);
				if (key_idx < 0)
					goto bad;
			}
		}
		struct order_info *oi = exchg_order_lookup(cl, event.update.client_oid);
		if (!oi)
			goto skip;
		struct exchg_order_info *info = &oi->info;

		switch (event.type) {
		case ORDER_UNKNOWN:
			exchg_log("Gemini sent order update with no \"type\":\n");
			json_fprintln(stderr, json, &toks[obj_idx]);
			goto skip;
		case ORDER_ACCEPTED:
			event.status = EXCHG_ORDER_PENDING;
			break;
		case ORDER_REJECTED:
			event.status = EXCHG_ORDER_ERROR;
			order_err_cpy(info, json, event.update.reason);
			break;
		case ORDER_BOOKED:
			event.status = EXCHG_ORDER_OPEN;
			break;
		case ORDER_FILL:
			if (event.update.got_is_live && !event.update.is_live)
				event.status = EXCHG_ORDER_FINISHED;
			else
				event.status = EXCHG_ORDER_OPEN;
			break;
		case ORDER_CANCELLED:
			event.status = EXCHG_ORDER_CANCELED;
			order_err_cpy(info, json, event.update.reason);
			break;
		case ORDER_CLOSED:
			event.status = EXCHG_ORDER_FINISHED;
			break;
		case ORDER_CANCEL_REJECTED:
			event.status = EXCHG_ORDER_PENDING;
			break;
		}
		if (event.type != ORDER_ACCEPTED && event.type != ORDER_REJECTED &&
		    event.type != ORDER_CANCEL_REJECTED) {
			if (!event.update.got_size) {
				problem = "missing \"executed_amount\"";
				goto bad;
			}
		}
		order_update(cl, oi, event.status, &event.update.size, event.type == ORDER_CANCEL_REJECTED);
		obj_idx = key_idx;
		continue;

	skip:
		obj_idx = json_skip(num_toks, toks, obj_idx);
	}

	if (warn) {
		exchg_log("%s%s sent data with non-object elements:\n", conn_host(conn), conn_path(conn));
		json_fprintln(stderr, json, &toks[0]);
	}
	return 0;
bad:
	exchg_log("%s%s sent bad update: %s:\n", conn_host(conn), conn_path(conn), problem);
	json_fprintln(stderr, json, &toks[0]);
	return -1;
}

static void order_events_on_disconnect(struct exchg_client *cl,
				       struct conn *conn, int reconnect_seconds) {
	struct http_data *data = conn_private(conn);
	struct gemini_client *g = cl->priv;

	free(data->payload);
	g->order_events_sub_acked = false;
	if (reconnect_seconds < 0)
		g->priv_ws_connected = false;
}

static const struct exchg_websocket_ops order_events_ops = {
	.add_headers = http_add_headers,
	.recv = order_events_recv,
	.on_disconnect = order_events_on_disconnect,
	.conn_data_size = sizeof(struct http_data),
};

static const char *gemini_host(struct exchg_client *cl) {
	if (cl->ctx->opts.sandbox)
		return "api.sandbox.gemini.com";
	else
		return "api.gemini.com";
}

static int gemini_priv_ws_connect(struct exchg_client *cl) {
	struct gemini_client *g = cl->priv;

	if (g->priv_ws_connected)
		return 0;

	g->priv_ws_connected = true;
	struct conn *conn = exchg_websocket_connect(cl, gemini_host(cl),
						    "/v1/order/events", &order_events_ops);
	if (!conn)
		return -1;

	char request[100];
	int len = sprintf(request, "{ \"nonce\": %lu, \"request\": \"/v1/order/events\" }",
			  current_micros());
	if (gemini_conn_auth(conn_private(conn), cl->hmac_ctx, request, len)) {
		conn_close(conn);
		return -1;
	}
	return 0;
}

static bool gemini_priv_ws_online(struct exchg_client *cl) {
	struct gemini_client *g = cl->priv;
	return g->order_events_sub_acked;
}

static int gemini_new_keypair(struct exchg_client *cl,
			      const unsigned char *key, size_t len) {
	if (!HMAC_Init_ex(cl->hmac_ctx, key, len, EVP_sha384(), NULL)) {
		exchg_log("%s HMAC_Init_ex() failure\n", __func__);
		return -1;
	}
	return 0;
}

struct exchg_client *alloc_gemini_client(struct exchg_context *ctx) {
	struct exchg_client *ret = alloc_exchg_client(ctx, EXCHG_GEMINI, 8000);
	if (!ret)
		return NULL;

	for (int i = 0; i < ARRAY_SIZE(symbol_info); i++) {
		const struct symbol_info *s = &symbol_info[i];

		struct exchg_pair_info *pi = &ret->pair_info[s->pair];
		pi->available = true;
		pi->base_decimals = s->base_decimals;
		pi->price_decimals = s->price_decimals;
		// TODO: get from api.gemini.com/v1/notionalvolume
		pi->fee_bps = 35;
		pi->min_size_is_base = true;
		pi->min_size.value = 1;
		pi->min_size.places = s->min_order;
	}
	ret->pair_info_current = true;
	ret->name = "Gemini";
	ret->new_keypair = gemini_new_keypair;
	ret->get_balances = gemini_get_balances;
	ret->l2_subscribe = gemini_l2_subscribe;
	ret->get_pair_info = gemini_get_pair_info;
	ret->place_order = gemini_place_order;
	ret->cancel_order = gemini_cancel_order;
	ret->priv_ws_connect = gemini_priv_ws_connect;
	ret->priv_ws_online = gemini_priv_ws_online;
	ret->destroy = gemini_destroy;
	ret->priv = malloc(sizeof(struct gemini_client));
	if (!ret->priv) {
		exchg_log("%s: OOM\n", __func__);
		free_exchg_client(ret);
		return NULL;
	}
	memset(ret->priv, 0, sizeof(struct gemini_client));
	return ret;
}
