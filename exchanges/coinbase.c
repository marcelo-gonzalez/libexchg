// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#include <stdbool.h>
#include <stdio.h>
#include <time.h>

#include "auth.h"
#include "client.h"
#include "coinbase.h"
#include "compiler.h"
#include "exchg/decimal.h"
#include "json-helpers.h"
#include "time-helpers.h"

struct coinbase_client {
	struct coinbase_pair_info {
		char *id;
		bool subbed;
		bool watching_l2;
	} pair_info[EXCHG_NUM_PAIRS];
	struct conn *ws;
};

enum msg_type {
	TYPE_UNKNOWN,
	TYPE_SNAPSHOT,
	TYPE_L2UPDATE,
};

struct ws_msg {
	enum msg_type type;
	enum exchg_pair pair;
	bool bids_parsed;
	bool asks_parsed;
	bool changes_parsed;
	bool need_time_fill;
	bool need_fee_calc;
	int64_t update_micros;
};

static int parse_changes(struct exchg_client *cl, struct ws_msg *msg,
			 const char *json, jsmntok_t *toks,
			 int idx, const char **problem) {
	if (unlikely(toks[idx].type != JSMN_ARRAY)) {
		*problem = "non-array update data";
		return -1;
	}
	struct exchg_l2_update *upd = &cl->update;
	struct exchg_pair_info *pi;

	if (msg->pair == INVALID_PAIR) {
		msg->need_fee_calc = true;
		pi = NULL;
	} else {
		pi = &cl->pair_info[msg->pair];
	}
	if (msg->update_micros == -1) {
		msg->need_time_fill = true;
	}

	int data_idx = idx+1;
	for (int i = 0; i < toks[idx].size; i++) {
		jsmntok_t *data = &toks[data_idx];

		if (unlikely(data->type != JSMN_ARRAY)) {
			*problem = "non-array update data";
			return -1;
		}
		if (unlikely(data->size != 3)) {
			*problem = "update data with num elements != 3";
			return -1;
		}
		bool is_bid;
		struct exchg_limit_order *order;
		int *num_orders;

		if (json_streq(json, &toks[data_idx+1], "buy")) {
			is_bid = true;
			num_orders = &upd->num_bids;
		} else if (json_streq(json, &toks[data_idx+1], "sell")) {
			is_bid = false;
			num_orders = &upd->num_asks;
		} else {
			*problem = "bad side string";
			return -1;
		}
		if (*num_orders >= cl->l2_update_size &&
		    exchg_realloc_order_bufs(cl, 2 * (*num_orders + 1))) {
			*problem = "OOM";
			return -1;
		}

		order = is_bid ? &upd->bids[upd->num_bids] : &upd->asks[upd->num_asks];
		(*num_orders)++;

		order->exchange_id = EXCHG_COINBASE;
		if (unlikely(json_get_decimal(&order->price, json, &toks[data_idx+2]))) {
			*problem = "bad price";
			return -1;
		}
		if (unlikely(json_get_decimal(&order->size, json, &toks[data_idx+3]))) {
			*problem = "bad size";
			return -1;
		}
		if (pi && is_bid)
			decimal_dec_bps(&order->net_price, &order->price,
					pi->fee_bps, pi->price_decimals);
		else if (pi && !is_bid)
			decimal_inc_bps(&order->net_price, &order->price,
					pi->fee_bps, pi->price_decimals);
		if (msg->update_micros != -1)
			order->update_micros = msg->update_micros;
		data_idx += 4;
	}
	return data_idx;
}

static int parse_snapshot(struct exchg_client *cl, struct ws_msg *msg, bool is_bids,
			  const char *json, jsmntok_t *toks,
			  int idx, const char **problem) {
	struct exchg_l2_update *upd = &cl->update;
	struct exchg_pair_info *pi;

	if (msg->pair == INVALID_PAIR) {
		msg->need_fee_calc = true;
		pi = NULL;
	} else {
		pi = &cl->pair_info[msg->pair];
	}

	struct exchg_limit_order *order;
	int *num_orders;

	if (unlikely(toks[idx].type != JSMN_ARRAY)) {
		*problem = "non-array update data";
		return -1;
	}

	if (is_bids) {
		num_orders = &upd->num_bids;
	} else {
		num_orders = &upd->num_asks;
	}
	if (*num_orders + toks[idx].size > cl->l2_update_size &&
	    exchg_realloc_order_bufs(cl, *num_orders + toks[idx].size)) {
		*problem = "OOM";
		return -1;
	}
	if (is_bids) {
		order = &upd->bids[upd->num_bids];
	} else {
		order = &upd->asks[upd->num_asks];
	}
	(*num_orders) += toks[idx].size;

	int data_idx = idx+1;
	for (int i = 0; i < toks[idx].size; i++) {
		jsmntok_t *data = &toks[data_idx];

		if (unlikely(data->type != JSMN_ARRAY)) {
			*problem = "non-array update data";
			return -1;
		}
		if (unlikely(data->size != 2)) {
			*problem = "update data with num elements != 2";
			return -1;
		}

		order->exchange_id = EXCHG_COINBASE;
		if (unlikely(json_get_decimal(&order->price, json, &toks[data_idx+1]))) {
			*problem = "bad price";
			return -1;
		}
		if (unlikely(json_get_decimal(&order->size, json, &toks[data_idx+2]))) {
			*problem = "bad size";
			return -1;
		}
		if (pi && is_bids)
			decimal_dec_bps(&order->net_price, &order->price,
					pi->fee_bps, pi->price_decimals);
		else if (pi)
			decimal_inc_bps(&order->net_price, &order->price,
					pi->fee_bps, pi->price_decimals);
		order->update_micros = 0;
		data_idx += 3;
		order++;
	}
	return data_idx;
}

static int update_finish(struct exchg_client *cl, struct ws_msg *msg,
			 const char **problem) {
	if (msg->type == TYPE_UNKNOWN) {
		*problem = "no \"type\"";
		return -1;
	}
	if (msg->pair == INVALID_PAIR) {
		*problem = "no \"product_ids\"";
		return -1;
	}
	if (msg->type == TYPE_L2UPDATE) {
		if (msg->update_micros == -1) {
			*problem = "no \"time\"";
			return -1;
		}
		if (!msg->changes_parsed) {
			*problem = "no \"changes\"";
			return -1;
		}
	} else {
		if (!msg->bids_parsed && !msg->asks_parsed) {
			*problem = "no \"bids\" or \"asks\"";
			return -1;
		}
	}
	if (msg->need_fee_calc) {
		struct exchg_pair_info *pi = &cl->pair_info[msg->pair];
		for (int i = 0; i < cl->update.num_bids; i++) {
			struct exchg_limit_order *order = &cl->update.bids[i];
			decimal_dec_bps(&order->net_price, &order->price,
					pi->fee_bps, pi->price_decimals);
		}
		for (int i = 0; i < cl->update.num_asks; i++) {
			struct exchg_limit_order *order = &cl->update.asks[i];
			decimal_inc_bps(&order->net_price, &order->price,
					pi->fee_bps, pi->price_decimals);
		}
	}
	if (msg->need_time_fill) {
		for (int i = 0; i < cl->update.num_bids; i++) {
			struct exchg_limit_order *order = &cl->update.bids[i];
			order->update_micros = msg->update_micros;
		}
		for (int i = 0; i < cl->update.num_asks; i++) {
			struct exchg_limit_order *order = &cl->update.asks[i];
			order->update_micros = msg->update_micros;
		}
	}
	exchg_l2_update(cl, msg->pair);
	return 0;
}

static int ws_recv(struct exchg_client *cl, struct conn *conn,
		   const char *json, int num_toks, jsmntok_t *toks) {
	struct coinbase_client *cb = cl->priv;
	const char *problem = "";
	if (toks[0].type != JSMN_OBJECT) {
		problem = "not a JSON object";
		goto bad;
	}

	exchg_update_init(cl);
	struct ws_msg msg = {
		.type = TYPE_UNKNOWN,
		.pair = INVALID_PAIR,
		.update_micros = -1,
	};
	int key_idx = 1;
	for (int j = 0; j < toks[0].size; j++) {
		jsmntok_t *key = &toks[key_idx];
		jsmntok_t *value = &toks[key_idx+1];

		if (json_streq(json, key, "type")) {
			if (json_streq(json, value, "snapshot")) {
				msg.type = TYPE_SNAPSHOT;
			} else if (json_streq(json, value, "l2update")) {
				msg.type = TYPE_L2UPDATE;
			} else if (json_streq(json, value, "subscriptions")) {
				return 0;
			} else {
				exchg_log("Coinbase websocket sent unrecognized msg type:\n");
				json_fprintln(stderr, json, &toks[0]);
				return 0;
			}
			key_idx += 2;
		} else if (json_streq(json, key, "product_id")) {
			if (unlikely(value->type != JSMN_STRING)) {
				problem = "bad \"product_id\"";
				goto bad;
			}
			for (enum exchg_pair p = 0; p < EXCHG_NUM_PAIRS; p++) {
				struct exchg_pair_info *info = &cl->pair_info[p];
				struct coinbase_pair_info *cbinfo = &cb->pair_info[p];

				if (!info->available)
					continue;
				if (__json_streq(json, value, cbinfo->id)) {
					msg.pair = p;
					break;
				}
			}
			if (unlikely(msg.pair == INVALID_PAIR)) {
				problem = "bad \"product_id\"";
				goto bad;
			}
			key_idx += 2;
		} else if (json_streq(json, key, "bids")) {
			if (unlikely(msg.changes_parsed)) {
				problem = "\"bids\" and \"changes\" given";
				goto bad;
			}
			key_idx = parse_snapshot(cl, &msg, true, json, toks,
						 key_idx + 1, &problem);
			if (key_idx < 0)
				goto bad;
			msg.bids_parsed = true;
		} else if (json_streq(json, key, "asks")) {
			if (unlikely(msg.changes_parsed)) {
				problem = "\"asks\" and \"changes\" given";
				goto bad;
			}
			key_idx = parse_snapshot(cl, &msg, false, json, toks,
						 key_idx + 1, &problem);
			if (key_idx < 0)
				goto bad;
			msg.asks_parsed = true;
		} else if (json_streq(json, key, "changes")) {
			if (unlikely(msg.bids_parsed || msg.asks_parsed)) {
				problem = "\"bids\" or \"asks\" and \"changes\" given";
				goto bad;
			}
			key_idx = parse_changes(cl, &msg, json, toks,
						key_idx + 1, &problem);
			if (key_idx < 0)
				goto bad;
			msg.changes_parsed = true;
		} else if (json_streq(json, key, "time")) {
			int us;
			struct tm tm;
			if (unlikely(value->type != JSMN_STRING)) {
				problem = "bad \"time\"";
				goto bad;
			}
			if (unlikely(sscanf(&json[value->start], "%d-%d-%dT%d:%d:%d.%dZ",
					    &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour,
					    &tm.tm_min, &tm.tm_sec, &us) != 7)) {
				problem = "bad \"time\"";
				goto bad;
			}
			tm.tm_mon -= 1;
			tm.tm_year -= 1900;
			msg.update_micros = mktime(&tm);
			if (unlikely(msg.update_micros < 0)) {
				problem = "bad \"time\"";
				goto bad;
			}
			msg.update_micros = 1000000*msg.update_micros + us;
			key_idx += 2;
		} else {
			key_idx = json_skip(num_toks, toks, key_idx + 1);
		}
	}
	if (update_finish(cl, &msg, &problem))
		goto bad;
	return 0;

bad:
	exchg_log("Coinbase gave bad book update: %s:\n", problem);
	json_fprintln(stderr, json, &toks[0]);
	return -1;
}

static int level2_sub(struct exchg_client *cl) {
	struct coinbase_client *cb = cl->priv;

	bool send_msg = false;
	char product_ids[200];
	char *c = product_ids;
	product_ids[0] = 0;

	for (enum exchg_pair pair = 0; pair < EXCHG_NUM_PAIRS; pair++) {
		struct coinbase_pair_info *cbinfo = &cb->pair_info[pair];
		struct exchg_pair_info *info = &cl->pair_info[pair];

		if (cbinfo->watching_l2 && !info->available) {
			exchg_log("pair %s not available on Coinbase\n",
				  exchg_pair_to_str(pair));
			cbinfo->watching_l2 = false;
		} else if (cbinfo->watching_l2 && !cbinfo->subbed) {
			send_msg = true;
			cbinfo->subbed = true;
			c += sprintf(c, "\"%s\", ", cbinfo->id);
		}
	}
	if (!send_msg)
		return 0;
	// Coinbase doesn't like the last comma
	*(c-2) = 0;
	if (conn_printf(cb->ws, "{ \"type\": \"subscribe\", "
			"\"product_ids\": [%s], "
			"\"channels\": [\"level2\"] }",
			product_ids) < 0)
		return -1;
	return 0;
}

static bool level2_sub_work(struct exchg_client *cl, void *p) {
	struct coinbase_client *cb = cl->priv;

	if (!cl->pair_info_current || !conn_established(cb->ws))
		return false;

	level2_sub(cl);
	return true;
}

static int ws_on_established(struct exchg_client *cl,
			     struct conn *conn) {
	if (!cl->pair_info_current)
		return queue_work_exclusive(cl, level2_sub_work, NULL);
	else
		return level2_sub(cl);
}

static void ws_on_disconnect(struct exchg_client *cl,
			     struct conn *conn,
			     int reconnect_seconds) {
	struct coinbase_client *cb = cl->priv;
	int num_pairs_gone = 0;
	enum exchg_pair pairs_gone[EXCHG_NUM_PAIRS];
	if (reconnect_seconds < 0)
		cb->ws = NULL;
	for (enum exchg_pair pair = 0; pair < EXCHG_NUM_PAIRS; pair++) {
		struct exchg_pair_info *info = &cl->pair_info[pair];
		struct coinbase_pair_info *cbinfo = &cb->pair_info[pair];
		if (cbinfo->watching_l2 && info->available) {
			pairs_gone[num_pairs_gone++] = pair;
			exchg_book_clear(cl, pair);
		}
		cbinfo->subbed = false;
	}
	exchg_data_disconnect(cl, conn, num_pairs_gone, pairs_gone);
}

static const struct exchg_websocket_ops ws_ops = {
	.on_conn_established = ws_on_established,
	.on_disconnect = ws_on_disconnect,
	.recv = ws_recv,
};

static int coinbase_l2_subscribe(struct exchg_client *cl,
				 enum exchg_pair pair) {
	struct coinbase_client *cb = cl->priv;
	struct coinbase_pair_info *ci = &cb->pair_info[pair];

	if (ci->subbed)
		return 0;

	ci->watching_l2 = true;

	if (cl->pair_info_current && conn_established(cb->ws))
		return level2_sub(cl);

	if (!cb->ws) {
		cb->ws = exchg_websocket_connect(cl, "ws-feed.pro.coinbase.com", "/",
						 &ws_ops);
		if (!cb->ws)
			return -1;
	}
	return 0;
}

struct pair_info_msg {
	enum exchg_currency base;
	enum exchg_currency counter;
	char *id;
	int base_decimals;
	int price_decimals;
	decimal_t base_increment;
	decimal_t quote_increment;
	decimal_t min_size;
	bool trading_disabled;
	bool online;
};

static int decimal_inc_to_places(const decimal_t *d) {
	if (d->value != 1)
		return -EINVAL;
	return d->places;
}

static int parse_info(struct exchg_client *cl, struct conn *conn,
		      int status, const char *json,
		      int num_toks, jsmntok_t *toks) {
	struct coinbase_client *cb = cl->priv;
	const char *problem = "";
	jsmntok_t *bad_tok = &toks[0];

	if (toks[0].type != JSMN_ARRAY) {
		problem = "didn't receive a JSON array\n";
		goto bad;
	}

	int obj_idx = 1;
	bool non_obj_warned = false;
	for (int i = 0; i < toks[0].size; i++) {
		bad_tok = &toks[obj_idx];
		if (toks[obj_idx].type != JSMN_OBJECT) {
			if (!non_obj_warned) {
				exchg_log("%s%s gave non-object array member (idx %d):\n",
					  conn_host(conn), conn_path(conn), i);
				json_fprintln(stderr, json, &toks[0]);
				non_obj_warned = true;
			}
			obj_idx = json_skip(num_toks, toks, obj_idx);
			continue;
		}

		struct pair_info_msg msg = {
			.base = -1,
			.counter = -1,
		};
		int key_idx = obj_idx + 1;

		for (int j = 0; j < toks[obj_idx].size; j++) {
			jsmntok_t *key = &toks[key_idx];
			jsmntok_t *value = &toks[key_idx+1];

			if (json_streq(json, key, "id")) {
				int err = json_strdup(&msg.id, json, value);
				if (err == ENOMEM) {
					exchg_log("%s: OOM\n", __func__);
					return -1;
				}
				if (err) {
					problem = "bad \"id\" field";
					goto bad;
				}
			} else if (json_streq(json, key, "base_currency")) {
				if (json_get_currency(&msg.base, json, value))
					goto skip;
			} else if (json_streq(json, key, "quote_currency")) {
				if (json_get_currency(&msg.counter, json, value))
					goto skip;
			} else if (json_streq(json, key, "status")) {
				if (json_streq(json, value, "online"))
					msg.online = true;
			} else if (json_streq(json, key, "trading_disabled")) {
				if (json_get_bool(&msg.trading_disabled, json, value)) {
					problem = "bad \"trading_disabled\" field";
					free(msg.id);
					goto bad;
				}
			} else if (json_streq(json, key, "base_min_size")) {
				if (json_get_decimal(&msg.min_size, json, value)) {
					problem = "bad \"base_min_size\" field";
					free(msg.id);
					goto bad;
				}
			} else if (json_streq(json, key, "base_increment")) {
				if (json_get_decimal(&msg.base_increment, json, value)) {
					problem = "bad \"base_increment\" field";
					free(msg.id);
					goto bad;
				}
			} else if (json_streq(json, key, "quote_increment")) {
				if (json_get_decimal(&msg.quote_increment, json, value)) {
					problem = "bad \"quote_increment\" field";
					free(msg.id);
					goto bad;
				}
			}
			key_idx = json_skip(num_toks, toks, key_idx + 1);
		}
		enum exchg_pair pair;
		if (!msg.id) {
			problem = "no \"id\" field";
			goto bad;
		}
		if (msg.base == -1) {
			problem = "no \"base_currency\" field";
			free(msg.id);
			goto bad;
		}
		if (msg.counter == -1) {
			problem = "no \"quote_currency\" field";
			free(msg.id);
			goto bad;
		}
		if (decimal_is_zero(&msg.min_size)) {
			problem = "no \"base_min_size\" field";
			free(msg.id);
			goto bad;
		}
		if (decimal_is_zero(&msg.base_increment)) {
			problem = "no \"base_increment\" field";
			free(msg.id);
			goto bad;
		}
		if (decimal_is_zero(&msg.quote_increment)) {
			problem = "no \"quote_increment\" field";
			free(msg.id);
			goto bad;
		}
		enum exchg_join_type j = exchg_ccy_join(&pair, msg.base, msg.counter);
		if (j == JOIN_TYPE_ERROR) {
			exchg_log("Coinbase offers pair %s - %s. Can't currently handle this pair.\n",
				  exchg_ccy_to_str(msg.base), exchg_ccy_to_str(msg.counter));
			goto skip;
		}
		if (j == JOIN_TYPE_FIRST_COUNTER) {
			exchg_log("Coinbase has %s as base and %s as counter for %s. Can't currently handle this.\n",
				  exchg_ccy_to_str(msg.base), exchg_ccy_to_str(msg.counter),
				  exchg_pair_to_str(pair));
			goto skip;
		}

		if (msg.trading_disabled) {
			exchg_log("Coinbase indicates trading disabled in %s:\n",
				  exchg_pair_to_str(pair));
			json_fprintln(stderr, json, &toks[obj_idx]);
			goto skip;
		}
		if (!msg.online) {
			exchg_log("Coinbase non-online status for %s:\n",
				  exchg_pair_to_str(pair));
			json_fprintln(stderr, json, &toks[obj_idx]);
			goto skip;
		}
		struct exchg_pair_info *pi = &cl->pair_info[pair];
		struct coinbase_pair_info *cpi = &cb->pair_info[pair];

		pi->available = true;
		pi->min_size = msg.min_size;
		pi->base_decimals = decimal_inc_to_places(&msg.base_increment);
		if (pi->base_decimals < 0) {
			problem = "bad \"base_increment\" field";
			free(msg.id);
			goto bad;
		}
		pi->price_decimals = decimal_inc_to_places(&msg.quote_increment);
		if (pi->price_decimals < 0) {
			problem = "bad \"quote_increment\" field";
			free(msg.id);
			goto bad;
		}
		pi->min_size_is_base = true;
		// TODO: get from api.pro.coinbase.com/fees
		pi->fee_bps = 50;

		cpi->id = msg.id;

		obj_idx = key_idx;
		continue;

	skip:
		free(msg.id);
		obj_idx = json_skip(num_toks, toks, obj_idx);
	}
	exchg_on_pair_info(cl);
	exchg_do_work(cl);
	return 0;

bad:
	cl->get_info_error = 1;
	exchg_log("Received bad data from %s%s %s:\n",
		  conn_host(conn), conn_path(conn), problem);
	json_fprintln(stderr, json, bad_tok);
	return -1;
}

static int add_user_agent(struct exchg_client *cl, struct conn *conn) {
	// libwebsockets sets User-agent and coinbase complains
	if (conn_add_header(conn, (unsigned char *)"User-Agent:",
			    (unsigned char *)"lws", 3))
		return 1;
	return 0;
}

static struct exchg_http_ops get_info_ops = {
	.recv = parse_info,
	.add_headers = add_user_agent,
	.on_closed = exchg_parse_info_on_closed,
};

static int coinbase_get_pair_info(struct exchg_client *cl) {
	if (!exchg_http_get("api.pro.coinbase.com", "/products", &get_info_ops, cl))
		return -1;
	return 0;
}

struct http_data {
	char timestamp[30];
	int timestamp_len;
	char hmac[HMAC_SHA256_B64_LEN];
	int hmac_len;
	void *request_private;
};

static int balances_add_headers(struct exchg_client *cl, struct conn *conn) {
	if (add_user_agent(cl, conn))
		return 1;

	struct http_data *data = conn_private(conn);
	if (conn_add_header(conn, (unsigned char *)"CB-ACCESS-KEY:",
			    cl->apikey_public, cl->apikey_public_len))
		return 1;
	if (conn_add_header(conn, (unsigned char *)"CB-ACCESS-SIGN:",
			    (unsigned char *)data->hmac, data->hmac_len))
		return 1;
	if (conn_add_header(conn, (unsigned char *)"CB-ACCESS-PASSPHRASE:",
			    (unsigned char *)cl->password, cl->password_len))
		return 1;
	if (conn_add_header(conn, (unsigned char *)"CB-ACCESS-TIMESTAMP:",
			    (unsigned char *)data->timestamp, data->timestamp_len))
		return 1;
	return 0;
}

static int balances_recv(struct exchg_client *cl, struct conn *conn,
			 int status, const char *json,
			 int num_toks, jsmntok_t *toks) {
	const char *problem = "";
	jsmntok_t *bad_tok = &toks[0];

	if (toks[0].type != JSMN_ARRAY) {
		problem = "didn't receive a JSON array\n";
		goto bad;
	}

	decimal_t balances[EXCHG_NUM_CCYS];
	int obj_idx = 1;
	bool non_obj_warned = false;

	memset(balances, 0, sizeof(balances));

	for (int i = 0; i < toks[0].size; i++) {
		bad_tok = &toks[obj_idx];
		if (toks[obj_idx].type != JSMN_OBJECT) {
			if (!non_obj_warned) {
				exchg_log("%s%s gave non-object array member (idx %d):\n",
					  conn_host(conn), conn_path(conn), i);
				json_fprintln(stderr, json, &toks[0]);
				non_obj_warned = true;
			}
			obj_idx = json_skip(num_toks, toks, obj_idx);
			continue;
		}

		int key_idx = obj_idx + 1;
		enum exchg_currency ccy = -1;
		decimal_t available;
		bool got_available = false;

		for (int j = 0; j < toks[obj_idx].size; j++) {
			jsmntok_t *key = &toks[key_idx];
			jsmntok_t *value = &toks[key_idx+1];

			if (json_streq(json, key, "currency")) {
				if (json_get_currency(&ccy, json, value))
					goto skip;
			} else if (json_streq(json, key, "available")) {
				if (json_get_decimal(&available, json, value)) {
					problem = "bad \"available\" field";
					goto bad;
				}
				got_available = true;
			}
			key_idx = json_skip(num_toks, toks, key_idx + 1);
		}
		if (ccy == -1) {
			exchg_log("%s%s sent account info with no currency:\n",
				  conn_host(conn), conn_path(conn));
			json_fprintln(stderr, json, bad_tok);
			goto skip;
		}
		if (!got_available) {
			problem = "no \"available\" field";
			goto bad;
		}
		balances[ccy] = available;
		obj_idx = key_idx;
		continue;

	skip:
		obj_idx = json_skip(num_toks, toks, obj_idx);
	}

	struct http_data *h = conn_private(conn);
	exchg_on_balances(cl, balances, h->request_private);
	return 0;

bad:
	exchg_log("Received bad data from %s%s %s:\n",
		  conn_host(conn), conn_path(conn), problem);
	json_fprintln(stderr, json, bad_tok);
	return -1;
}

static struct exchg_http_ops get_balances_ops = {
	.recv = balances_recv,
	.add_headers = balances_add_headers,
	.conn_data_size = sizeof(struct http_data),
};

static int coinbase_get_balances(struct exchg_client *cl, void *req_private) {
	struct conn *conn = exchg_http_get("api.pro.coinbase.com", "/accounts", &get_balances_ops, cl);
	if (!conn)
		return -1;
	struct http_data *data = conn_private(conn);
	int64_t time = current_seconds();
	data->timestamp_len = sprintf(data->timestamp, "%"PRId64, time);
	data->request_private = req_private;

	unsigned char to_auth[1024];
	unsigned char *auth_end = to_auth;

	memcpy(auth_end, data->timestamp, data->timestamp_len);
	auth_end += data->timestamp_len;
	auth_end = memcpy(auth_end, "GET", 3);
	auth_end += 3;
	auth_end = memcpy(auth_end, "/accounts", strlen("/accounts"));
	auth_end += strlen("/accounts");
	data->hmac_len = hmac_b64(cl->hmac_ctx, to_auth, auth_end - to_auth, data->hmac);
	if (data->hmac_len < 0) {
		conn_close(conn);
		return -1;
	}
	return 0;
}

static int64_t coinbase_place_order(struct exchg_client *cl, struct exchg_order *order,
				    struct exchg_place_order_opts *opts, void *private) {
	printf("%s not is implement\n", __func__);
	return 0;
}

static int coinbase_new_keypair(struct exchg_client *cl,
				const unsigned char *key, size_t len) {
	unsigned char *k;
	len = base64_decode(key, len, &k);
	if (len < 0)
		return len;
	if (!HMAC_Init_ex(cl->hmac_ctx, k, len, EVP_sha256(), NULL)) {
		exchg_log("%s HMAC_Init_ex() failure\n", __func__);
		free(k);
		return -1;
	}
	free(k);
	return 0;
}

static void coinbase_destroy(struct exchg_client *cl) {
	struct coinbase_client *cb = cl->priv;

	for (enum exchg_pair p = 0; p < EXCHG_NUM_PAIRS; p++)
		free(cb->pair_info[p].id);
	free(cb);
	free_exchg_client(cl);
}

struct exchg_client *alloc_coinbase_client(struct exchg_context *ctx) {
	struct exchg_client *ret = alloc_exchg_client(ctx, EXCHG_COINBASE, 2000);
	if (!ret)
		return NULL;
	struct coinbase_client *cb = malloc(sizeof(*cb));
	if (!cb) {
		exchg_log("%s: OOM\n", __func__);
		free_exchg_client(ret);
		return NULL;
	}
	memset(cb, 0, sizeof(*cb));

	ret->name = "Coinbase";
	ret->priv = cb;
	ret->l2_subscribe = coinbase_l2_subscribe;
	ret->get_pair_info = coinbase_get_pair_info;
	ret->get_balances = coinbase_get_balances;
	ret->place_order = coinbase_place_order;
	ret->new_keypair = coinbase_new_keypair;
	ret->destroy = coinbase_destroy;
	return ret;
}
