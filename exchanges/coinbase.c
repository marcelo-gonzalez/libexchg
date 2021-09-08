// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#include <glib.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "auth.h"
#include "client.h"
#include "coinbase.h"
#include "compiler.h"
#include "exchg/decimal.h"
#include "json-helpers.h"
#include "time-helpers.h"

struct coinbase_client {
	bool watching_user_chan;
	bool user_chan_subbed;
	bool sub_acked;
	struct coinbase_pair_info {
		char *id;
		bool subbed;
		bool watching_l2;
	} pair_info[EXCHG_NUM_PAIRS];
	struct conn *ws;
	GHashTable *orders;
};

enum msg_type {
	TYPE_UNKNOWN,
	TYPE_SNAPSHOT,
	TYPE_L2UPDATE,
	TYPE_RECEIVED,
	TYPE_OPEN,
	TYPE_MATCH,
	TYPE_DONE,
	// TODO: TYPE_CHANGED,
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
	jsmntok_t *client_oid;
	jsmntok_t *order_id;
	jsmntok_t *maker_oid;
	jsmntok_t *taker_oid;
	jsmntok_t *reason;
	bool got_remaining_size;
	decimal_t remaining_size;
	bool got_size;
	decimal_t size;
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
			  const char *json, jsmntok_t *toks, int idx, const char **problem) {
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

static void do_l2_update(struct exchg_client *cl, struct ws_msg *msg) {
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
}

// 00000000-0000-0000-0005-cac7e817653c -> 0x5cac7e817653c
static int64_t parse_oid(const char *json, jsmntok_t *tok) {
	char num[17];
	char *p = num;

	if (tok->end - tok->start != 36)
		return -1;
	if (strncmp(&json[tok->start], "00000000-0000-0000-",
		    strlen("00000000-0000-0000-")))
		return -1;
	// too big...
	if (json[tok->start+19] == '8' || json[tok->start+19] == '9' ||
	    (json[tok->start+19] >= 'a' && json[tok->start+19] <= 'f'))
		return -1;

	for (int i = 19; i < 23; i++) {
		if (json[tok->start+i] != '0') {
			memcpy(num, &json[tok->start+i], 23-i);
			p += 23-i;
			break;
		}
	}
	if (p > num) {
		memcpy(p, &json[tok->start+24], 12);
		p += 12;
	} else {
		for (int i = 24; i < 36; i++) {
			if (json[tok->start+i] != '0') {
				memcpy(p, &json[tok->start+i], 36-i);
				p += 36-i;
				break;
			}
		}
	}
	if (p == num)
		return 0;
	*p = 0;
	char *end;
	long long n = strtoll(num, &end, 16);
	if (*end)
		return -1;
	return n;
}

static int msg_finish(struct exchg_client *cl, struct ws_msg *msg,
		      char *json, jsmntok_t *first_tok, const char **problem) {
	struct coinbase_client *cb = cl->priv;
	struct order_info *info;

	if (msg->pair == INVALID_PAIR) {
		*problem = "no \"product_ids\"";
		return -1;
	}
	switch (msg->type) {
	case TYPE_UNKNOWN:
		*problem = "no \"type\"";
		return -1;
	case TYPE_L2UPDATE:
		if (msg->update_micros == -1) {
			*problem = "no \"time\"";
			return -1;
		}
		if (!msg->changes_parsed) {
			*problem = "no \"changes\"";
			return -1;
		}
		break;
	case TYPE_SNAPSHOT:
		if (!msg->bids_parsed && !msg->asks_parsed) {
			*problem = "no \"bids\" or \"asks\"";
			return -1;
		}
		break;
	case TYPE_RECEIVED:
		if (!msg->client_oid)
			return 0;
		if (!msg->order_id) {
			*problem = "\"received\" message with no \"order_id\"";
			return -1;
		}
		int64_t client_oid = parse_oid(json, msg->client_oid);
		if (client_oid < 0)
			return 0;
		info = exchg_order_lookup(cl, client_oid);
		if (!info)
			return 0;
		char *id;
		if (json_strdup(&id, json, msg->order_id)) {
			*problem = "OOM copying order id";
			return -1;
		}
		g_hash_table_insert(cb->orders, id, info);
		info->info.status = EXCHG_ORDER_PENDING;
		break;
	case TYPE_MATCH:
		if (!msg->maker_oid) {
			*problem = "\"received\" message with no \"maker_order_id\"";
			return -1;
		}
		if (!msg->taker_oid) {
			*problem = "\"received\" message with no \"taker_order_id\"";
			return -1;
		}
		if (!msg->got_size) {
			*problem = "\"received\" message with no \"size\"";
			return -1;
		}
		json[msg->taker_oid->end] = 0;
		info = g_hash_table_lookup(cb->orders, &json[msg->taker_oid->start]);
		if (!info) {
			json[msg->maker_oid->end] = 0;
			info = g_hash_table_lookup(cb->orders, &json[msg->maker_oid->start]);
		}
		if (!info)
			return 0;
		decimal_add(&info->info.filled_size, &info->info.filled_size, &msg->size);
		if (info->info.opts.immediate_or_cancel)
			info->info.status = EXCHG_ORDER_PENDING;
		else
			info->info.status = EXCHG_ORDER_OPEN;
		break;
	case TYPE_OPEN:
	case TYPE_DONE:
		if (!msg->order_id) {
			*problem = "\"open\" or \"done\" message with no \"order_id\"";
			return -1;
		}
		if (!msg->got_remaining_size) {
			*problem = "\"open\" or \"done\" message with no \"remaining_size\"";
			return -1;
		}
		json[msg->order_id->end] = 0;
		info = g_hash_table_lookup(cb->orders, &json[msg->order_id->start]);
		if (!info)
			return 0;
		decimal_subtract(&info->info.filled_size, &info->info.order.size,
				 &msg->remaining_size);
		if (decimal_is_negative(&info->info.filled_size)) {
			char original[30], remaining[30];
			decimal_to_str(original, &info->info.order.size);
			decimal_to_str(remaining, &msg->remaining_size);
			exchg_log("Coinbase indicates %s remaining for order %"PRId64
				  ". This is greater than the original full size: %s\n",
				  remaining, info->info.id, original);
			decimal_zero(&info->info.filled_size);
		}
		if (msg->type == TYPE_OPEN) {
			info->info.status = EXCHG_ORDER_OPEN;
		} else {
			if (!msg->reason) {
				exchg_log("Coinbase sent \"done\" message with no \"reason\":");
				json[msg->order_id->end] = '\"';
				json_fprintln(stderr, json, first_tok);
				info->info.status = EXCHG_ORDER_FINISHED;
			} else if (json_streq(json, msg->reason, "filled"))
				info->info.status = EXCHG_ORDER_FINISHED;
			else if (json_streq(json, msg->reason, "canceled"))
				info->info.status = EXCHG_ORDER_CANCELED;
			else {
				exchg_log("Coinbase sent \"done\" message with unrecognized \"reason\":");
				json[msg->order_id->end] = '\"';
				json_fprintln(stderr, json, first_tok);
				info->info.status = EXCHG_ORDER_FINISHED;
			}
			g_hash_table_remove(cb->orders, &json[msg->order_id->start]);
		}
		break;
	}
	if (msg->type == TYPE_L2UPDATE || msg->type == TYPE_SNAPSHOT)
		do_l2_update(cl, msg);
	else
		exchg_order_update(cl, info);
	return 0;
}

static int ws_recv(struct exchg_client *cl, struct conn *conn,
		   char *json, int num_toks, jsmntok_t *toks) {
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
			} else if (json_streq(json, value, "done")) {
				msg.type = TYPE_DONE;
			} else if (json_streq(json, value, "received")) {
				msg.type = TYPE_RECEIVED;
			} else if (json_streq(json, value, "match")) {
				msg.type = TYPE_MATCH;
			} else if (json_streq(json, value, "open")) {
				msg.type = TYPE_OPEN;
			} else if (json_streq(json, value, "subscriptions")) {
				cb->sub_acked = true;
				// TODO: actually parse it to see if the user channel is there
				if (cb->watching_user_chan)
					exchg_on_event(cl, EXCHG_PRIVATE_WS_ONLINE);
				return 0;
			} else if (json_streq(json, value, "error")) {
				exchg_log("Coinbase error:\n");
				json_fprintln(stderr, json, &toks[0]);
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
			struct tm tm = {};
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
		} else if (json_streq(json, key, "client_oid")) {
			if (value->type != JSMN_STRING) {
				problem = "non-string \"client_oid\"";
				goto bad;
			}
			msg.client_oid = value;
			key_idx += 2;
		} else if (json_streq(json, key, "order_id")) {
			if (value->type != JSMN_STRING) {
				problem = "non-string \"order_id\"";
				goto bad;
			}
			msg.order_id = value;
			key_idx += 2;
		} else if (json_streq(json, key, "maker_order_id")) {
			if (value->type != JSMN_STRING) {
				problem = "non-string \"maker_order_id\"";
				goto bad;
			}
			msg.maker_oid = value;
			key_idx += 2;
		} else if (json_streq(json, key, "taker_order_id")) {
			if (value->type != JSMN_STRING) {
				problem = "non-string \"taker_order_id\"";
				goto bad;
			}
			msg.taker_oid = value;
			key_idx += 2;
		} else if (json_streq(json, key, "reason")) {
			if (value->type != JSMN_STRING) {
				problem = "non-string \"reason\"";
				goto bad;
			}
			msg.reason = value;
			key_idx += 2;
		} else if (json_streq(json, key, "remaining_size")) {
			if (json_get_decimal(&msg.remaining_size, json, value)) {
				problem = "bad \"remaining_size\"";
				goto bad;
			}
			msg.got_remaining_size = true;
			key_idx += 2;
		} else if (json_streq(json, key, "size")) {
			if (json_get_decimal(&msg.size, json, value)) {
				problem = "bad \"size\"";
				goto bad;
			}
			msg.got_size = true;
			key_idx += 2;
		} else {
			key_idx = json_skip(num_toks, toks, key_idx + 1);
		}
	}
	if (msg_finish(cl, &msg, json, &toks[0], &problem))
		goto bad;
	return 0;

bad:
	exchg_log("Coinbase gave bad update: %s:\n", problem);
	json_fprintln(stderr, json, &toks[0]);
	return -1;
}

struct coinbase_auth {
	char timestamp[30];
	int timestamp_len;
	char hmac[HMAC_SHA256_B64_LEN];
	int hmac_len;
};

static int coinbase_auth(struct coinbase_auth *auth, HMAC_CTX *hmac_ctx,
			 const char *path, const char *method,
			 const char *body, size_t body_len) {
	int64_t time = current_seconds();
	auth->timestamp_len = sprintf(auth->timestamp, "%"PRId64, time);

	unsigned char to_auth[1024];
	unsigned char *auth_end = to_auth;

	memcpy(auth_end, auth->timestamp, auth->timestamp_len);
	auth_end += auth->timestamp_len;
	auth_end = memcpy(auth_end, method, strlen(method));
	auth_end += strlen(method);
	auth_end = memcpy(auth_end, path, strlen(path));
	auth_end += strlen(path);
	memcpy(auth_end, body, body_len);
	auth_end += body_len;
	auth->hmac_len = hmac_b64(hmac_ctx, to_auth, auth_end - to_auth, auth->hmac);
	if (auth->hmac_len < 0)
		return auth->hmac_len;
	return 0;
}

static int channel_sub(struct exchg_client *cl) {
	struct coinbase_client *cb = cl->priv;
	bool level2_sub = false;
	bool user_sub = false;
	char level2[200];
	char user[200];
	char *cl2 = level2;
	char *cu = user;

	cl2 += sprintf(cl2, "{ \"name\": \"level2\", \"product_ids\": [");
	cu += sprintf(cu, "{ \"name\": \"user\", \"product_ids\": [");

	for (enum exchg_pair pair = 0; pair < EXCHG_NUM_PAIRS; pair++) {
		struct coinbase_pair_info *cbinfo = &cb->pair_info[pair];
		struct exchg_pair_info *info = &cl->pair_info[pair];

		if (cbinfo->watching_l2 && !info->available) {
			exchg_log("pair %s not available on Coinbase\n",
				  exchg_pair_to_str(pair));
			cbinfo->watching_l2 = false;
		} else if (cbinfo->watching_l2 && !cbinfo->subbed) {
			level2_sub = true;
			cbinfo->subbed = true;
			cl2 += sprintf(cl2, "\"%s\", ", cbinfo->id);
		}
		if (info->available && cb->watching_user_chan &&
		    !cb->user_chan_subbed) {
			cu += sprintf(cu, "\"%s\", ", cbinfo->id);
			user_sub = true;
		}
	}
	if (!level2_sub && !user_sub)
		return 0;

	if (level2_sub) {
		// Coinbase doesn't like the last comma
		cl2 -= 2;
		cl2 += sprintf(cl2, "]}");
	} else
		level2[0] = 0;
	if (user_sub) {
		cu -= 2;
		cu += sprintf(cu, "]}");
		cb->user_chan_subbed = true;
	} else
		user[0] = 0;

	char auth_fields[1024];
	if (user_sub) {
		struct coinbase_auth auth;
		char *au = auth_fields;

		if (coinbase_auth(&auth, cl->hmac_ctx, "/users/self/verify", "GET", NULL, 0))
			return -1;
		au += sprintf(au, ", \"signature\": \"%s\", ", auth.hmac);
		au += sprintf(au, "\"key\": \"%s\", ", cl->apikey_public);
		au += sprintf(au, "\"passphrase\": \"%s\", ", cl->password);
		au += sprintf(au, "\"timestamp\": \"%s\"", auth.timestamp);
	} else {
		auth_fields[0] = 0;
	}
	if (conn_printf(cb->ws, "{ \"type\": \"subscribe\", "
			"\"channels\": [%s%s%s]%s}", level2,
			level2_sub && user_sub ? "," : "", user, auth_fields) < 0)
		return -1;
	return 0;
}

static bool sub_work(struct exchg_client *cl, void *p) {
	struct coinbase_client *cb = cl->priv;

	if (!cl->pair_info_current || !conn_established(cb->ws))
		return false;

	channel_sub(cl);
	return true;
}

static int ws_on_established(struct exchg_client *cl,
			     struct conn *conn) {
	if (!cl->pair_info_current)
		return queue_work_exclusive(cl, sub_work, NULL);
	else
		return channel_sub(cl);
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
	cb->user_chan_subbed = false;
	cb->sub_acked = false;
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
		return channel_sub(cl);

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
		      int status, char *json, int num_toks, jsmntok_t *toks) {
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
	struct coinbase_auth auth;
	union {
		void *private;
		int64_t id;
	};
};

static int private_add_headers(struct exchg_client *cl, struct conn *conn) {
	if (add_user_agent(cl, conn))
		return 1;

	struct http_data *data = conn_private(conn);
	if (conn_add_header(conn, (unsigned char *)"CB-ACCESS-KEY:",
			    cl->apikey_public, cl->apikey_public_len))
		return 1;
	if (conn_add_header(conn, (unsigned char *)"CB-ACCESS-SIGN:",
			    (unsigned char *)data->auth.hmac, data->auth.hmac_len))
		return 1;
	if (conn_add_header(conn, (unsigned char *)"CB-ACCESS-PASSPHRASE:",
			    (unsigned char *)cl->password, cl->password_len))
		return 1;
	if (conn_add_header(conn, (unsigned char *)"CB-ACCESS-TIMESTAMP:",
			    (unsigned char *)data->auth.timestamp, data->auth.timestamp_len))
		return 1;
	if (conn_http_body_len(conn) > 0) {
		if (conn_add_header(conn, (unsigned char *)"Content-Type:",
				    (unsigned char *)"application/json", strlen("application/json")))
			return 1;
		char l[16];
		int len = sprintf(l, "%zu", conn_http_body_len(conn));
		if (conn_add_header(conn, (unsigned char *)"Content-Length:",
				    (unsigned char *)l, len))
			return 1;
	}
	return 0;
}

static int balances_recv(struct exchg_client *cl, struct conn *conn,
			 int status, char *json, int num_toks, jsmntok_t *toks) {
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
	exchg_on_balances(cl, balances, h->private);
	return 0;

bad:
	exchg_log("Received bad data from %s%s %s:\n",
		  conn_host(conn), conn_path(conn), problem);
	json_fprintln(stderr, json, bad_tok);
	return -1;
}

static struct exchg_http_ops get_balances_ops = {
	.recv = balances_recv,
	.add_headers = private_add_headers,
	.conn_data_size = sizeof(struct http_data),
};

static int coinbase_conn_auth(struct coinbase_auth *auth, HMAC_CTX *hmac_ctx, struct conn *http) {
	return coinbase_auth(auth, hmac_ctx, conn_path(http), conn_method(http),
			     conn_http_body(http), conn_http_body_len(http));

}

static int coinbase_get_balances(struct exchg_client *cl, void *req_private) {
	struct conn *conn = exchg_http_get("api.pro.coinbase.com", "/accounts", &get_balances_ops, cl);
	if (!conn)
		return -1;
	struct http_data *data = conn_private(conn);
	data->private = req_private;
	if (coinbase_conn_auth(&data->auth, cl->hmac_ctx, conn)) {
		conn_close(conn);
		return -1;
	}
	return 0;
}

static int orders_recv(struct exchg_client *cl, struct conn *conn,
		       int status, char *json, int num_toks, jsmntok_t *toks) {
	struct http_data *data = conn_private(conn);
	struct order_info *info = exchg_order_lookup(cl, data->id);

	// We received a "done" message on the websocket and freed it already
	if (!info)
		return 0;

	if (toks[0].type != JSMN_OBJECT) {
		exchg_log("Received non-object data from %s%s:\n",
			  conn_host(conn), conn_path(conn));
		json_fprintln(stderr, json, &toks[0]);
		return -1;
	}

	int key_idx = 1;
	for (int i = 0; i < toks[0].size; i++) {
		jsmntok_t *key = &toks[key_idx];
		jsmntok_t *value = key + 1;

		// We just get all updates on the websocket for now. usually those come
		// faster, anyway. Is is possible to get an error message here after
		// having gotten a normal \"received\" message on the websocket?
		// Would guess no but if so, then we need to remove the order from
		// the hash table in struct coinbase_client
		if (json_streq(json, key, "message")) {
			info->info.status = EXCHG_ORDER_ERROR;
			json_strncpy(info->info.err, json, value, EXCHG_ORDER_ERR_SIZE);
			exchg_order_update(cl, info);
			return 0;
		} else {
			key_idx = json_skip(num_toks, toks, key_idx + 1);
		}
	}
	if (info->info.status == EXCHG_ORDER_SUBMITTED)
		info->info.status = EXCHG_ORDER_PENDING;
	exchg_order_update(cl, info);
	return 0;
}

static struct exchg_http_ops place_order_ops = {
	.recv = orders_recv,
	.add_headers = private_add_headers,
	.conn_data_size = sizeof(struct http_data),
};

// 0x5cac7e817653c -> 00000000-0000-0000-0005-cac7e817653c
// Coinbase wants a UUID but we don't need a real one. We just want
// a value unique to this process and any of its restarts in the past or future.
// dst must be >= 37 bytes long
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

static int place_order(struct exchg_client *cl, struct conn *http,
		       struct order_info *oi, bool update_on_err) {
	struct coinbase_client *cb = cl->priv;
	struct http_data *data = conn_private(http);
	struct exchg_order_info *info = &oi->info;
	struct exchg_pair_info *pinfo = &cl->pair_info[info->order.pair];
	struct coinbase_pair_info *cb_info = &cb->pair_info[info->order.pair];
	char price[30], size[30];
	char oid[37];

	if (!pinfo->available) {
		exchg_log("Can't submit order in %s on Coinbase. Pair not "
			  "available on the exchange.\n",
			  exchg_pair_to_str(info->order.pair));
		if (update_on_err) {
			snprintf(info->err, EXCHG_ORDER_ERR_SIZE,
				 "%s not available on Coinbase",
				 exchg_pair_to_str(info->order.pair));
			info->status = EXCHG_ORDER_ERROR;
			exchg_order_update(cl, oi);
		}
		return -1;
	}

	write_oid(oid, info->id);
	decimal_to_str(price, &info->order.price);
	decimal_to_str(size, &info->order.size);
	if (conn_http_body_sprintf(http, "{ \"client_oid\": \"%s\", "
				   "\"product_id\": \"%s\", "
				   "\"type\": \"limit\", \"side\": \"%s\", "
				   "\"price\": \"%s\", \"size\": \"%s\", "
				   "\"time_in_force\": \"%s\"}",
				   oid, cb_info->id,
				   info->order.side == EXCHG_SIDE_BUY ? "buy" : "sell",
				   price, size,
				   info->opts.immediate_or_cancel ? "IOC" : "GTC") < 0) {
		if (update_on_err) {
			snprintf(info->err, EXCHG_ORDER_ERR_SIZE, "Out-Of-Memory");
			info->status = EXCHG_ORDER_ERROR;
			exchg_order_update(cl, oi);
		}
		return -1;
	}
	data->id = info->id;
	int ret = coinbase_conn_auth(&data->auth, cl->hmac_ctx, http);
	if (!ret) {
		info->status = EXCHG_ORDER_SUBMITTED;
	} else if (ret && update_on_err) {
		snprintf(info->err, EXCHG_ORDER_ERR_SIZE, "error computing request HMAC");
		info->status = EXCHG_ORDER_ERROR;
		exchg_order_update(cl, oi);
	}
	return ret;
}

static bool place_order_work(struct exchg_client *cl, void *p) {
	struct order_info *info = p;

	if (!cl->pair_info_current)
		return false;

	struct conn *http = exchg_http_post("api.pro.coinbase.com", "/orders",
					    &place_order_ops, cl);
	if (!http) {
		info->info.status = EXCHG_ORDER_ERROR;
		strncpy(info->info.err, "HTTP POST failed", EXCHG_ORDER_ERR_SIZE);
		exchg_order_update(cl, info);
		return true;
	}
	if (place_order(cl, http, info, true))
		conn_close(http);
	return true;
}

static int64_t coinbase_place_order(struct exchg_client *cl, struct exchg_order *order,
				    struct exchg_place_order_opts *opts, void *private) {
	struct order_info *info;

	if (likely(cl->pair_info_current)) {
		struct conn *http = exchg_http_post("api.pro.coinbase.com", "/orders",
						    &place_order_ops, cl);
		if (!http)
			return -1;
		info = exchg_new_order(cl, order, opts, private, 0);
		if (!info) {
			conn_close(http);
			return -1;
		}
		if (place_order(cl, http, info, false)) {
			order_info_free(cl, info);
			conn_close(http);
			return -1;
		}
		// TODO: if not already connected, we might miss updates, so
		// we should actively fetch updates in that case.
		cl->priv_ws_connect(cl);
	} else {
		if (cl->priv_ws_connect(cl))
			return -1;

		info = exchg_new_order(cl, order, opts, private, 0);
		if (!info)
			return -1;
		if (queue_work(cl, place_order_work, info)) {
			order_info_free(cl, info);
			return -1;
		}
	}
	return info->info.id;
}

static int cancel_order_recv(struct exchg_client *cl, struct conn *conn,
			     int status, char *json, int num_toks, jsmntok_t *toks) {
	if (num_toks > 1) {
		// TODO: retry if we sent the cancel very soon after sending the
		// order and the requests might have raced
		struct http_data *data = conn_private(conn);
		struct order_info *oi = exchg_order_lookup(cl, data->id);

		if (oi) {
			oi->info.cancelation_failed = true;
			exchg_order_update(cl, oi);
		}
		exchg_log("Cancelation of order %"PRId64" failed:\n", data->id);
		json_fprintln(stderr, json, &toks[0]);
	}
	return 0;
}

static struct exchg_http_ops cancel_order_ops = {
	.recv = cancel_order_recv,
	.add_headers = private_add_headers,
	.conn_data_size = sizeof(struct http_data),
};

static int coinbase_cancel_order(struct exchg_client *cl, struct order_info *info) {
	struct coinbase_client *cb = cl->priv;
	if (unlikely(info->info.status == EXCHG_ORDER_UNSUBMITTED)) {
		remove_work(cl, place_order_work, info);
		info->info.status = EXCHG_ORDER_CANCELED;
		exchg_order_update(cl, info);
		return 0;
	}

	char path[strlen("/orders/client:") + 36 + strlen("?product_id=") + 10];
	sprintf(path, "/orders/client:");
	write_oid(&path[strlen("/orders/client:")], info->info.id);
	// note that since the order status is not UNSUBMITTED, cl->pair_info_current
	// is true and cb->pair_info[pair].id is valid
	sprintf(&path[strlen("/orders/client:")+36],
		"?product_id=%s", cb->pair_info[info->info.order.pair].id);

	struct conn *http = exchg_http_delete("api.pro.coinbase.com", path,
					      &cancel_order_ops, cl);
	if (!http)
		return -1;
	struct http_data *data = conn_private(http);
	if (coinbase_conn_auth(&data->auth, cl->hmac_ctx, http)) {
		conn_close(http);
		return -1;
	}
	data->id = info->info.id;
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

static int coinbase_priv_ws_connect(struct exchg_client *cl) {
	struct coinbase_client *cb = cl->priv;

	if (exchg_get_pair_info(cl))
		return -1;

	cb->watching_user_chan = true;
	if (!cb->ws) {
		cb->ws = exchg_websocket_connect(cl, "ws-feed.pro.coinbase.com", "/",
						 &ws_ops);
		if (!cb->ws)
			return -1;
		return 0;
	} else {
		return channel_sub(cl);
	}
}

static bool coinbase_priv_ws_online(struct exchg_client *cl) {
	struct coinbase_client *cb = cl->priv;
	return cb->watching_user_chan && cb->sub_acked;
}

static void coinbase_destroy(struct exchg_client *cl) {
	struct coinbase_client *cb = cl->priv;

	for (enum exchg_pair p = 0; p < EXCHG_NUM_PAIRS; p++)
		free(cb->pair_info[p].id);
	g_hash_table_unref(cb->orders);
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
	cb->orders = g_hash_table_new_full(g_str_hash, g_str_equal, free, NULL);

	ret->name = "Coinbase";
	ret->priv = cb;
	ret->l2_subscribe = coinbase_l2_subscribe;
	ret->get_pair_info = coinbase_get_pair_info;
	ret->get_balances = coinbase_get_balances;
	ret->place_order = coinbase_place_order;
	ret->cancel_order = coinbase_cancel_order;
	ret->priv_ws_connect = coinbase_priv_ws_connect;
	ret->priv_ws_online = coinbase_priv_ws_online;
	ret->new_keypair = coinbase_new_keypair;
	ret->destroy = coinbase_destroy;
	return ret;
}
