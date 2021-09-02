// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#include <glib.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <stdio.h>

#include "exchg/decimal.h"
#include "auth.h"
#include "compiler.h"
#include "client.h"
#include "json-helpers.h"
#include "kraken.h"
#include "time-helpers.h"

struct kraken_client {
	struct kraken_pair_info {
		bool subbed;
		bool watching_l2;
		int channel_id;
		char *wsname;
	} pair_info[EXCHG_NUM_PAIRS];
	int next_order_id;
	SHA256_CTX sha_ctx;
	GHashTable *channel_mapping;
	struct conn *conn;
	bool openorders_recvd;
	struct conn *private_ws;
	bool getting_token;
	char *ws_token;
};

static int kraken_subscribe(struct kraken_client *kkn, enum exchg_pair pair) {
	struct kraken_pair_info *pi = &kkn->pair_info[pair];

	pi->subbed = true;
	if (conn_printf(kkn->conn, "{ \"event\": \"subscribe\", "
			"\"pair\": [\"%s\"], "
			"\"subscription\": {\"name\": \"book\", "
			"\"depth\": 1000}}",
			pi->wsname) < 0)
		return -1;
	return 0;
}

static bool wsname_match(const char *json, jsmntok_t *tok, const char *str) {
	size_t len = tok->end - tok->start;
	int jpos = tok->start;
	int spos = 0;

	for (int i = 0; i < len && str[spos]; i++) {
		char jc = json[jpos++];
		char sc = str[spos++];

		if (jc == '\\') {
			jc = json[jpos++];
			if (jc != '/')
				return false;
		}
		if (sc == '\\') {
			sc = str[spos++];
			if (sc != '/')
				return false;
		}
		if (jc != sc)
			return false;
	}
	return !str[spos] && jpos == tok->end;
}

enum event_type {
	EVENT_SUB_STATUS,
	EVENT_ADD_EXCHG_ORDER,
	EVENT_UNKNOWN,
};

enum channel_name {
	CHAN_UNSET,
	CHAN_UNKNOWN,
	CHAN_OPENORDERS,
	CHAN_BOOK,
};

struct event_msg {
	int channel_id;
	bool got_status;
	bool status_ok;
	jsmntok_t *error_msg;
	enum event_type type;
	enum channel_name name;
	enum exchg_pair pair;
	int64_t reqid;
};

static int parse_event(struct exchg_client *cl, struct conn *conn,
		       const char *json, int num_toks, jsmntok_t *toks) {
	struct kraken_client *kkn = cl->priv;
	const char *problem;
	struct event_msg status = {
		.channel_id = -1,
		.got_status = false,
		.status_ok = false,
		.error_msg = NULL,
		.type = EVENT_UNKNOWN,
		.name = CHAN_UNSET,
		.pair = INVALID_PAIR,
		.reqid = -1,
	};

	int key_idx = 1;
	for (int i = 0; i < toks[0].size; i++) {
		jsmntok_t *key = &toks[key_idx];
		jsmntok_t *value = key + 1;

		if (json_streq(json, key, "event")) {
			if (json_streq(json, value, "subscriptionStatus")) {
				status.type = EVENT_SUB_STATUS;
			} else if (json_streq(json, value,
					      "addOrderStatus")) {
				status.type = EVENT_ADD_EXCHG_ORDER;
			} else
				return 0;
			key_idx += 2;
		} else if (json_streq(json, key, "subscription")) {
			if (value->type != JSMN_OBJECT) {
				problem = "bad \"subscription\"";
				goto bad;
			}
			int n = value->size;
			key_idx += 2;
			for (int j = 0; j < n; j++) {
				key = &toks[key_idx];
				value = key + 1;

				if (json_streq(json, key, "name")) {
					if (json_streq(json, value, "book")) {
						status.name = CHAN_BOOK;
					} else if (json_streq(json, value, "openOrders")) {
						status.name = CHAN_OPENORDERS;
					} else
						status.name = CHAN_UNKNOWN;
				}
				key_idx = json_skip(num_toks,
						    toks, key_idx+1);
			}
		} else if (json_streq(json, key, "channelID")) {
			if (json_get_int(&status.channel_id, json, value)) {
				problem = "bad \"channelID\"";
				goto bad;
			}
			key_idx += 2;
		} else if (json_streq(json, key, "status")) {
			status.got_status = true;
			if (json_streq(json, value, "subscribed") ||
			    json_streq(json, value, "ok")) {
				status.status_ok = true;
			}
			key_idx += 2;
		} else if (json_streq(json, key, "errorMessage")) {
			status.error_msg = value;
			key_idx = json_skip(num_toks, toks, key_idx+1);
		} else if (json_streq(json, key, "pair")) {
			for (enum exchg_pair pair = 0;
			     pair < EXCHG_NUM_PAIRS; pair++) {
				struct kraken_pair_info *p = &kkn->pair_info[pair];
				if (!p->wsname)
					continue;
				if (wsname_match(json, value, p->wsname)) {
					status.pair = pair;
					break;
				}
			}
			if (status.pair == INVALID_PAIR) {
				problem = "bad \"pair\"";
				goto bad;
			}
			key_idx += 2;
		} else if (json_streq(json, key, "reqid")) {
			if (json_get_int64(&status.reqid, json, value)) {
				problem = "bad \"reqid\"";
				goto bad;
			}
			key_idx += 2;
		} else {
			key_idx = json_skip(num_toks, toks, key_idx+1);
		}
	}
	if (status.type == EVENT_UNKNOWN) {
		problem = "missing \"event\"";
		goto bad;
	}
	if (!status.got_status) {
		problem = "missing \"status\"";
		goto bad;
	}

	if (status.type == EVENT_SUB_STATUS) {
		if (!status.status_ok) {
			problem = "bad \"status\"";
			goto bad;
		}
		if (status.name == CHAN_UNSET) {
			problem = "missing \"subscription\":\"name\"";
			goto bad;
		} else if (status.name != CHAN_BOOK) {
			return 0;
		}
		if (status.channel_id == -1) {
			problem = "missing \"channelID\"";
			goto bad;
		}
		if (status.pair == INVALID_PAIR) {
			problem = "missing \"pair\"";
			goto bad;
		}
		g_hash_table_insert(kkn->channel_mapping,
				    GINT_TO_POINTER(status.channel_id),
				    GINT_TO_POINTER(status.pair));
	} else if (status.type == EVENT_ADD_EXCHG_ORDER) {
		if (status.reqid == -1) {
			problem = "no \"reqid\" field";
			goto bad;
		}
		struct order_info *oi = exchg_order_lookup(cl, status.reqid);
		if (!oi) {
			exchg_log("Kraken: unrecognized \"reqid\":\n");
			json_fprintln(stderr, json, &toks[0]);
			return 0;
		}
		if (status.status_ok) {
			oi->info.status = EXCHG_ORDER_PENDING;
			exchg_order_update(cl, oi);
		} else {
			oi->info.status = EXCHG_ORDER_ERROR;
			if (status.error_msg)
				json_strncpy(oi->info.err, json,
					     status.error_msg, EXCHG_ORDER_ERR_SIZE);
			else
				strncpy(oi->info.err, "<unknown>", EXCHG_ORDER_ERR_SIZE);
			exchg_order_update(cl, oi);
		}
	}
	return 0;

bad:
	exchg_log("Kraken sent bad event update: %s:\n", problem);
	json_fprintln(stderr, json, &toks[0]);
	return -1;
}

static int insert_orders_side(struct exchg_client *cl, const char *json,
			      int num_toks, jsmntok_t *toks, int idx,
			      enum exchg_pair pair, bool bids, bool is_initial) {
	const char *problem;

	if (toks[idx].type != JSMN_ARRAY) {
		problem = "non-array update";
		goto bad;
	}

	int n = toks[idx].size;
	struct exchg_l2_update *upd = &cl->update;
	struct exchg_pair_info *pi = &cl->pair_info[pair];
	int *num = bids ? &upd->num_bids : &upd->num_asks;

	// TODO: do something better on error throughout.
	// Do we really wanna close the connection when a bad thing happens?
	if (n + *num > cl->l2_update_size &&
	    exchg_realloc_order_bufs(cl, 2 * (n + *num)))
		return -1;

	struct exchg_limit_order *order = bids ? &upd->bids[upd->num_bids] :
		&upd->asks[upd->num_asks];

	(*num) += n;
	idx++;
	for (int i = 0; i < n; i++, order++) {
		jsmntok_t *tok = &toks[idx];
		jsmntok_t *price = tok + 1;
		jsmntok_t *size = tok + 2;
		jsmntok_t *time = tok + 3;
		decimal_t ts;

		if (tok->type != JSMN_ARRAY) {
			problem = "non-array update";
			goto bad;
		}
		if (tok->size < 3) {
			problem = "update datapoint with num elements < 3";
			goto bad;
		}
		if (json_get_decimal(&order->price, json, price)) {
			problem = "bad price";
			goto bad;
		}
		if (json_get_decimal(&order->size, json, size)) {
			problem = "bad size";
			goto bad;
		}
		if (json_get_decimal(&ts, json, time)) {
			problem = "bad timestamp";
			goto bad;
		}

		// TODO: do this in realloc_order_bufs() and on first alloc()
		order->exchange_id = EXCHG_KRAKEN;
		if (is_initial)
			order->update_micros = 0;
		else
			order->update_micros = decimal_to_fractional(&ts, 6);
		if (bids)
			decimal_dec_bps(&order->net_price, &order->price,
					pi->fee_bps, pi->price_decimals);
		else
			decimal_inc_bps(&order->net_price, &order->price,
					pi->fee_bps, pi->price_decimals);
		if (likely(tok->size == 3))
			idx += 4;
		else
			idx = json_skip(num_toks, toks, idx);
	}
	return idx;
bad:
	exchg_log("Kraken sent bad order book update: %s:\n", problem);
	json_fprintln(stderr, json, &toks[0]);
	return -1;
}

static int insert_orders(struct exchg_client *cl, const char *json,
			 int num_toks, jsmntok_t *toks, int idx, enum exchg_pair pair) {
	if (toks[idx].type != JSMN_OBJECT) {
		exchg_log("Kraken sent non-object update data:\n");
		json_fprintln(stderr, json, &toks[0]);
		return -1;
	}

	int n = toks[idx].size;
	idx++;
	for (int i = 0; i < n; i++) {
		jsmntok_t *key = &toks[idx];

		if (json_streq(json, key, "a")) {
			idx = insert_orders_side(cl, json, num_toks,
						 toks, idx+1, pair, false, false);
		} else if (json_streq(json, key, "as")) {
			idx = insert_orders_side(cl, json, num_toks,
						 toks, idx+1, pair, false, true);
		} else if (json_streq(json, key, "b")) {
			idx = insert_orders_side(cl, json, num_toks, toks,
						 idx+1, pair, true, false);
		} else if (json_streq(json, key, "bs")) {
			idx = insert_orders_side(cl, json, num_toks, toks,
						 idx+1, pair, true, true);
		} else {
			idx = json_skip(num_toks, toks, idx+1);
		}
		if (idx < 0)
			return idx;
	}
	return idx;
}

static int kraken_recv(struct exchg_client *cl, struct conn *conn,
		       char *json, int num_toks, jsmntok_t *toks) {
	struct kraken_client *kkn = cl->priv;

	if (num_toks < 3)
		return 0;

	if (toks[0].type == JSMN_OBJECT)
		return parse_event(cl, conn, json, num_toks, toks);

	if (toks[0].type != JSMN_ARRAY) {
		exchg_log("Kraken sent non-object, non-array data\n");
		json_fprintln(stderr, json, &toks[0]);
		return -1;
	}

	if (toks[0].size < 4)
		return 0;

	if (toks[0].size > 5) {
		exchg_log("Kraken sent array data with unexpected"
			  " number of elements: %d:\n", toks[0].size);
		json_fprintln(stderr, json, &toks[0]);
		return -1;
	}

	int channel_id;
	if (json_get_int(&channel_id, json, &toks[1])) {
		exchg_log("Kraken sent update with bad first-element channel id:\n");
		json_fprintln(stderr, json, &toks[0]);
		return -1;
	}

	void *val;
	if (!g_hash_table_lookup_extended(kkn->channel_mapping,
					  GINT_TO_POINTER(channel_id),
					  NULL, &val)) {
		exchg_log("Kraken sent update with unrecognized"
			  " channel id: %d:\n",
			  channel_id);
		json_fprintln(stderr, json, &toks[0]);
		return -1;
	}

	enum exchg_pair pair = GPOINTER_TO_INT(val);
	exchg_update_init(cl);

	int idx = insert_orders(cl, json, num_toks, toks, 2, pair);
	if (idx < 0)
		return idx;
	if (toks[0].size == 5) {
		idx = insert_orders(cl, json, num_toks, toks, idx, pair);
		if (idx < 0)
			return idx;
	}
	exchg_l2_update(cl, pair);
	return 0;
}

static int book_sub(struct exchg_client *cl) {
	struct kraken_client *kkn = cl->priv;

	for (enum exchg_pair pair = 0; pair < EXCHG_NUM_PAIRS; pair++) {
		struct kraken_pair_info *kpi = &kkn->pair_info[pair];
		struct exchg_pair_info *pi = &cl->pair_info[pair];
		if (kpi->watching_l2 && !pi->available) {
			exchg_log("pair %s not available on kraken\n",
				  exchg_pair_to_str(pair));
			kpi->watching_l2 = false;
		} else if (kpi->watching_l2 && !kpi->subbed) {
			if (kraken_subscribe(kkn, pair))
				return -1;
		}
	}
	return 0;
}

static bool book_sub_work(struct exchg_client *cl, void *p) {
	struct kraken_client *kkn = cl->priv;

	if (!cl->pair_info_current || !conn_established(kkn->conn))
		return false;

	book_sub(cl);
	return true;
}

static int kraken_conn_established(struct exchg_client *cl,
				   struct conn *conn) {
	if (!cl->pair_info_current)
		return queue_work_exclusive(cl, book_sub_work, NULL);
	else
		return book_sub(cl);
}

static void kraken_on_disconnect(struct exchg_client *cl, struct conn *conn,
				 int reconnect_seconds) {
	struct kraken_client *kkn = cl->priv;
	int num_pairs_gone = 0;
	enum exchg_pair pairs_gone[EXCHG_NUM_PAIRS];
	if (reconnect_seconds < 0)
		kkn->conn = NULL;
	for (enum exchg_pair pair = 0; pair < EXCHG_NUM_PAIRS; pair++) {
		struct exchg_pair_info *pi = &cl->pair_info[pair];
		struct kraken_pair_info *kpi = &kkn->pair_info[pair];
		if (kpi->watching_l2 && pi->available) {
			pairs_gone[num_pairs_gone++] = pair;
			exchg_book_clear(cl, pair);
		}
		kpi->subbed = false;
	}
	exchg_data_disconnect(cl, conn, num_pairs_gone, pairs_gone);
}

static const struct exchg_websocket_ops websocket_ops = {
	.on_conn_established = kraken_conn_established,
	.on_disconnect = kraken_on_disconnect,
	.recv = kraken_recv,
};

static int kraken_connect(struct exchg_client *cl) {
	struct kraken_client *kkn = cl->priv;
	kkn->conn = exchg_websocket_connect(cl, "ws.kraken.com", "/",
					    &websocket_ops);
	if (kkn->conn)
		return 0;
	return -1;
}

static int kraken_str_to_pair(enum exchg_pair *pair, const char *json,
			      jsmntok_t *tok) {
	if (json_streq(json, tok, "XXBTZUSD"))
		*pair = EXCHG_PAIR_BTCUSD;
	else if (json_streq(json, tok, "XETHZUSD"))
		*pair = EXCHG_PAIR_ETHUSD;
	else if (json_streq(json, tok, "XETHXXBT"))
		*pair = EXCHG_PAIR_ETHBTC;
	else if (json_streq(json, tok, "XZECZUSD"))
		*pair = EXCHG_PAIR_ZECUSD;
	else if (json_streq(json, tok, "XZECXXBT"))
		*pair = EXCHG_PAIR_ZECBTC;
	else if (json_streq(json, tok, "XZECXETH"))
		*pair = EXCHG_PAIR_ZECETH;
	else if (json_streq(json, tok, "ZECBCH"))
		*pair = EXCHG_PAIR_ZECBCH;
	else if (json_streq(json, tok, "XZECXLTC"))
		*pair = EXCHG_PAIR_ZECLTC;
	else if (json_streq(json, tok, "BCHUSD"))
		*pair = EXCHG_PAIR_BCHUSD;
	else if (json_streq(json, tok, "BCHXBT"))
		*pair = EXCHG_PAIR_BCHBTC;
	else if (json_streq(json, tok, "BCHETH"))
		*pair = EXCHG_PAIR_BCHETH;
	else if (json_streq(json, tok, "XLTCZUSD"))
		*pair = EXCHG_PAIR_LTCUSD;
	else if (json_streq(json, tok, "XLTCXXBT"))
		*pair = EXCHG_PAIR_LTCBTC;
	else if (json_streq(json, tok, "LTCETH"))
		*pair = EXCHG_PAIR_LTCETH;
	else if (json_streq(json, tok, "LTCBCH"))
		*pair = EXCHG_PAIR_LTCBCH;
	else if (json_streq(json, tok, "DAIUSD"))
		*pair = EXCHG_PAIR_DAIUSD;
	else
		return EINVAL;
	return 0;
}

static int kraken_str_to_ccy(enum exchg_currency *ccy, const char *json,
			     jsmntok_t *tok) {
	if (json_streq(json, tok, "ZUSD"))
		*ccy = EXCHG_CCY_USD;
	else if (json_streq(json, tok, "XXBT"))
		*ccy = EXCHG_CCY_BTC;
	else if (json_streq(json, tok, "XETH"))
		*ccy = EXCHG_CCY_ETH;
	else if (json_streq(json, tok, "XZEC"))
		*ccy = EXCHG_CCY_ZEC;
	else if (json_streq(json, tok, "XXRP"))
		*ccy = EXCHG_CCY_XRP;
	else if (json_streq(json, tok, "XLTC"))
		*ccy = EXCHG_CCY_LTC;
	else if (json_streq(json, tok, "BCH"))
		*ccy = EXCHG_CCY_BCH;
	else if (json_streq(json, tok, "DAI"))
		*ccy = EXCHG_CCY_DAI;
	else
		return EINVAL;
	return 0;
}

static int parse_info_result(struct exchg_client *cl, const char *json,
			     int num_toks, jsmntok_t *toks,
			     int idx, char *problem) {
	struct kraken_client *kkn = cl->priv;

	if (toks[idx].type != JSMN_OBJECT) {
		sprintf(problem, "non-object result");
		return -1;
	}

	int n = toks[idx].size;
	idx++;
	for (int i = 0; i < n; i++) {
		jsmntok_t *key = &toks[idx];
		jsmntok_t *value = &toks[idx+1];
		enum exchg_pair pair;

		if (kraken_str_to_pair(&pair, json, key)) {
			idx = json_skip(num_toks, toks, idx+1);
			continue;
		}

		if (value->type != JSMN_OBJECT) {
			sprintf(problem, "non-object info for pair %s", exchg_pair_to_str(pair));
			return -1;
		}

		bool got_wsname = false;
		bool got_lot_decimals = false;
		bool got_pair_decimals = false;
		bool got_ordermin = false;
		bool got_fees = false;
		struct kraken_pair_info *kpi = &kkn->pair_info[pair];
		struct exchg_pair_info *pi = &cl->pair_info[pair];
		int m = value->size;
		idx += 2;
		for (int j = 0; j < m; j++) {
			key = &toks[idx];
			value = &toks[idx+1];

			if (json_streq(json, key, "wsname")) {
				free(kpi->wsname);
				int err = json_strdup(&kpi->wsname, json, value);
				if (err == ENOMEM) {
					sprintf(problem, "%s: OOM", __func__);
					return -1;
				} else if (err) {
					sprintf(problem, "bad wsname for pair %s", exchg_pair_to_str(pair));
					return -1;
				}
				got_wsname = true;
				idx += 2;
			} else if (json_streq(json, key, "lot_decimals")) {
				if (json_get_int(&pi->base_decimals, json, value)) {
					sprintf(problem, "bad \"lot_decimals\""
						" for pair %s", exchg_pair_to_str(pair));
					return -1;
				}
				got_lot_decimals = true;
				idx += 2;
			} else if (json_streq(json, key, "pair_decimals")) {
				if (json_get_int(&pi->price_decimals, json, value)) {
					sprintf(problem, "bad \"lot_decimals\""
						" for pair %s", exchg_pair_to_str(pair));
					return -1;
				}
				got_pair_decimals = true;
				idx += 2;
			} else if (json_streq(json, key, "ordermin")) {
				if (json_get_decimal(&pi->min_size, json, value)) {
					sprintf(problem, "bad \"ordermin\""
						" for pair %s", exchg_pair_to_str(pair));
					return -1;
				}
				pi->min_size_is_base = true;
				got_ordermin = true;
				idx += 2;
			} else if (json_streq(json, key, "fees")) {
				jsmntok_t *fees = value+1;
				jsmntok_t *first_fee = fees+2;
				decimal_t fee;

				// TODO: save whole fee schedule
				if (value->type != JSMN_ARRAY ||
				    value->size < 1 || fees->type != JSMN_ARRAY ||
				    fees->size != 2 ||
				    json_get_decimal(&fee, json, first_fee)) {
					sprintf(problem, "bad \"fees\""
						" for pair %s", exchg_pair_to_str(pair));
					return -1;
				}
				pi->fee_bps = decimal_to_fractional(&fee, 2);
				got_fees = true;
				idx = json_skip(num_toks, toks, idx+1);
			} else {
				idx = json_skip(num_toks, toks, idx+1);
			}
		}

		if (!got_wsname) {
			sprintf(problem, "missing \"wsname\" for pair %s",
				exchg_pair_to_str(pair));
			return -1;
		}
		if (!got_lot_decimals) {
			sprintf(problem, "missing \"lot_decimals\" for pair %s",
				exchg_pair_to_str(pair));
			return -1;
		}
		if (!got_pair_decimals) {
			sprintf(problem, "missing \"pair_decimals\" for pair %s",
				exchg_pair_to_str(pair));
			return -1;
		}
		if (!got_ordermin) {
			sprintf(problem, "missing \"ordermin\" for pair %s",
				exchg_pair_to_str(pair));
			return -1;
		}
		if (!got_fees) {
			sprintf(problem, "missing \"fees\" for pair %s",
				exchg_pair_to_str(pair));
			return -1;
		}
		pi->available = true;
	}
	return idx;
}

static int kraken_parse_info(struct exchg_client *cl, struct conn *conn,
			     int status, char *json, int num_toks, jsmntok_t *toks) {
	const char *url = "https://api.kraken.com/0/public/AssetPairs";
	char problem[100];

	if (status != 200) {
		cl->get_info_error = 1;
		exchg_log("status %d from %s:\n", status, url);
		if (num_toks > 0)
			json_fprintln(stderr, json, &toks[0]);
		return -1;
	}

	if (num_toks < 2) {
		sprintf(problem, "no data received");
		goto bad;
	}
	if (toks[0].type != JSMN_OBJECT) {
		sprintf(problem, "didn't receive a JSON object\n");
		goto bad;
	}

	int key_idx = 1;
	for (int i = 0; i < toks[0].size; i++) {
		jsmntok_t *key = &toks[key_idx];
		jsmntok_t *value = &toks[key_idx+1];

		if (json_streq(json, key, "result")) {
			key_idx = parse_info_result(cl, json, num_toks,
						    toks, key_idx+1, problem);
			if (key_idx < 0)
				goto bad;
		} else if (json_streq(json, key, "error")) {
			if (value->type != JSMN_ARRAY || value->size > 0) {
				cl->get_info_error = 1;
				exchg_log("Error indicated at %s:\n", url);
				json_fprintln(stderr, json, value);
				return -1;
			}
			key_idx = json_skip(num_toks, toks, key_idx+1);
		} else {
			key_idx = json_skip(num_toks, toks, key_idx+1);
		}
	}

	exchg_on_pair_info(cl);
	exchg_do_work(cl);

	return 0;

bad:
	cl->get_info_error = 1;
	exchg_log("Received bad data from "
		  "https://api.kraken.com/0/public/AssetPairs: %s:\n", problem);
	if (num_toks > 0)
		json_fprintln(stderr, json, &toks[0]);
	return -1;
}

static struct exchg_http_ops get_info_ops = {
	.recv = kraken_parse_info,
	.on_error = exchg_parse_info_on_error,
	.on_closed = exchg_parse_info_on_closed,
};

static int kraken_l2_subscribe(struct exchg_client *cl,
			       enum exchg_pair pair) {
	struct kraken_client *kkn = cl->priv;
	struct kraken_pair_info *kpi = &kkn->pair_info[pair];

	if (kpi->subbed)
		return 0;

	kpi->watching_l2 = true;

	if (cl->pair_info_current && conn_established(kkn->conn))
		return kraken_subscribe(kkn, pair);

	if (!kkn->conn && kraken_connect(cl))
		return -1;
	return 0;
}

static int kraken_get_pair_info(struct exchg_client *cl) {
	if (!exchg_http_get("api.kraken.com", "/0/public/AssetPairs",
			    &get_info_ops, cl))
		return -1;
	return 0;
}

struct http_data {
	size_t to_hash_len;
	size_t body_len;
	char *body;
	char to_hash[256];
	size_t hmac_len;
	char hmac[HMAC_SHA512_B64_LEN];
	void *request_private;
};

static int private_http_add_headers(struct exchg_client *cl, struct conn *conn) {
	struct http_data *h = conn_private(conn);

	if (conn_add_header(conn, (unsigned char *)"API-Key:",
			    (unsigned char *)cl->apikey_public,
			    cl->apikey_public_len))
		return 1;
	if (conn_add_header(conn, (unsigned char *)"API-Sign:",
			    (unsigned char*)h->hmac, h->hmac_len))
		return 1;
	if (conn_add_header(conn, (unsigned char *)"Content-Type:",
			    (unsigned char *)
			    "application/x-www-form-urlencoded",
			    strlen("application/x-www-form-urlencoded")))
		return 1;
	char l[16];
	size_t len = sprintf(l, "%zu", h->body_len);
	if (conn_add_header(conn, (unsigned char *)"Content-Length:",
			    (unsigned char *)l, len))
		return 1;
	return 0;
}

static int balances_recv(struct exchg_client *cl, struct conn *conn,
			 int status, char *json, int num_toks, jsmntok_t *toks) {
	const char *problem;

	if (num_toks < 1) {
		exchg_log("Kraken sent balance info with no data\n");
		return -1;
	}

	if (toks[0].type != JSMN_OBJECT) {
		problem = "non-object info";
		goto bad;
	}

	decimal_t balances[EXCHG_NUM_CCYS];
	memset(balances, 0, sizeof(balances));

	bool warn = false;
	int key_idx = 1;
	for (int i = 0; i < toks[0].size; i++) {
		jsmntok_t *key = &toks[key_idx];
		jsmntok_t *value = key + 1;

		if (json_streq(json, key, "error")) {
			if (value->size > 0) {
				exchg_log("Kraken balances error:\n");
				json_fprintln(stderr, json, value);
				return -1;
			}
			key_idx = json_skip(num_toks, toks, key_idx+1);
		} else if (json_streq(json, key, "result")) {
			if (value->type != JSMN_OBJECT) {
				problem = "non-object \"result\"";
				goto bad;
			}

			enum exchg_currency c;
			int n = value->size;
			key_idx += 2;
			for (int j = 0; j < n; j++) {
				key = &toks[key_idx];
				value = key + 1;

				if (kraken_str_to_ccy(&c, json, key)) {
					warn = true;
					key_idx = json_skip(
						num_toks, toks, key_idx+1);
					continue;
				}
				if (json_get_decimal(&balances[c],
						     json, value)) {
					problem = "bad balance value";
					goto bad;
				}
				key_idx += 2;
			}
		} else
			key_idx = json_skip(num_toks, toks, key_idx+1);
	}

	struct http_data *h = conn_private(conn);
	exchg_on_balances(cl, balances, h->request_private);

	if (warn) {
		exchg_log("Some Kraken balances couldn't be parsed:\n");
		json_fprintln(stderr, json, &toks[0]);
	}
	return 0;

bad:
	exchg_log("Kraken sent bad balance info: %s:\n", problem);
	json_fprintln(stderr, json, &toks[0]);
	return -1;
}

static struct exchg_http_ops balances_ops = {
	.recv = balances_recv,
	.add_headers = private_http_add_headers,
	.conn_data_size = sizeof(struct http_data),
};

static int private_http_post(struct exchg_client *cl, const char *path,
			     struct exchg_http_ops *ops, void *req_private) {
	struct kraken_client *k = cl->priv;
	struct conn *http = exchg_http_post("api.kraken.com", path, ops, cl);
	if (!http)
		return -1;

	struct http_data *h = conn_private(http);
	h->request_private = req_private;

	int64_t nonce = current_micros();
	h->to_hash_len = sprintf(h->to_hash, "%"PRId64, nonce);
	h->body = h->to_hash + h->to_hash_len;
	h->body_len = conn_http_body_sprintf(http, "nonce=%"PRId64, nonce);
	if (h->body_len < 0) {
		conn_close(http);
		return -1;
	}
	memcpy(h->body, conn_http_body(http), h->body_len);
	h->to_hash_len += h->body_len;

	unsigned char to_auth[200+SHA256_DIGEST_LENGTH];
	size_t path_len = strlen(path);
	unsigned char *hash = to_auth + path_len;

	memcpy(to_auth, path, path_len);

	SHA256_Init(&k->sha_ctx);
	SHA256_Update(&k->sha_ctx, h->to_hash, h->to_hash_len);
	SHA256_Final(hash, &k->sha_ctx);

	h->hmac_len = hmac_b64(cl->hmac_ctx,
			       to_auth,
			       path_len +
			       SHA256_DIGEST_LENGTH, h->hmac);
	if (h->hmac_len < 0) {
		conn_close(http);
		return -1;
	}
	return 0;
}

static int kraken_get_balances(struct exchg_client *cl, void *req_private) {
	return private_http_post(cl, "/0/private/Balance", &balances_ops, req_private);
}

static int kraken_new_keypair(struct exchg_client *cl,
			      const unsigned char *key, size_t len) {
	struct kraken_client *kc = cl->priv;

	free(kc->ws_token);
	kc->ws_token = NULL;

	unsigned char *k;
	len = base64_decode(key, len, &k);
	if (len < 0)
		return len;
	if (!HMAC_Init_ex(cl->hmac_ctx, k, len, EVP_sha512(), NULL)) {
		exchg_log("%s HMAC_Init_ex() failure\n", __func__);
		free(k);
		return -1;
	}
	free(k);
	return 0;
}

static int token_recv(struct exchg_client *cl, struct conn *conn,
		      int status, char *json, int num_toks, jsmntok_t *toks) {
	struct kraken_client *kc = cl->priv;
	const char *problem;
	const char *url = "api.kraken.com/0/private/GetWebSocketsTokeninfo";

	kc->getting_token = false;

	if (num_toks < 1) {
		exchg_log("%s returned no data\n", url);
		return -1;
	}

	if (toks[0].type != JSMN_OBJECT) {
		problem = "non-object info";
		goto bad;
	}

	char *token = NULL;
	int key_idx = 1;
	for (int i = 0; i < toks[0].size; i++) {
		jsmntok_t *key = &toks[key_idx];
		jsmntok_t *value = key + 1;

		if (json_streq(json, key, "error") && value->size > 0) {
			problem = "error field set";
			goto bad;
		} else if (json_streq(json, key, "result")) {
			if (value->type != JSMN_OBJECT) {
				problem = "non-object \"result\"";
				goto bad;
			}
			int n = value->size;
			key_idx += 2;
			for (int j = 0; j < n; j++) {
				key = &toks[key_idx];
				value = key + 1;

				if (json_streq(json, key, "token")) {
					int err = json_strdup(&token, json, value);
					if (err == ENOMEM) {
						exchg_log("%s: OOM\n", __func__);
						return -1;
					} else if (err) {
						problem = "bad \"token\"";
						goto bad;
					}
					key_idx += 2;
				} else
					key_idx = json_skip(num_toks,
							    toks, key_idx+1);
			}
		} else
			key_idx = json_skip(num_toks, toks, key_idx+1);
	}

	if (!token) {
		problem = "no token given";
		goto bad;
	}
	free(kc->ws_token);
	kc->ws_token = token;
	exchg_do_work(cl);
	return 0;

bad:
	exchg_log("%s: %s\n", url, problem);
	json_fprintln(stderr, json, &toks[0]);
	return -1;
}

static void token_on_closed(struct exchg_client *cl, struct conn *conn) {
	struct kraken_client *kc = cl->priv;

	kc->getting_token = false;
}

static struct exchg_http_ops token_ops = {
	.recv = token_recv,
	.add_headers = private_http_add_headers,
	.on_closed = token_on_closed,
	.conn_data_size = sizeof(struct http_data),
};

static int get_token(struct exchg_client *cl) {
	struct kraken_client *kc = cl->priv;

	kc->getting_token = true;
	return private_http_post(cl, "/0/private/GetWebSocketsToken",
				 &token_ops, NULL);
}

enum openorders_status {
	NO_STATUS,
	STATUS_CANCELED,
	STATUS_CLOSED,
	STATUS_OPEN,
	STATUS_PENDING,
};

struct openorders_update {
	enum openorders_status status;
	bool got_size;
	decimal_t size;
	int64_t id;
	jsmntok_t *cancel_reason;
};

static int parse_openorders(struct exchg_client *cl,
			    const char *json, int num_toks, jsmntok_t *toks) {
	struct kraken_client *kkn = cl->priv;
	const char *problem;

	if (!kkn->openorders_recvd) {
		kkn->openorders_recvd = true;
		exchg_on_event(cl, EXCHG_PRIVATE_WS_ONLINE);
		exchg_do_work(cl);
		exchg_log("Kraken: openOrders channel inited\n");
		return 0;
	}
	if (toks[1].type != JSMN_ARRAY) {
		problem = "non array first element";
		goto bad;
	}
	if (toks[1].size == 0)
		return 0;

	int key_idx = 3;
	for (int i = 0; i < toks[2].size; i++) {
		jsmntok_t *key = &toks[key_idx];
		jsmntok_t *value = key + 1;

		if (value->type != JSMN_OBJECT) {
			problem = "non-object order update";
			goto bad;
		}

		struct openorders_update upd = {
			.status = NO_STATUS,
			.id = -1,
		};

		int n = value->size;
		key_idx += 2;
		for (int j = 0; j < n; j++) {
			key = &toks[key_idx];
			value = key + 1;

			if (json_streq(json, key, "status")) {
				if (json_streq(json, value, "canceled"))
					upd.status = STATUS_CANCELED;
				else if (json_streq(json, value, "closed"))
					upd.status = STATUS_CLOSED;
				else if (json_streq(json, value, "open"))
					upd.status = STATUS_OPEN;
				else if (json_streq(json, value, "pending"))
					upd.status = STATUS_PENDING;
			} else if (json_streq(json, key, "userref")) {
				if (json_get_int64(&upd.id, json, value)) {
					problem = "bad \"userref\" field";
					goto bad;
				}
			} else if (json_streq(json, key, "vol_exec")) {
				upd.got_size = true;
				if (json_get_decimal(&upd.size, json, value)) {
					problem = "bad \"vol_exec\" field";
					goto bad;
				}
			} else if (json_streq(json, key, "cancel_reason")) {
				upd.cancel_reason = value;
			}

			key_idx = json_skip(num_toks, toks, key_idx+1);
		}
		if (upd.id == -1) {
			continue;
		}
		if (upd.status == NO_STATUS)
			continue;

		struct order_info *oi = exchg_order_lookup(cl, upd.id);
		if (!oi) {
			exchg_log("Kraken: unrecognized \"userref\":\n");
			json_fprintln(stderr, json, &toks[0]);
			continue;
		}

		if (upd.got_size)
			oi->info.filled_size = upd.size;
		if (upd.status == STATUS_CLOSED)
			oi->info.status = EXCHG_ORDER_FINISHED;
		else if (upd.status == STATUS_CANCELED) {
			if (upd.cancel_reason)
				json_strncpy(oi->info.err, json, upd.cancel_reason, EXCHG_ORDER_ERR_SIZE);
			else
				strncpy(oi->info.err, "<unknown>", EXCHG_ORDER_ERR_SIZE);
			oi->info.status = EXCHG_ORDER_CANCELED;
		} else if (upd.status == STATUS_OPEN)
			oi->info.status = EXCHG_ORDER_OPEN;
		else if (upd.status == STATUS_PENDING)
			oi->info.status = EXCHG_ORDER_PENDING;
		exchg_order_update(cl, oi);
	}
	return 0;

bad:
	exchg_log("ws-auth.kraken.com returned bad data: %s:\n", problem);
	json_fprintln(stderr, json, &toks[0]);
	return -1;
}

static int private_ws_recv(struct exchg_client *cl, struct conn *conn,
			   char *json, int num_toks, jsmntok_t *toks) {
	const char *problem;

	if (toks[0].type == JSMN_OBJECT)
		return parse_event(cl, conn, json, num_toks, toks);

	if (toks[0].type != JSMN_ARRAY) {
		problem = "not an object or an array";
		goto bad;
	}
	if (toks[0].size != 3) {
		problem = "array num elements != 3";
		goto bad;
	}
	jsmntok_t *type = &toks[json_skip(num_toks, toks, 1)];

	if (json_streq(json, type, "openOrders")) {
		return parse_openorders(cl, json, num_toks, toks);
	} else {
		exchg_log("Kraken privte websocket sent data on unknown channel:\n");
		json_fprintln(stderr, json, &toks[0]);
	}
	return 0;

bad:
	exchg_log("ws-auth.kraken.com returned bad data: %s:\n", problem);
	json_fprintln(stderr, json, &toks[0]);
	return -1;
}

static int priv_sub(struct kraken_client *kkn) {
	if (conn_printf(kkn->private_ws, "{ \"event\": "
			"\"subscribe\", \"subscription\":"
			" {\"name\": \"openOrders\", "
			"\"token\": \"%s\"}}", kkn->ws_token) < 0)
		return -1;
	return 0;
}

static bool priv_sub_work(struct exchg_client *cl, void *p) {
	struct kraken_client *kkn = cl->priv;

	if (!kkn->ws_token || !conn_established(kkn->private_ws))
		return false;
	priv_sub(kkn);
	return true;
}

static int private_ws_on_established(struct exchg_client *cl,
				     struct conn *conn) {
	struct kraken_client *kkn = cl->priv;

	if (kkn->ws_token)
		return priv_sub(kkn);

	if (queue_work_exclusive(cl, priv_sub_work, NULL))
		return -1;
	if (!kkn->getting_token)
		return get_token(cl);
	return 0;
}

static void private_ws_on_disconnect(struct exchg_client *cl,
				     struct conn *conn,
				     int reconnect_seconds) {
	struct kraken_client *kkn = cl->priv;
	if (reconnect_seconds < 0)
		kkn->private_ws = NULL;
	kkn->openorders_recvd = false;
}

static const struct exchg_websocket_ops private_ws_ops = {
	.on_conn_established = private_ws_on_established,
	.on_disconnect = private_ws_on_disconnect,
	.recv = private_ws_recv,
};

static int private_ws_connect(struct exchg_client *cl) {
	struct kraken_client *kkn = cl->priv;

	kkn->private_ws = exchg_websocket_connect(cl, "ws-auth.kraken.com", "/",
						  &private_ws_ops);
	if (kkn->private_ws)
		return 0;
	return -1;
}

bool kraken_private_ws_online(struct exchg_client *cl) {
	struct kraken_client *kc = cl->priv;

	kc = cl->priv;
	return cl->pair_info_current && kc->openorders_recvd;
}

static int kraken_private_ws_connect(struct exchg_client *cl) {
	struct kraken_client *kc = cl->priv;

	if (kc->private_ws)
		return 0;

	if (exchg_get_pair_info(cl))
		return -1;

	if (private_ws_connect(cl))
		return -1;

	if (!kc->ws_token && !kc->getting_token)
		return get_token(cl);
	return 0;
}

static int private_ws_add_order(struct exchg_client *cl,
				struct exchg_order_info *info) {
	struct kraken_client *kkn = cl->priv;
	struct exchg_pair_info *pi = &cl->pair_info[info->order.pair];
	struct kraken_pair_info *kpi = &kkn->pair_info[info->order.pair];
	char sz[30], px[30];
	const char *timeinforce = "";

	if (unlikely(!pi->available)) {
		exchg_log("Kraken can't submit order in %s. Pair not available on Kraken\n",
			  exchg_pair_to_str(info->order.pair));
		return -1;
	}

	if (info->opts.immediate_or_cancel)
		timeinforce = ", \"timeinforce\": \"IOC\"";
	decimal_to_str(sz, &info->order.size);
	decimal_trim(&info->order.price, &info->order.price,
		     pi->price_decimals);
	decimal_to_str(px, &info->order.price);

	if (conn_printf(kkn->private_ws, "{\"event\": \"addOrder\", "
			"\"token\": \"%s\", \"reqid\": %"PRId64", "
			"\"userref\": \"%"PRId64"\", "
			"\"ordertype\": \"limit\", "
			"\"type\": \"%s\", "
			"\"pair\": \"%s\", "
			"\"price\": \"%s\", "
			"\"volume\": \"%s\"%s}",
			kkn->ws_token, info->id, info->id,
			info->order.side == EXCHG_SIDE_BUY ?
			"buy" : "sell", kpi->wsname, px, sz,
			timeinforce) < 0)
		return -1;
	info->status = EXCHG_ORDER_SUBMITTED;
	return 0;
}

static bool place_order_work(struct exchg_client *cl, void *p) {
	struct kraken_client *kkn = cl->priv;

	if (!cl->pair_info_current || !kkn->openorders_recvd)
		return false;
	private_ws_add_order(cl, (struct exchg_order_info *)p);
	return true;
}

static int64_t kraken_place_order(struct exchg_client *cl, struct exchg_order *order,
				  struct exchg_place_order_opts *opts,
				  void *request_private) {
	struct kraken_client *kkn = cl->priv;

	struct order_info *info = __exchg_new_order(cl, order, opts, request_private,
						    kkn->next_order_id++);
	if (!info)
		return -ENOMEM;

	if (cl->pair_info_current && kkn->openorders_recvd) {
		if (private_ws_add_order(cl, &info->info))
			return -1;
		return info->info.id;
	}

	if (!cl->pair_info_current && exchg_get_pair_info(cl))
		return -1;

	if (kraken_private_ws_connect(cl))
		return -1;

	if (queue_work(cl, place_order_work, info))
		return -ENOMEM;
	return info->info.id;
}

static void kraken_destroy(struct exchg_client *cl) {
	struct kraken_client *kkn = cl->priv;
	g_hash_table_unref(kkn->channel_mapping);
	for (enum exchg_pair p = 0; p < EXCHG_NUM_PAIRS; p++)
		free(kkn->pair_info[p].wsname);
	free(kkn->ws_token);
	free(kkn);
	free_exchg_client(cl);
}

struct exchg_client *alloc_kraken_client(struct exchg_context *ctx) {
	if (ctx->opts.sandbox) {
		exchg_log("kraken doesn't have a sandbox API endpoint\n");
		return NULL;
	}

	struct exchg_client *ret = alloc_exchg_client(ctx, EXCHG_KRAKEN, 2000);
	if (!ret)
		return NULL;
	struct kraken_client *kkn = malloc(sizeof(*kkn));
	if (!kkn) {
		exchg_log("OOM\n");
		free_exchg_client(ret);
		return NULL;
	}
	memset(kkn, 0, sizeof(*kkn));
	kkn->channel_mapping = g_hash_table_new(g_direct_hash, g_direct_equal);
	kkn->next_order_id = current_millis() % 86400000;

	ret->name = "Kraken";
	ret->priv = kkn;
	ret->l2_subscribe = kraken_l2_subscribe;
	ret->get_pair_info = kraken_get_pair_info;
	ret->get_balances = kraken_get_balances;
	ret->place_order = kraken_place_order;
	ret->priv_ws_connect = kraken_private_ws_connect;
	ret->priv_ws_online = kraken_private_ws_online;
	ret->new_keypair = kraken_new_keypair;
	ret->destroy = kraken_destroy;
	return ret;
}
