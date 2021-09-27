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
	unsigned int next_reqid;
	SHA256_CTX sha_ctx;
	GHashTable *channel_mapping;
	GHashTable *cancelations;
	struct websocket *data_ws;
	bool openorders_recvd;
	struct websocket *private_ws;
	bool getting_token;
	char *ws_token;
};

struct http_data {
	size_t hmac_len;
	char hmac[HMAC_SHA512_B64_LEN];
	size_t body_len;
	union {
		void *request_private;
		int64_t order_id;
	};
};

static int private_http_add_headers(struct exchg_client *cl, struct http *http) {
	struct http_data *h = http_private(http);

	if (http_add_header(http, (unsigned char *)"API-Key:",
			    (unsigned char *)cl->apikey_public,
			    cl->apikey_public_len))
		return 1;
	if (http_add_header(http, (unsigned char *)"API-Sign:",
			    (unsigned char*)h->hmac, h->hmac_len))
		return 1;
	if (http_add_header(http, (unsigned char *)"Content-Type:",
			    (unsigned char *)
			    "application/x-www-form-urlencoded",
			    strlen("application/x-www-form-urlencoded")))
		return 1;
	char l[16];
	size_t len = sprintf(l, "%zu", http_body_len(http));
	if (http_add_header(http, (unsigned char *)"Content-Length:",
			    (unsigned char *)l, len))
		return 1;
	return 0;
}

static int private_http_auth(struct exchg_client *cl, struct http *http) {
	struct http_data *h = http_private(http);
	struct kraken_client *k = client_private(cl);

	// 123456{body}&nonce=123456
	char *to_hash = malloc(20 + h->body_len + 27);
	if (!to_hash) {
		fprintf(stderr, "%s: OOM\n", __func__);
		return -1;
	}
	char *p = to_hash;
	int64_t nonce = current_micros();

	http_body_trunc(http, h->body_len);
	if (http_body_sprintf(http, "%snonce=%"PRId64,
			      http_body_len(http) > 0 ? "&" : "", nonce) < 0) {
		free(to_hash);
		return -1;
	}
	p += sprintf(p, "%"PRId64, nonce);
	memcpy(p, http_body(http), http_body_len(http));
	p += http_body_len(http);

	unsigned char to_auth[200+SHA256_DIGEST_LENGTH];
	const char *path = http_path(http);
	size_t path_len = strlen(path);
	unsigned char *hash = to_auth + path_len;

	memcpy(to_auth, path, path_len);

	SHA256_Init(&k->sha_ctx);
	SHA256_Update(&k->sha_ctx, to_hash, p-to_hash);
	SHA256_Final(hash, &k->sha_ctx);

	h->hmac_len = hmac_b64(cl->hmac_ctx, to_auth,
			       path_len + SHA256_DIGEST_LENGTH, h->hmac);
	if (h->hmac_len < 0) {
		free(to_hash);
		return -1;
	}
	free(to_hash);
	return 0;
}

static bool error_is_set(const char *json, jsmntok_t *err) {
	return err->type == JSMN_STRING || err->size > 0;
}

static void do_retry(struct exchg_client *cl, struct http *http,
		    const char *json, jsmntok_t *err) {
	if (private_http_auth(cl, http))
		return;
	exchg_log("Kraken: retrying https://%s%s %s after receiving error:\n",
		  http_host(http), http_path(http), http_method(http));
	json_fprintln(stderr, json, err);
	http_retry(http);
}

static bool retry_invalid_nonce(struct exchg_client *cl, struct http *http,
				const char *json, jsmntok_t *err) {
	if (err->type == JSMN_ARRAY) {
		for (int i = 1; i <= err->size; i++) {
			if (json_streq(json, err+i, "EAPI:Invalid nonce")) {
				do_retry(cl, http, json, err);
				return true;
			}
		}
	} else if (err->type == JSMN_STRING) {
		if (json_streq(json, err, "EAPI:Invalid nonce")) {
			do_retry(cl, http, json, err);
			return true;
		}
	}
	return false;
}

static int token_recv(struct exchg_client *cl, struct http *http,
		      int status, char *json, int num_toks, jsmntok_t *toks) {
	struct kraken_client *kc = client_private(cl);
	const char *problem;
	const char *url = "api.kraken.com/0/private/GetWebSocketsTokeninfo";

	if (toks[0].type != JSMN_OBJECT) {
		problem = "non-object info";
		goto bad;
	}

	char *token = NULL;
	int key_idx = 1;
	for (int i = 0; i < toks[0].size; i++) {
		jsmntok_t *key = &toks[key_idx];
		jsmntok_t *value = key + 1;

		if (json_streq(json, key, "error")) {
			if (error_is_set(json, value)) {
				if (retry_invalid_nonce(cl, http, json, value))
					return 0;
				problem = "error field set";
				goto bad;
			}
			key_idx = json_skip(num_toks, toks, key_idx+1);
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
						kc->getting_token = false;
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
	kc->getting_token = false;
	free(kc->ws_token);
	kc->ws_token = token;
	exchg_do_work(cl);
	return 0;

bad:
	kc->getting_token = false;
	exchg_log("%s: %s\n", url, problem);
	json_fprintln(stderr, json, &toks[0]);
	return -1;
}

static void token_on_free(struct exchg_client *cl, struct http *http) {
	struct kraken_client *kc = client_private(cl);

	kc->getting_token = false;
}

static struct exchg_http_ops token_ops = {
	.recv = token_recv,
	.add_headers = private_http_add_headers,
	.on_free = token_on_free,
	.conn_data_size = sizeof(struct http_data),
};

static int get_token(struct exchg_client *cl) {
	struct kraken_client *kc = client_private(cl);
	struct http *http = exchg_http_post("api.kraken.com", "/0/private/GetWebSocketsToken",
					    &token_ops, cl);
	if (!http)
		return -1;
	if (private_http_auth(cl, http)) {
		http_close(http);
		return -1;
	}
	kc->getting_token = true;
	return 0;
}

static int priv_sub(struct kraken_client *kkn) {
	if (websocket_printf(kkn->private_ws, "{ \"event\": "
			     "\"subscribe\", \"subscription\":"
			     " {\"name\": \"openOrders\", "
			     "\"token\": \"%s\"}}", kkn->ws_token) < 0)
		return -1;
	return 0;
}

static bool priv_sub_work(struct exchg_client *cl, void *p) {
	struct kraken_client *kkn = client_private(cl);

	if (!kkn->ws_token || !websocket_established(kkn->private_ws))
		return false;
	priv_sub(kkn);
	return true;
}

static int kraken_subscribe(struct kraken_client *kkn, enum exchg_pair pair) {
	struct kraken_pair_info *pi = &kkn->pair_info[pair];

	pi->subbed = true;
	if (websocket_printf(kkn->data_ws, "{ \"event\": \"subscribe\", "
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

struct kraken_order {
	bool canceling;
	unsigned int cancel_reqid;
};

static void cancel_free(struct exchg_client *cl, unsigned int reqid) {
	struct kraken_client *kkn = client_private(cl);

	g_hash_table_remove(kkn->cancelations, GUINT_TO_POINTER(reqid));
}

static void cancel_done(struct exchg_client *cl, struct order_info *oi) {
	struct kraken_order *k = order_info_private(oi);

	if (k->cancel_reqid > 0)
		cancel_free(cl, k->cancel_reqid);
	k->canceling = false;
	k->cancel_reqid = 0;
}

static void order_update(struct exchg_client *cl, struct order_info *oi,
			 enum exchg_order_status new_status, const decimal_t *new_size, bool cancel_failed) {
	if (order_status_done(new_status))
		cancel_done(cl, oi);
	exchg_order_update(cl, oi, new_status, new_size, cancel_failed);
}

enum event_type {
	EVENT_SUB_STATUS,
	EVENT_ADD_ORDER,
	EVENT_CANCEL_ORDER,
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
	jsmntok_t *status;
	jsmntok_t *error_msg;
	enum event_type type;
	enum channel_name name;
	enum exchg_pair pair;
	unsigned int reqid;
};

static int parse_event(struct exchg_client *cl,
		       const char *json, int num_toks, jsmntok_t *toks) {
	struct kraken_client *kkn = client_private(cl);
	const char *problem;
	struct event_msg status = {
		.channel_id = -1,
		.status = NULL,
		.error_msg = NULL,
		.type = EVENT_UNKNOWN,
		.name = CHAN_UNSET,
		.pair = INVALID_PAIR,
	};

	int key_idx = 1;
	for (int i = 0; i < toks[0].size; i++) {
		jsmntok_t *key = &toks[key_idx];
		jsmntok_t *value = key + 1;

		if (json_streq(json, key, "event")) {
			if (json_streq(json, value, "subscriptionStatus")) {
				status.type = EVENT_SUB_STATUS;
			} else if (json_streq(json, value, "addOrderStatus")) {
				status.type = EVENT_ADD_ORDER;
			} else if (json_streq(json, value, "cancelOrderStatus")) {
				status.type = EVENT_CANCEL_ORDER;
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
			status.status = value;
			key_idx = json_skip(num_toks, toks, key_idx+1);
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
			if (json_get_uint(&status.reqid, json, value)) {
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
	if (!status.status) {
		problem = "missing \"status\"";
		goto bad;
	}

	if (status.type == EVENT_SUB_STATUS) {
		if (!json_streq(json, status.status, "subscribed")) {
			// TODO: also probly should check that subscription:name:
			// is "openOrders"
			if (kkn->private_ws && !kkn->openorders_recvd &&
			    status.error_msg &&
			    json_streq(json, status.error_msg,
				       "ESession:Invalid session")) {
				exchg_log("Getting new token after subscription error:\n");
				json_fprintln(stderr, json, &toks[0]);
				free(kkn->ws_token);
				kkn->ws_token = NULL;
				get_token(cl);
				queue_work_exclusive(cl, priv_sub_work, NULL);
				return 0;
			}
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
	} else if (status.type == EVENT_ADD_ORDER) {
		if (status.reqid == 0) {
			problem = "no \"reqid\" field";
			goto bad;
		}
		struct order_info *oi = exchg_order_lookup(cl, status.reqid);
		if (!oi) {
			exchg_log("Kraken: unrecognized \"reqid\":\n");
			json_fprintln(stderr, json, &toks[0]);
			return 0;
		}
		enum exchg_order_status new_status;
		if (json_streq(json, status.status, "ok")) {
			new_status = EXCHG_ORDER_PENDING;
		} else {
			new_status = EXCHG_ORDER_ERROR;
			order_err_cpy(&oi->info, json, status.error_msg);
		}
		order_update(cl, oi, new_status, NULL, false);
	} else if (status.type == EVENT_CANCEL_ORDER) {
		if (status.reqid == 0)
			return 0;
		unsigned int id = GPOINTER_TO_UINT(g_hash_table_lookup(kkn->cancelations,
								       GUINT_TO_POINTER(status.reqid)));
		if (!id)
			return 0;
		struct order_info *oi = exchg_order_lookup(cl, id);
		if (!oi) {
			exchg_log("Kraken: Received order cancel update for unknown order:\n");
			json_fprintln(stderr, json, &toks[0]);
			cancel_free(cl, id);
			return 0;
		}
		cancel_done(cl, oi);
		if (json_streq(json, status.status, "ok")) {
			exchg_order_update(cl, oi, EXCHG_ORDER_CANCELED, NULL, false);
		} else {
			order_err_cpy(&oi->info, json, status.error_msg);
			exchg_order_update(cl, oi, EXCHG_ORDER_SUBMITTED, NULL, true);
			exchg_log("Kraken: cancelation of order %u failed:\n", id);
			json_fprintln(stderr, json, &toks[0]);
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

static int kraken_recv(struct exchg_client *cl, struct websocket *w,
		       char *json, int num_toks, jsmntok_t *toks) {
	struct kraken_client *kkn = client_private(cl);

	if (num_toks < 3)
		return 0;

	if (toks[0].type == JSMN_OBJECT)
		return parse_event(cl, json, num_toks, toks);

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
	struct kraken_client *kkn = client_private(cl);

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
	struct kraken_client *kkn = client_private(cl);

	if (!cl->pair_info_current || !websocket_established(kkn->data_ws))
		return false;

	book_sub(cl);
	return true;
}

static int kraken_conn_established(struct exchg_client *cl,
				   struct websocket *w) {
	if (!cl->pair_info_current)
		return queue_work_exclusive(cl, book_sub_work, NULL);
	else
		return book_sub(cl);
}

static int kraken_on_disconnect(struct exchg_client *cl, struct websocket *w,
				int reconnect_seconds) {
	struct kraken_client *kkn = client_private(cl);
	int num_pairs_gone = 0;
	enum exchg_pair pairs_gone[EXCHG_NUM_PAIRS];
	if (reconnect_seconds < 0)
		kkn->data_ws = NULL;
	for (enum exchg_pair pair = 0; pair < EXCHG_NUM_PAIRS; pair++) {
		struct exchg_pair_info *pi = &cl->pair_info[pair];
		struct kraken_pair_info *kpi = &kkn->pair_info[pair];
		if (kpi->watching_l2 && pi->available) {
			pairs_gone[num_pairs_gone++] = pair;
			exchg_book_clear(cl, pair);
		}
		kpi->subbed = false;
	}
	exchg_data_disconnect(cl, w, num_pairs_gone, pairs_gone);
	return 0;
}

static const struct exchg_websocket_ops websocket_ops = {
	.on_conn_established = kraken_conn_established,
	.on_disconnect = kraken_on_disconnect,
	.recv = kraken_recv,
};

static int kraken_connect(struct exchg_client *cl) {
	struct kraken_client *kkn = client_private(cl);
	kkn->data_ws = exchg_websocket_connect(cl, "ws.kraken.com", "/",
					       &websocket_ops);
	if (kkn->data_ws)
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

static const char *kraken_pair_to_str(enum exchg_pair pair) {
	switch (pair) {
	case EXCHG_PAIR_BTCUSD:
		return "XXBTZUSD";
	case EXCHG_PAIR_ETHUSD:
		return "XETHZUSD";
	case EXCHG_PAIR_ETHBTC:
		return "XETHXXBT";
	case EXCHG_PAIR_ZECUSD:
		return "XZECZUSD";
	case EXCHG_PAIR_ZECBTC:
		return "XZECXXBT";
	case EXCHG_PAIR_ZECETH:
		return "XZECXETH";
	case EXCHG_PAIR_ZECBCH:
		return "ZECBCH";
	case EXCHG_PAIR_ZECLTC:
		return "XZECXLTC";
	case EXCHG_PAIR_BCHUSD:
		return "BCHUSD";
	case EXCHG_PAIR_BCHBTC:
		return "BCHXBT";
	case EXCHG_PAIR_BCHETH:
		return "BCHETH";
	case EXCHG_PAIR_LTCUSD:
		return "XLTCZUSD";
	case EXCHG_PAIR_LTCBTC:
		return "XLTCXXBT";
	case EXCHG_PAIR_LTCETH:
		return "LTCETH";
	case EXCHG_PAIR_LTCBCH:
		return "LTCBCH";
	case EXCHG_PAIR_DAIUSD:
		return "DAIUSD";
	default:
		return NULL;
	}
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
	struct kraken_client *kkn = client_private(cl);

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

static int kraken_parse_info(struct exchg_client *cl, struct http *http,
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

static int kraken_l2_subscribe(struct exchg_client *cl, enum exchg_pair pair) {
	struct kraken_client *kkn = client_private(cl);
	struct kraken_pair_info *kpi = &kkn->pair_info[pair];

	if (kpi->subbed)
		return 0;

	kpi->watching_l2 = true;

	if (cl->pair_info_current && websocket_established(kkn->data_ws))
		return kraken_subscribe(kkn, pair);

	if (!kkn->data_ws && kraken_connect(cl))
		return -1;
	return 0;
}

static int kraken_get_pair_info(struct exchg_client *cl) {
	if (!exchg_http_get("api.kraken.com", "/0/public/AssetPairs",
			    &get_info_ops, cl))
		return -1;
	return 0;
}

static int balances_recv(struct exchg_client *cl, struct http *http,
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
			if (error_is_set(json, value)) {
				if (retry_invalid_nonce(cl, http, json, value))
					return 0;
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

	struct http_data *h = http_private(http);
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

static int kraken_get_balances(struct exchg_client *cl, void *req_private) {
	struct http *http = exchg_http_post("api.kraken.com", "/0/private/Balance",
					    &balances_ops, cl);
	if (!http)
		return -1;
	struct http_data *h = http_private(http);
	h->request_private = req_private;

	if (private_http_auth(cl, http)) {
		http_close(http);
		return -1;
	}
	return 0;
}

static int kraken_new_keypair(struct exchg_client *cl,
			      const unsigned char *key, size_t len) {
	struct kraken_client *kc = client_private(cl);

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

enum openorders_status {
	NO_STATUS,
	STATUS_CANCELED,
	STATUS_CLOSED,
	STATUS_OPEN,
	STATUS_PENDING,
};

struct openorders_update {
	enum openorders_status status;
	decimal_t size;
	int64_t id;
	jsmntok_t *cancel_reason;
};

static int parse_openorders(struct exchg_client *cl,
			    const char *json, int num_toks, jsmntok_t *toks) {
	struct kraken_client *kkn = client_private(cl);
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
		if (!oi)
			continue;

		enum exchg_order_status status;

		switch (upd.status) {
		case STATUS_CLOSED:
			status = EXCHG_ORDER_FINISHED;
			break;
		case STATUS_CANCELED:
			order_err_cpy(&oi->info, json, upd.cancel_reason);
			status = EXCHG_ORDER_CANCELED;
			break;
		case STATUS_OPEN:
			status = EXCHG_ORDER_OPEN;
			break;
		case STATUS_PENDING:
		case NO_STATUS:
			status = EXCHG_ORDER_PENDING;
			break;
		}
		order_update(cl, oi, status, &upd.size, false);
	}
	return 0;

bad:
	exchg_log("ws-auth.kraken.com returned bad data: %s:\n", problem);
	json_fprintln(stderr, json, &toks[0]);
	return -1;
}

static int private_ws_recv(struct exchg_client *cl, struct websocket *w,
			   char *json, int num_toks, jsmntok_t *toks) {
	const char *problem;

	if (toks[0].type == JSMN_OBJECT)
		return parse_event(cl, json, num_toks, toks);

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

static int private_ws_on_established(struct exchg_client *cl, struct websocket *w) {
	struct kraken_client *kkn = client_private(cl);

	if (kkn->ws_token)
		return priv_sub(kkn);

	if (queue_work_exclusive(cl, priv_sub_work, NULL))
		return -1;
	if (!kkn->getting_token)
		return get_token(cl);
	return 0;
}

static int private_ws_on_disconnect(struct exchg_client *cl,
				    struct websocket *w,
				    int reconnect_seconds) {
	struct kraken_client *kkn = client_private(cl);
	if (reconnect_seconds < 0)
		kkn->private_ws = NULL;
	kkn->openorders_recvd = false;
	return 0;
}

static const struct exchg_websocket_ops private_ws_ops = {
	.on_conn_established = private_ws_on_established,
	.on_disconnect = private_ws_on_disconnect,
	.recv = private_ws_recv,
};

static int private_ws_connect(struct exchg_client *cl) {
	struct kraken_client *kkn = client_private(cl);

	kkn->private_ws = exchg_websocket_connect(cl, "ws-auth.kraken.com", "/",
						  &private_ws_ops);
	if (kkn->private_ws)
		return 0;
	return -1;
}

bool kraken_private_ws_online(struct exchg_client *cl) {
	struct kraken_client *kc = client_private(cl);

	return cl->pair_info_current && kc->openorders_recvd;
}

static int kraken_private_ws_connect(struct exchg_client *cl) {
	struct kraken_client *kc = client_private(cl);

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
	struct kraken_client *kkn = client_private(cl);
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

	if (websocket_printf(kkn->private_ws, "{\"event\": \"addOrder\", "
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

static int add_order_recv(struct exchg_client *cl, struct http *http,
			  int status, char *json, int num_toks, jsmntok_t *toks) {
	struct http_data *data = http_private(http);
	struct order_info *info = exchg_order_lookup(cl, data->order_id);

	if (!info)
		return 0;

	if (toks[0].type != JSMN_OBJECT) {
		exchg_log("%s%s sent non-object data:\n", http_host(http), http_path(http));
		json_fprintln(stderr, json, &toks[0]);
		return 0;
	}

	int key_idx = 1;
	for (int i = 0; i < toks[0].size; i++) {
		jsmntok_t *key = &toks[key_idx];
		jsmntok_t *value = key + 1;

		if (json_streq(json, key, "error")) {
			enum exchg_order_status new_status = EXCHG_ORDER_PENDING;

			if (value->type != JSMN_ARRAY || value->size > 1) {
				order_err_cpy(&info->info, json, value);
				new_status = EXCHG_ORDER_ERROR;
			} else if (value->size == 1) {
				order_err_cpy(&info->info, json, value+1);
				new_status = EXCHG_ORDER_ERROR;
			}
			order_update(cl, info, new_status, NULL, false);
			return 0;
		}
		key_idx = json_skip(num_toks, toks, key_idx+1);
	}
	order_update(cl, info, EXCHG_ORDER_PENDING, NULL, false);
	return 0;
}

static void add_order_on_err(struct exchg_client *cl, struct http *http,
			     const char *err) {
	struct http_data *data = http_private(http);
	struct order_info *info = exchg_order_lookup(cl, data->order_id);

	if (!info)
		return;
	if (err)
		strncpy(info->info.err, err, EXCHG_ORDER_ERR_SIZE);
	else
		strncpy(info->info.err, "<unknown>", EXCHG_ORDER_ERR_SIZE);
	order_update(cl, info, EXCHG_ORDER_ERROR, NULL, false);
}

static int __attribute__((format (printf, 2, 3)))
kraken_body_sprintf(struct http *http, const char *fmt, ...) {
	va_list ap;
	int len;
	struct http_data *data = http_private(http);

	va_start(ap, fmt);
	len = http_body_vsprintf(http, fmt, ap);
	if (len > 0)
		data->body_len += len;
	va_end(ap);
	return len;
}

static struct exchg_http_ops add_order_ops = {
	.recv = add_order_recv,
	.on_error = add_order_on_err,
	.add_headers = private_http_add_headers,
	.conn_data_size = sizeof(struct http_data),
};

static int http_post_add_order(struct exchg_client *cl,
			       struct order_info *oi, bool update_on_err) {
	struct exchg_order_info *info = &oi->info;
	struct exchg_pair_info *pi = &cl->pair_info[info->order.pair];
	char sz[30], px[30];

	if (unlikely(!pi->available)) {
		exchg_log("Kraken can't submit order in %s. Pair not available on Kraken\n",
			  exchg_pair_to_str(info->order.pair));
		if (update_on_err)
			order_err_update(cl, oi, "%s not available on Kraken",
					 exchg_pair_to_str(info->order.pair));
		return -1;
	}

	struct http *http = exchg_http_post("api.kraken.com", "/0/private/AddOrder",
					    &add_order_ops, cl);
	if (!http) {
		if (update_on_err)
			order_err_update(cl, oi, "HTTP POST failed");
		return -1;
	}

	decimal_to_str(sz, &info->order.size);
	decimal_trim(&info->order.price, &info->order.price,
		     pi->price_decimals);
	decimal_to_str(px, &info->order.price);

	if (kraken_body_sprintf(http, "userref=%"PRId64"&ordertype=limit&"
				"type=%s&pair=%s&price=%s&volume=%s",
				info->id, info->order.side == EXCHG_SIDE_BUY ?
				"buy" : "sell", kraken_pair_to_str(info->order.pair),
				px, sz) < 0) {
		if (update_on_err)
			order_err_update(cl, oi, "OOM writing order");
		http_close(http);
		return -1;
	}
	if (info->opts.immediate_or_cancel &&
	    kraken_body_sprintf(http, "&timeinforce=IOC") < 0) {
		if (update_on_err)
			order_err_update(cl, oi, "OOM writing order");
		http_close(http);
		return -1;
	}
	if (private_http_auth(cl, http)) {
		if (update_on_err)
			order_err_update(cl, oi, "HMAC computation failed");
		http_close(http);
		return -1;
	}
	info->status = EXCHG_ORDER_SUBMITTED;
	struct http_data *data = http_private(http);
	data->order_id = info->id;
	return 0;
}

static bool place_order_work(struct exchg_client *cl, void *p) {
	if (!cl->pair_info_current)
		return false;
	http_post_add_order(cl, (struct order_info *)p, true);
	return true;
}

static unsigned int get_reqid(struct exchg_client *cl) {
	struct kraken_client *kkn = client_private(cl);
	unsigned int reqid = kkn->next_reqid++;

	if (reqid == 0)
		reqid = kkn->next_reqid++;
	return reqid;
}

static int64_t kraken_place_order(struct exchg_client *cl, const struct exchg_order *order,
				  const struct exchg_place_order_opts *opts,
				  void *request_private) {
	struct kraken_client *kkn = client_private(cl);

	struct order_info *info = __exchg_new_order(cl, order, opts, request_private,
						    sizeof(struct kraken_order), get_reqid(cl));
	if (!info)
		return -ENOMEM;
	struct kraken_order *k = order_info_private(info);
	k->cancel_reqid = 0;
	k->canceling = false;

	if (unlikely(!cl->pair_info_current)) {
		if (exchg_get_pair_info(cl) || queue_work(cl, place_order_work, info)) {
			order_info_free(cl, info);
			return -1;
		}
		return 0;
	}

	if (kkn->openorders_recvd && kkn->ws_token) {
		if (private_ws_add_order(cl, &info->info)) {
			order_info_free(cl, info);
			return -1;
		}
	} else {
		if (http_post_add_order(cl, info, false)) {
			order_info_free(cl, info);
			return -1;
		}
	}
	return info->info.id;
}

static int cancel_order_recv(struct exchg_client *cl, struct http *http,
			     int status, char *json, int num_toks, jsmntok_t *toks) {
	struct http_data *data = http_private(http);
	struct order_info *oi = exchg_order_lookup(cl, data->order_id);
	const char *problem = "";

	if (!oi)
		return 0;

	cancel_done(cl, oi);

	if (toks[0].type != JSMN_OBJECT) {
		problem = "not an object";
		goto bad;
	}

	bool got_count = false;
	int count;
	int key_idx = 1;
	for (int i = 0; i < toks[0].size; i++) {
		jsmntok_t *key = &toks[key_idx];
		jsmntok_t *value = key + 1;

		if (json_streq(json, key, "error")) {
			if (value->type == JSMN_ARRAY && value->size == 0) {
				key_idx += 2;
				continue;
			}
			if (value->type != JSMN_ARRAY || value->size > 1)
				order_err_cpy(&oi->info, json, value);
			else
				order_err_cpy(&oi->info, json, value+1);
			exchg_order_update(cl, oi, EXCHG_ORDER_SUBMITTED, NULL, true);
			return 0;
		} else if (json_streq(json, key, "result")) {
			if (value->type != JSMN_OBJECT) {
				problem = "bad \"result\"";
				goto bad;
			}
			int n = value->size;
			key_idx += 2;
			for (int j = 0; j < n; j++) {
				key = &toks[key_idx];
				value = key + 1;

				if (json_streq(json, key, "count")) {
					if (json_get_int(&count, json, value)) {
						problem = "bad \"result\":\"count\"";
						goto bad;
					}
					got_count = true;
					key_idx += 2;
				} else {
					key_idx = json_skip(num_toks, toks, key_idx+1);
				}
			}
		} else {
			key_idx = json_skip(num_toks, toks, key_idx+1);
		}
	}
	if (!got_count) {
		problem = "no \"result\":\"count\"";
		goto bad;
	}
	if (count != 1) {
		exchg_log("%s%s sent data with \"result\":\"count\" != 1:\n", http_host(http), http_path(http));
		json_fprintln(stderr, json, &toks[0]);
	}
	if (count > 0)
		exchg_order_update(cl, oi, EXCHG_ORDER_CANCELED, NULL, false);
	return 0;

bad:
	snprintf(oi->info.err, EXCHG_ORDER_ERR_SIZE, "%s%s sent bad data",
		 http_host(http), http_path(http));
	exchg_order_update(cl, oi, EXCHG_ORDER_SUBMITTED, NULL, true);
	exchg_log("%s%s sent bad data: %s\n", http_host(http), http_path(http), problem);
	json_fprintln(stderr, json, &toks[0]);
	return 0;
}

static void cancel_order_on_err(struct exchg_client *cl, struct http *http,
				const char *err) {
	struct http_data *data = http_private(http);
	struct order_info *info = exchg_order_lookup(cl, data->order_id);

	if (!info)
		return;
	if (err)
		strncpy(info->info.err, err, EXCHG_ORDER_ERR_SIZE);
	else
		strncpy(info->info.err, "<unknown>", EXCHG_ORDER_ERR_SIZE);
	cancel_done(cl, info);
	exchg_order_update(cl, info, EXCHG_ORDER_SUBMITTED, NULL, true);
}

static void cancel_order_on_closed(struct exchg_client *cl, struct http *http) {
	struct http_data *data = http_private(http);
	struct order_info *info = exchg_order_lookup(cl, data->order_id);

	if (info)
		cancel_done(cl, info);
}

static struct exchg_http_ops cancel_order_ops = {
	.recv = cancel_order_recv,
	.add_headers = private_http_add_headers,
	.on_error = cancel_order_on_err,
	.on_closed = cancel_order_on_closed,
	.conn_data_size = sizeof(struct http_data),
};

static int kraken_cancel_order(struct exchg_client *cl, struct order_info *info) {
	struct kraken_client *kkn = client_private(cl);
	struct kraken_order *ko = order_info_private(info);

	if (unlikely(ko->canceling))
		return 0;

	if (websocket_established(kkn->private_ws) && kkn->ws_token) {
		unsigned int reqid = get_reqid(cl);
		// TODO: there should be an exchg_cancel_orders()
		// function canceling multiple at once
		if (websocket_printf(kkn->private_ws, "{\"event\": \"cancelOrder\", \"reqid\": %u, "
				     "\"token\": \"%s\", \"txid\": [\"%"PRId64"\"]}",
				     reqid, kkn->ws_token, info->info.id) < 0)
			return -1;
		ko->cancel_reqid = reqid;
		// cast is fine since the id comes from ->next_reqid
		g_hash_table_insert(kkn->cancelations, GUINT_TO_POINTER(reqid),
				    GUINT_TO_POINTER((unsigned int)info->info.id));
	} else {
		struct http *http = exchg_http_post("api.kraken.com", "/0/private/CancelOrder",
						    &cancel_order_ops, cl);
		if (!http)
			return -1;
		if (kraken_body_sprintf(http, "txid=%"PRId64, info->info.id) < 0) {
			http_close(http);
			return -1;
		}
		if (private_http_auth(cl, http)) {
			http_close(http);
			return -1;
		}
		struct http_data *data = http_private(http);
		data->order_id = info->info.id;
	}
	ko->canceling = true;
	return 0;
}

static void kraken_destroy(struct exchg_client *cl) {
	struct kraken_client *kkn = client_private(cl);
	g_hash_table_unref(kkn->channel_mapping);
	g_hash_table_unref(kkn->cancelations);
	for (enum exchg_pair p = 0; p < EXCHG_NUM_PAIRS; p++)
		free(kkn->pair_info[p].wsname);
	free(kkn->ws_token);
	free_exchg_client(cl);
}

struct exchg_client *alloc_kraken_client(struct exchg_context *ctx) {
	if (ctx->opts.sandbox) {
		exchg_log("kraken doesn't have a sandbox API endpoint\n");
		return NULL;
	}

	struct exchg_client *ret = alloc_exchg_client(ctx, EXCHG_KRAKEN, 2000, sizeof(struct kraken_client));
	if (!ret)
		return NULL;
	struct kraken_client *kkn = client_private(ret);

	kkn->channel_mapping = g_hash_table_new(g_direct_hash, g_direct_equal);
	kkn->cancelations = g_hash_table_new(g_direct_hash, g_direct_equal);
	kkn->next_reqid = current_millis() % 86400000;

	ret->name = "Kraken";
	ret->l2_subscribe = kraken_l2_subscribe;
	ret->get_pair_info = kraken_get_pair_info;
	ret->get_balances = kraken_get_balances;
	ret->place_order = kraken_place_order;
	ret->cancel_order = kraken_cancel_order;
	ret->priv_ws_connect = kraken_private_ws_connect;
	ret->priv_ws_online = kraken_private_ws_online;
	ret->new_keypair = kraken_new_keypair;
	ret->destroy = kraken_destroy;
	return ret;
}
