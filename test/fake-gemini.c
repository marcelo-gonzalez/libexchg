#include <glib.h>
#include <jsmn/jsmn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "auth.h"
#include "exchg/exchg.h"
#include "json-helpers.h"
#include "fake-net.h"
#include "fake-gemini.h"
#include "util.h"
#include "net-backend.h"

struct gemini_websocket {
	enum exchg_pair pair;
	int sequence;
	int first_sent;
};

static size_t gemini_write_orders(char *buf, struct gemini_websocket *g,
				  struct fake_book_update *up, enum exchg_side side) {
	char *c = buf;
	struct fake_book_update_single *orders;
	int n;

	if (side == EXCHG_SIDE_BUY) {
		orders = &up->bids[0];
		n = up->num_bids;
	} else {
		orders = &up->asks[0];
		n = up->num_asks;
	}

	for (int i = 0; i < n; i++) {
		char size[30], price[30];
		decimal_to_str(size, &orders[i].size);
		decimal_to_str(price, &orders[i].price);

		const char *reason, *sidestr;
		if (!g->first_sent)
			reason = "initial";
		else if (!decimal_is_zero(&orders[i].size))
			reason = "place";
		else
			reason = "cancel";

		if (side == EXCHG_SIDE_BUY)
			sidestr = "bid";
		else
			sidestr = "ask";

		// note "delta" is missing
		c += sprintf(c,
			     "{\"type\": \"change\", \"reason\": \"%s\""
			     ", \"price\": \"%s\", "
			     "\"remaining\": \"%s\", \"side\": \"%s\"}, ",
			     reason, price, size, sidestr);
	}
	return c-buf;
}

static int get_counter(void) {
	static int x;
	return ++x;
}

static size_t gemini_ws_read(struct websocket *ws, char **dst, struct exchg_test_event *msg) {
	struct gemini_websocket *g = ws->priv;
	char *buf = xzalloc(1<<13);
	size_t len = sprintf(buf, "{\"type\": \"update\", \"event_id\": %d, "
			     "\"socket_sequence\": %d, \"events\": [",
			     get_counter(), g->sequence++);
	len += gemini_write_orders(buf+len, g, &msg->data.book, EXCHG_SIDE_BUY);
	len += gemini_write_orders(buf+len, g, &msg->data.book, EXCHG_SIDE_SELL);
	len += sprintf(buf+len, "]}");
	*dst = buf;
	return len;
}

static void gemini_ws_destroy(struct websocket *w) {
	free(w->priv);
	free(w);
}

static int gemini_ws_matches(struct websocket *w, enum exchg_pair p) {
	struct gemini_websocket *g = w->priv;
	return g->pair == p;
}

struct websocket *gemini_ws_dial(struct exchg_net_context *ctx,
				 const char *path, void *private) {
	if (strncmp(path, "/v1/marketdata/", strlen("/v1/marketdata/"))) {
		// TODO helper
		fprintf(stderr, "Gemini bad path: %s\n", path);
		return NULL;
	}
	enum exchg_pair pair;
	char p[7];
	if (strlen(path) < strlen("/v1/marketdata/") + 6) {
		fprintf(stderr, "Gemini bad path: %s\n", path);
		return NULL;
	}
	memcpy(p, path + strlen("/v1/marketdata/"), 6);
	p[6] = 0;
	if (exchg_str_to_pair(&pair, p)) {
		fprintf(stderr, "Gemini bad path: %s\n", path);
		return NULL;
	}

	struct websocket *s = fake_websocket_alloc(ctx, private);
	// TODO: can set that in core code
	s->id = EXCHG_GEMINI;
	s->read = gemini_ws_read;
	s->write = no_ws_write;
	s->matches = gemini_ws_matches;
	s->destroy = gemini_ws_destroy;
	struct gemini_websocket *g = xzalloc(sizeof(struct gemini_websocket));
	g->pair = pair;
	s->priv = g;
	return s;
}

static size_t balances_read(struct http_req *req, struct exchg_test_event *ev,
			    char **dst) {
	struct auth_check *a = req->priv;
	char *buf = xzalloc(400);
	char *b = buf;

	if (a->hmac_status == AUTH_GOOD) {
		b += sprintf(b, "[");
		for (enum exchg_currency c = 0; c < EXCHG_NUM_CCYS; c++) {
			decimal_t *balance = &req->ctx->balances[EXCHG_GEMINI][c];
			if (!decimal_is_positive(balance))
				continue;
			char s[30];
			decimal_to_str(s, balance);
			b += sprintf(b, "{ \"type\": \"exchange\", \"currency\": \"%s\", "
				     "\"amount\": \"%s\", \"available\": \"%s\", "
				     "\"availableForWithdrawal\": \"%s\" }, ",
				     exchg_ccy_to_upper(c), s, s, s);
		}
		b += sprintf(b, "]");
		*dst = buf;
		return b-buf;
	}
	if (a->hmac_status == AUTH_BAD) {
		size_t len =  sprintf(buf, "{ \"result\": \"error\", \"reason\": \"InvalidSignature\","
				      "\"message\": \"InvalidSignature\" }");
		*dst = buf;
		return len;
	}
	size_t len = sprintf(buf, "{}");
	*dst = buf;
	return len;
}

static void auth_add_header(struct auth_check *a, const unsigned char *name,
			    const unsigned char *val, size_t len) {
	if (!strcmp((char *)name, "X-GEMINI-APIKEY:")) {
		auth_check_set_public(a, val, len);
	} else if (!strcmp((char *)name, "X-GEMINI-PAYLOAD:")) {
		auth_check_set_payload(a, val, len);
	} else if (!strcmp((char *)name, "X-GEMINI-SIGNATURE:")) {
		auth_check_set_hmac(a, val, len);
	}
}

static void balances_add_header(struct http_req *req, const unsigned char *name,
				const unsigned char *val, size_t len) {
	auth_add_header((struct auth_check *)req->priv, name, val, len);
}

static void balances_free(struct http_req *req) {
	auth_check_free((struct auth_check *)req->priv);
	fake_http_req_free(req);
}

static void balances_fill_event(struct http_req *req, struct exchg_test_event *ev) {
	ev->type = EXCHG_EVENT_BALANCES;
}

static struct http_req *balances_dial(struct exchg_net_context *ctx,
				      const char *path, const char *method,
				      void *private) {
	if (strcmp(method, "POST")) {
		fprintf(stderr, "Gemini bad method for %s: %s\n", path, method);
		return NULL;
	}

	struct http_req *req = fake_http_req_alloc(ctx, private);
	req->fill_event = balances_fill_event;
	req->read = balances_read;
	req->add_header = balances_add_header;
	req->write = no_http_write;
	req->destroy = balances_free;
	req->priv = auth_check_alloc(strlen(exchg_test_gemini_public),
				     (unsigned char *)exchg_test_gemini_public,
				     strlen(exchg_test_gemini_private),
				     (unsigned char *)exchg_test_gemini_private,
				     1, HEX_LOWER, EVP_sha384());
	return req;
}

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*x))

struct http_place_order {
	struct auth_check *auth;
	// TODO: maybe but the struct exchg_test_event * in struct http_req
	struct fake_ack ack;
	jsmn_parser parser;
	jsmntok_t toks[200];
};

static size_t place_order_read(struct http_req *req, struct exchg_test_event *ev,
			       char **dst) {
	struct http_place_order *p = req->priv;
	char *buf = xzalloc(1<<10);
	char *b = buf;

	if (p->auth->hmac_status == AUTH_GOOD) {
		char price[30];
		char size[30];

		decimal_to_str(price, &ev->data.ack.price);
		decimal_to_str(size, &ev->data.ack.size);
		size_t len =  sprintf(b,
				      "{ \"order_id\": \"123\", \"id\": \"123\", \"symbol\": \"%s\", "
				      "\"exchange\": \"gemini\", \"avg_execution_price\": \"%s\""
				      ", \"side\": \"%s\", \"type\": \"exchange limit\", \"timestamp\": \"161"
				      "1872750\", \"timestampms\": 1611872750275, \"is_live\": false, \"i"
				      "s_cancelled\": false, \"is_hidden\": false, \"was_forced\": false"
				      ", \"executed_amount\": \"%s\", \"client_order_id\": \"%"PRId64"\", "
				      "\"options\": [ \"immediate-or-cancel\" ], \"price\": \"%s\", "
				      "\"original_amount\": \"%s\", \"remaining_amount\": \"0\" }\n",
				      exchg_pair_to_str(ev->data.ack.pair), price,
				      ev->data.ack.side == EXCHG_SIDE_BUY ? "buy" : "sell",
				      size, ev->data.ack.id, price, size);
		*dst = buf;
		return len;
	}
	if (p->auth->hmac_status == AUTH_BAD) {
		size_t len =  sprintf(buf, "{ \"result\": \"error\", \"reason\": \"InvalidSignature\","
				      "\"message\": \"InvalidSignature\" }");
		*dst = buf;
		return len;
	}
	size_t len = sprintf(buf, "{}");
	*dst = buf;
	return len;
}

static void place_order_add_header(struct http_req *req, const unsigned char *name,
				   const unsigned char *val, size_t len) {
	struct http_place_order *o = req->priv;

	auth_add_header(o->auth, name, val, len);
	if (strcmp((char *)name, "X-GEMINI-PAYLOAD:"))
		return;

	char problem[100];
	char *json = (char *)g_base64_decode((char *)val, &len);
	jsmn_init(&o->parser);
	int n = jsmn_parse(&o->parser, json, len, o->toks, ARRAY_SIZE(o->toks));
	if (n < 1) {
		sprintf(problem, "jsmn_parse(): %d", n);
		goto bad;
	}
	if (o->toks[0].type != JSMN_OBJECT) {
		sprintf(problem, "non-object json");
		goto bad;
	}

	o->ack.finished = true;
	o->ack.id = -1;
	bool got_price = false;
	bool got_size = false;
	bool got_pair = false;
	bool got_side = false;

	int key_idx = 1;
	for (int i = 0; i < o->toks[0].size; i++) {
		jsmntok_t *key = &o->toks[key_idx];
		jsmntok_t *val = key + 1;

		if (json_streq(json, key, "client_order_id")) {
			if (json_get_int64(&o->ack.id, json, val)) {
				sprintf(problem, "bad order id");
				goto bad;
			}
			key_idx += 2;
		} else if (json_streq(json, key, "symbol")) {
			if (json_get_pair(&o->ack.pair, json, val)) {
				sprintf(problem, "bad currency");
				goto bad;
			}
			got_pair = true;
			key_idx += 2;
		} else if (json_streq(json, key, "amount")) {
			if (json_get_decimal(&o->ack.size, json, val)) {
				sprintf(problem, "bad amount");
				goto bad;
			}
			got_size = true;
			key_idx += 2;
		} else if (json_streq(json, key, "price")) {
			if (json_get_decimal(&o->ack.price, json, val)) {
				sprintf(problem, "bad price");
				goto bad;
			}
			got_price = true;
			key_idx += 2;
		} else if (json_streq(json, key, "side")) {
			if (json_streq(json, val, "buy")) {
				o->ack.side = EXCHG_SIDE_BUY;
			} else if (json_streq(json, val, "sell")) {
				o->ack.side = EXCHG_SIDE_SELL;
			} else {
				sprintf(problem, "bad side");
				goto bad;
			}
			got_side = true;
			key_idx += 2;
		} else {
			key_idx = json_skip(n, o->toks, key_idx+1);
		}
	}
	if (o->ack.id == -1) {
		sprintf(problem, "no client_order_id given");
		goto bad;
	}
	if (!got_pair) {
		sprintf(problem, "no pair given");
		goto bad;
	}
	if (!got_size) {
		sprintf(problem, "no amount given");
		goto bad;
	}
	if (!got_price) {
		sprintf(problem, "no price given");
		goto bad;
	}
	if (!got_side) {
		sprintf(problem, "no side given");
		goto bad;
	}
	g_free(json);
	return;

bad:
	fprintf(stderr, "%s: %s\n", __func__, problem);
	g_free(json);
}

static void place_order_free(struct http_req *req) {
	struct http_place_order *o = req->priv;
	auth_check_free(o->auth);
	free(o);
	fake_http_req_free(req);
}

static void place_order_fill_event(struct http_req *req, struct exchg_test_event *ev) {
	struct http_place_order *o = req->priv;
	ev->type = EXCHG_EVENT_ORDER_ACK;
	ev->data.ack = o->ack;
}

static struct http_req *place_order_dial(struct exchg_net_context *ctx,
					 const char *path, const char *method,
					 void *private) {
	if (strcmp(method, "POST")) {
		fprintf(stderr, "Gemini bad method for %s: %s\n", path, method);
		return NULL;
	}

	struct http_req *req = fake_http_req_alloc(ctx, private);
	req->read = place_order_read;
	req->fill_event = place_order_fill_event;
	req->add_header = place_order_add_header;
	req->write = no_http_write;
	req->destroy = place_order_free;

	struct http_place_order *o = xzalloc(sizeof(*o));
	o->auth = auth_check_alloc(strlen(exchg_test_gemini_public),
				   (unsigned char *)exchg_test_gemini_public,
				   strlen(exchg_test_gemini_private),
				   (unsigned char *)exchg_test_gemini_private,
				   1, HEX_LOWER, EVP_sha384());
	req->priv = o;
	return req;
}

struct http_req *gemini_http_dial(struct exchg_net_context *ctx,
				  const char *path, const char *method,
				  void *private) {
	if (!strcmp(path, "/v1/balances"))
		return balances_dial(ctx, path, method, private);
	if (!strcmp(path, "/v1/order/new"))
		return place_order_dial(ctx, path, method, private);
	fprintf(stderr, "Gemini bad path: %s\n", path);
	return NULL;

}
