// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "auth.h"
#include "client.h"
#include "net-backend.h"

#include "util.h"
#include "fake-net.h"
#include "fake-bitstamp.h"
#include "fake-gemini.h"
#include "fake-kraken.h"
#include "fake-coinbase.h"

#ifndef TAILQ_FOREACH_SAFE
#define	TAILQ_FOREACH_SAFE(var, head, field, tmp)		\
	for ((var) = ((head)->tqh_first);			\
	     (var) && ((tmp) = (var)->field.tqe_next, 1);	\
	     (var) = (tmp))
#endif

static int buf_init(struct buf *buf, size_t size) {
	buf->buf = malloc(size);
	if (!buf->buf) {
		fprintf(stderr, "%s: OOM\n", __func__);
		return -1;
	}
	buf->size = size;
	buf->len = 0;
	return 0;
}

static int buf_vsprintf(struct buf *buf, const char *fmt, va_list ap) {
	int len;
	va_list a;

	va_copy(a, ap);
	while ((len = vsnprintf(&buf->buf[buf->len],
				buf->size - buf->len, fmt, ap)) >=
	       buf->size - buf->len) {
		int sz = 2*(buf->len + len + 1);
		char *b = realloc(buf->buf, sz);
		if (!b) {
			fprintf(stderr, "%s: OOM\n", __func__);
			return -1;
		}
		buf->buf = b;
		buf->size = sz;
		va_copy(ap, a);
		va_copy(a, ap);
	}
	buf->len += len;
	return len;
}

int buf_xsprintf(struct buf *buf, const char *fmt, ...) {
	va_list ap;

	va_start(ap, fmt);
	int ret = buf_vsprintf(buf, fmt, ap);
	if (ret < 0)
		exit(1);
	va_end(ap);

	return ret;
}

void buf_xcpy(struct buf *buf, void *src, size_t len) {
	if (buf->size < len + buf->len) {
		int sz = 2 * (len + buf->len);
		char *b = realloc(buf->buf, sz);
		if (!b) {
			fprintf(stderr, "%s: OOM\n", __func__);
			exit(1);
		}
		buf->buf = b;
		buf->size = sz;
	}
	memcpy(&buf->buf[buf->len], src, len);
	buf->len += len;
}

int http_vsprintf(struct http_req *req, const char *fmt, va_list ap) {
	if (!req->body.buf && buf_init(&req->body, 200))
		return -1;

	return buf_vsprintf(&req->body, fmt, ap);
}

char *http_body(struct http_req *req) {
	return req->body.buf;
}

static int ws_matches(struct websocket *ws, struct exchg_test_event *ev) {
	return ev->type == EXCHG_EVENT_BOOK_UPDATE &&
		ws->established && ws->id == ev->id &&
		ws->matches(ws, ev->data.book.pair);
}

void exchg_test_set_callback(struct exchg_net_context *ctx,
			     exchg_test_callback_t cb,
			     void *private) {
	ctx->callback = cb;
	ctx->cb_private = private;
}

void exchg_test_event_print(struct exchg_test_event *ev) {
	const char *type;

	switch (ev->type) {
	case EXCHG_EVENT_HTTP_PREP:
		type = "HTTP_PREP";
		break;
	case EXCHG_EVENT_WS_PREP:
		type = "WS_PREP";
		break;
	case EXCHG_EVENT_BOOK_UPDATE:
		type = "BOOK_UPDATE";
		break;
	case EXCHG_EVENT_ORDER_ACK:
		type = "ORDER_ACK";
		break;
	case EXCHG_EVENT_PAIRS_DATA:
		type = "PAIRS_DATA";
		break;
	case EXCHG_EVENT_BALANCES:
		type = "BALANCES";
		break;
	case EXCHG_EVENT_WS_PROTOCOL:
		type = "WS_PROTOCOL";
		break;
	case EXCHG_EVENT_HTTP_PROTOCOL:
		type = "HTTP_PROTOCOL";
		break;
	case EXCHG_EVENT_WS_CLOSE:
		type = "WS_CLOSE";
		break;
	case EXCHG_EVENT_HTTP_CLOSE:
		type = "HTTP_CLOSE";
		break;
	default:
		type = "<Unknown Type : Internal Error>";
		break;
	}

	printf("event: %s %s\n", exchg_id_to_name(ev->id), type);
}

static void set_matching_ws(struct exchg_net_context *ctx,
			    struct test_event *ev) {
	struct websocket *ws;
	LIST_FOREACH(ws, &ctx->ws_list, list) {
		if (ws_matches(ws, &ev->event)) {
			ev->conn.ws = ws;
			break;
		}
	}
}

struct exchg_net_context *exchg_test_net_ctx(struct exchg_context *ctx) {
	return ctx->net_context;
}

void exchg_test_add_events(struct exchg_net_context *ctx,
			   int n, struct exchg_test_event *events) {
	for (int i = 0; i < n; i++) {
		if (events[i].type != EXCHG_EVENT_BOOK_UPDATE) {
			fprintf(stderr, "only can add book updtes for now\n");
			continue;
		}
		struct test_event *e = xzalloc(sizeof(*e));
		memcpy(&e->event, &events[i], sizeof(events[i]));
		e->conn_type = CONN_TYPE_WS;
		set_matching_ws(ctx, e);
		TAILQ_INSERT_TAIL(&ctx->events, e, list);
	}
}

int exchg_test_l2_queue_order(struct exchg_test_l2_updates *u,
			      bool is_bid, decimal_t *price, decimal_t *size) {
	if (is_bid) {
		if (u->num_bids >= u->bid_cap) {
			int new_cap = u->bid_cap * 2 + 1;
			struct exchg_test_l2_update *bids = realloc(u->bids, sizeof(*u->bids) * new_cap);
			if (!bids) {
				exchg_log("%s: OOM\n", __func__);
				return -1;
			}
			u->bids = bids;
			u->bid_cap = new_cap;
		}
		u->bids[u->num_bids].price = *price;
		u->bids[u->num_bids].size = *size;
		u->num_bids++;
	} else {
		if (u->num_asks >= u->ask_cap) {
			int new_cap = u->ask_cap * 2 + 1;
			struct exchg_test_l2_update *asks = realloc(u->asks, sizeof(*u->asks) * new_cap);
			if (!asks) {
				exchg_log("%s: OOM\n", __func__);
				return -1;
			}
			u->asks = asks;
			u->ask_cap = new_cap;
		}
		u->asks[u->num_asks].price = *price;
		u->asks[u->num_asks].size = *size;
		u->num_asks++;
	}
	return 0;
}

void exchg_test_add_l2_events(struct exchg_net_context *ctx,
			      int n, struct exchg_test_str_l2_updates *msgs) {
	for (int i = 0; i < n; i++) {
		struct exchg_test_str_l2_updates *o = &msgs[i];
		struct test_event *event = xzalloc(sizeof(*event));
		struct exchg_test_event *e = &event->event;

		event->conn_type = CONN_TYPE_WS;
		e->id = o->id;
		e->type = EXCHG_EVENT_BOOK_UPDATE;
		e->data.book.pair = o->pair;

		for (struct exchg_test_str_l2_update *s = &o->bids[0];
		     s->price; s++) {
			decimal_t price, size;
			decimal_from_str(&price, s->price);
			decimal_from_str(&size, s->size);
			if (exchg_test_l2_queue_order(&e->data.book, true, &price, &size)) {
				exchg_log("%s: OOM\n", __func__);
				return;
			}
		}
		for (struct exchg_test_str_l2_update *s = &o->asks[0];
		     s->price; s++) {
			decimal_t price, size;
			decimal_from_str(&price, s->price);
			decimal_from_str(&size, s->size);
			if (exchg_test_l2_queue_order(&e->data.book, false, &price, &size)) {
				exchg_log("%s: OOM\n", __func__);
				return;
			}
		}
		set_matching_ws(ctx, event);
		TAILQ_INSERT_TAIL(&ctx->events, event, list);
	}
}

void *test_event_private(struct exchg_test_event *event) {
	struct test_event *container = (struct test_event *)((void *)event -
							     (void *)&((struct test_event *)NULL)->event);
	return container->private;
}

struct exchg_test_event *exchg_fake_queue_ws_event(
	struct websocket *w, enum exchg_test_event_type type, size_t private_size) {
	struct test_event *event = xzalloc(sizeof(*event) + private_size);
	struct exchg_test_event *e = &event->event;

	event->conn_type = CONN_TYPE_WS;
	event->conn.ws = w;
	e->id = w->id;
	e->type = type;

	struct test_event *last = NULL, *tmp;
	TAILQ_FOREACH(tmp, &w->ctx->events, list) {
		if (tmp->event.type == EXCHG_EVENT_WS_PROTOCOL &&
		    tmp->conn.ws == w)
			last = tmp;
	}
	if (last)
		TAILQ_INSERT_AFTER(&w->ctx->events, last, event, list);
	else
		TAILQ_INSERT_HEAD(&w->ctx->events, event, list);
	return e;
}

struct exchg_net_context *net_new(struct net_callbacks *c) {
	struct exchg_net_context *ctx = xzalloc(sizeof(*ctx));
	TAILQ_INIT(&ctx->events);
	LIST_INIT(&ctx->ws_list);
	ctx->callbacks = c;
	return ctx;
}

struct exchg_context *exchg_test_new(struct exchg_callbacks *c,
				     const struct exchg_options *opts, void *user) {
	return exchg_new(c, opts, user);
}

static void free_event(struct exchg_net_context *ctx, struct test_event *ev) {
	TAILQ_REMOVE(&ctx->events, ev, list);
	if (ev->event.type == EXCHG_EVENT_BOOK_UPDATE) {
		free(ev->event.data.book.bids);
		free(ev->event.data.book.asks);
	}
	free(ev);
}

int net_service(struct exchg_net_context *ctx) {
	int ret;
	struct buf buf;
	struct test_event *ev, *e, *tmp;
	struct exchg_test_event *event = NULL;
	struct websocket_callbacks *ws = &ctx->callbacks->ws;
	struct http_callbacks *http = &ctx->callbacks->http;
	struct http_req *http_req;
	struct websocket *wsock;

	ev = TAILQ_FIRST(&ctx->events);
	if (ev)
		event = &ev->event;

	if (ctx->callback)
		ctx->callback(ctx, event, ctx->cb_private);

	ev = TAILQ_FIRST(&ctx->events);
	if (!ev) {
		fprintf(stderr, "%s called with no events left to process\n",
			__func__);
		return -1;
	}
	event = &ev->event;

	switch (ev->conn_type) {
	case CONN_TYPE_WS:
		wsock = ev->conn.ws;
		if (!wsock) {
			set_matching_ws(ctx, ev);
			wsock = ev->conn.ws;
		}
		if (!wsock) {
			fprintf(stderr, "event with no matching websocket:\n"
				"%s %d\n", exchg_id_to_name(event->id), event->type);
			break;
		}
		switch (event->type) {
		case EXCHG_EVENT_WS_PREP:
			ws->on_established(wsock->user);
			wsock->established = true;
			TAILQ_FOREACH(e, &ctx->events, list) {
				if (e != ev && ws_matches(wsock, &e->event))
					e->conn.ws = wsock;
			}
			break;
		case EXCHG_EVENT_WS_CLOSE:
			TAILQ_FOREACH_SAFE(e, &ctx->events, list, tmp) {
				if (e != ev && e->conn_type == CONN_TYPE_WS &&
				    e->conn.ws == ev->conn.ws) {
					free_event(ctx, e);
				}
			}
			ws->on_closed(wsock->user);
			wsock->destroy(wsock);
			break;
		default:
			if (buf_init(&buf, 1<<10))
				return -1;
			wsock->read(wsock, &buf, event);
			ws->recv(wsock->user, buf.buf, buf.len);
			free(buf.buf);
			break;
		}
		break;
	case CONN_TYPE_HTTP:
		http_req = ev->conn.http;
		switch (event->type) {
		case EXCHG_EVENT_HTTP_PREP:
			ret = http->add_headers(http_req->user, http_req);
			// TODO: if (ret) close(req);
			if (!ret)
				http_req->write(http_req);
			if (!ret)
				http->on_established(http_req->user,
						     http_req->status);
			// callback to fill in here
			break;
		case EXCHG_EVENT_HTTP_CLOSE:
			TAILQ_FOREACH_SAFE(e, &ctx->events, list, tmp) {
				if (e != ev && e->conn_type == CONN_TYPE_HTTP &&
				    e->conn.http == ev->conn.http) {
					free_event(ctx, e);
				}
			}
			http->on_closed(http_req->user);
			http_req->destroy(http_req);
			break;
		default:
			if (buf_init(&buf, 1<<10))
				return -1;
			http_req->read(http_req, event, &buf);
			http->recv(http_req->user, buf.buf, buf.len);
			free(buf.buf);
			http_close(http_req);
			http_req->read_event = NULL;
			break;
		}
		break;
	}
	free_event(ctx, ev);
	return 0;
}

void net_destroy(struct exchg_net_context *ctx) {
	struct test_event *e, *tmp;
	TAILQ_FOREACH_SAFE(e, &ctx->events, list, tmp) {
		free_event(ctx, e);
	}
	free(ctx);
}

void no_ws_write(struct websocket *w, char *buf, size_t len) {}

void no_http_add_header(struct http_req *req, const unsigned char *name,
			const unsigned char *val, size_t len) {}

void no_http_write(struct http_req *req) {}

int http_add_header(struct http_req *req, const unsigned char *name,
		    const unsigned char *val, size_t len) {
	req->add_header(req, name, val, len);
	return 0;
}

void fake_http_req_free(struct http_req *req) {
	free(req->body.buf);
	free(req);
}

struct http_req *fake_http_req_alloc(struct exchg_net_context *ctx, enum exchg_id exchange,
				     enum exchg_test_event_type type, void *private) {
	struct http_req *req = xzalloc(sizeof(*req));
	struct test_event *prep_event = xzalloc(sizeof(*prep_event));
	struct test_event *read_event = xzalloc(sizeof(*read_event));
	struct exchg_test_event *prep_ev = &prep_event->event;;
	struct exchg_test_event *read_ev = &read_event->event;;

	read_event->conn_type = CONN_TYPE_HTTP;
	read_event->conn.http = req;
	read_ev->id = exchange;
	read_ev->type = type;
	TAILQ_INSERT_HEAD(&ctx->events, read_event, list);

	prep_event->conn_type = CONN_TYPE_HTTP;
	prep_event->conn.http = req;
	prep_ev->id = exchange;
	prep_ev->type = EXCHG_EVENT_HTTP_PREP;
	TAILQ_INSERT_HEAD(&ctx->events, prep_event, list);

	req->id = exchange;
	req->status = 200;
	req->user = private;
	req->ctx = ctx;
	req->read_event = read_ev;
	return req;
}

struct http_req *http_dial(struct exchg_net_context *ctx,
			   const char *host, const char *path,
			   const char *method, void *private) {
	struct http_req *http;

	if (!strcmp(host, "api.gemini.com")) {
		http = gemini_http_dial(ctx, path, method, private);
	} else if (!strcmp(host, "api.kraken.com")) {
		http = kraken_http_dial(ctx, path, method, private);
	} else if (!strcmp(host, "bitstamp.net") ||
		   !strcmp(host, "www.bitstamp.net")) {
		http = bitstamp_http_dial(ctx, path, method, private);
	} else if (!strcmp(host, "api.pro.coinbase.com")) {
		http = coinbase_http_dial(ctx, path, method, private);
	} else {
		fprintf(stderr,
			"client attempted to contact unknown host: %s\n", host);
		return NULL;
	}

	if (!http)
		return NULL;

	return http;
}

int http_status(struct http_req *req) {
	return req->status;
}

void http_close(struct http_req *http) {
	struct test_event *event;
	struct exchg_test_event *ev;

	TAILQ_FOREACH(event, &http->ctx->events, list) {
		if (event->event.type == EXCHG_EVENT_HTTP_CLOSE &&
		    event->conn.http == http)
			return;
	}

	event = xzalloc(sizeof(*event));
	event->conn_type = CONN_TYPE_HTTP;
	event->conn.http = http;
	ev = &event->event;
	ev->id = http->id;
	ev->type = EXCHG_EVENT_HTTP_CLOSE;
	TAILQ_INSERT_HEAD(&http->ctx->events, event, list);
}

int ws_vprintf(struct websocket *ws, const char *fmt, va_list ap) {
	va_list a;
	va_copy(a, ap);
	char buf[1024];
	size_t len = vsnprintf(buf, sizeof(buf), fmt, ap);

	if (len < sizeof(buf)) {
		ws->write(ws, buf, len);
		return len;
	} else {
		struct buf b;

		if (buf_init(&b, len+1))
			return -1;
		len = buf_vsprintf(&b, fmt, a);
		if (len < 0) {
			free(b.buf);
			return len;
		}
		ws->write(ws, b.buf, len);
		free(b.buf);
		return len;
	}
}

void ws_close(struct websocket *ws) {
	struct test_event *event;
	struct exchg_test_event *ev;

	TAILQ_FOREACH(event, &ws->ctx->events, list) {
		if (event->event.type == EXCHG_EVENT_WS_CLOSE &&
		    event->conn.ws == ws)
			return;
	}

	event = xzalloc(sizeof(*event));
	event->conn_type = CONN_TYPE_WS;
	event->conn.ws = ws;
	ev = &event->event;
	ev->type = EXCHG_EVENT_WS_CLOSE;
	ev->id = ws->id;
	TAILQ_INSERT_HEAD(&ws->ctx->events, event, list);
}

struct websocket *fake_websocket_alloc(struct exchg_net_context *ctx, void *user) {
	struct websocket *s = xzalloc(sizeof(*s));
	s->user = user;
	s->ctx = ctx;
	LIST_INSERT_HEAD(&ctx->ws_list, s, list);
	return s;
}

struct websocket *ws_dial(struct exchg_net_context *ctx, const char *host,
			  const char *path, void *private) {
	struct websocket *ws;
	enum exchg_id exchange;

	if (!strcmp(host, "api.gemini.com")) {
		exchange = EXCHG_GEMINI;
		ws =  gemini_ws_dial(ctx, path, private);
	} else if (!strcmp(host, "ws.kraken.com")) {
		exchange = EXCHG_KRAKEN;
		ws = kraken_ws_dial(ctx, path, private);
	} else if (!strcmp(host, "ws-auth.kraken.com")) {
		exchange = EXCHG_KRAKEN;
		ws = kraken_ws_auth_dial(ctx, path, private);
	} else if (!strcmp(host, "ws.bitstamp.net")) {
		exchange = EXCHG_BITSTAMP;
		ws = bitstamp_ws_dial(ctx, path, private);
	} else if (!strcmp(host, "ws-feed.pro.coinbase.com")) {
		exchange = EXCHG_COINBASE;
		ws = coinbase_ws_dial(ctx, path, private);
	} else {
		fprintf(stderr,
			"client attempted to contact unknown websocket host: %s\n",
			host);
		return NULL;
	}

	struct test_event *event = xzalloc(sizeof(*event));
	struct exchg_test_event *ev = &event->event;
	event->conn_type = CONN_TYPE_WS;
	event->conn.ws = ws;
	ev->id = exchange;
	ev->type = EXCHG_EVENT_WS_PREP;
	TAILQ_INSERT_HEAD(&ctx->events, event, list);
	return ws;
}

decimal_t *exchg_test_balances(struct exchg_net_context *ctx, enum exchg_id id) {
	return ctx->balances[id];
}

struct auth_check *auth_check_alloc(size_t public_len, const unsigned char *public,
				    size_t private_len, const unsigned char *private,
				    int hmac_hex, enum hex_type type, const EVP_MD *md) {
	struct auth_check *a = xzalloc(sizeof(*a));
	a->public_len = public_len;
	a->private_len = private_len;
	a->public = xzalloc(public_len);
	a->private = xzalloc(private_len);
	memcpy(a->public, public, public_len);
	memcpy(a->private, private, private_len);

	a->hmac_ctx = HMAC_CTX_new();
	if (!a->hmac_ctx) {
		fprintf(stderr, "%s: OOM\n", __func__);
		exit(1);
	}
	if (!HMAC_Init_ex(a->hmac_ctx, private, private_len, md, NULL)) {
		fprintf(stderr, "%s: HMAC_Init_ex() failure\n", __func__);
		exit(1);
	}
	a->hmac_hex = hmac_hex;
	a->hex_type = type;
	a->apikey_status = AUTH_UNSET;
	a->hmac_status = AUTH_UNSET;
	return a;
}

void auth_check_free(struct auth_check *a) {
	free(a->hmac);
	free(a->payload);
	free(a->public);
	free(a->private);
	HMAC_CTX_free(a->hmac_ctx);
	free(a);
}

static void hmac_verify(struct auth_check *a) {
	if (a->apikey_status != AUTH_GOOD || !a->payload || !a->hmac)
		return;

	char hmac[HMAC_TEXT_LEN_MAX];
	int hmac_len;
	if (a->hmac_hex)
		hmac_len = hmac_hex(a->hmac_ctx, a->payload,
				    a->payload_len, hmac, a->hex_type);
	else
		hmac_len = hmac_b64(a->hmac_ctx, a->payload,
				    a->payload_len, hmac);

	if (hmac_len != a->hmac_len || memcmp(hmac, a->hmac, hmac_len)) {
		a->hmac_status = AUTH_BAD;
		return;
	}
	a->hmac_status = AUTH_GOOD;
}

void auth_check_set_public(struct auth_check *a, const unsigned char *c, size_t len) {
	if (len != a->public_len ||
	    memcmp(c, a->public, a->public_len))
		a->apikey_status = AUTH_BAD;
	else
		a->apikey_status = AUTH_GOOD;
	hmac_verify(a);
}

void auth_check_set_payload(struct auth_check *a, const unsigned char *c, size_t len) {
	a->payload = xdupwithnull(c, len);
	a->payload_len = len;
	hmac_verify(a);
}

void auth_check_set_hmac(struct auth_check *a, const unsigned char *c, size_t len) {
	a->hmac = (char *)xdupwithnull(c, len);
	a->hmac_len = len;
	hmac_verify(a);
}
