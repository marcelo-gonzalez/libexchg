// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#include <glib.h>
#include <jsmn/jsmn.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <sys/queue.h>

#include "auth.h"
#include "compiler.h"
#include "exchg/currency.h"
#include "client.h"
#include "exchg/exchg.h"
#include "net-backend.h"
#include "order-book.h"
#include "time-helpers.h"

#include "exchanges/bitstamp.h"
#include "exchanges/coinbase.h"
#include "exchanges/gemini.h"
#include "exchanges/kraken.h"

// TODO split into two structs, http vs websocket
struct conn {
	enum conn_type type;
	char *method;
	char *host;
	char *path;
	bool established;
	bool disconnecting;
	struct timer *retry;
	struct timespec last_connected;
	int retry_seconds_idx;
	jsmn_parser parser;
	jsmntok_t *tokens;
	int num_tokens;
	char *buf;
	int buf_size;
	int buf_pos;
	struct exchg_client *cl;
	union {
		struct conn_ws {
			struct websocket_conn *conn;
			const struct exchg_websocket_ops *ops;
		} ws;
		struct conn_http {
			struct http_conn *req;
			const struct exchg_http_ops *ops;
			bool print_data;
		} http;
	};
	LIST_ENTRY(conn) list;
	void *request_private;
	char private[];
};

void *conn_request_private(struct conn *c) {
	return c->request_private;
}

bool conn_disconnecting(struct conn *c) {
	return c->disconnecting;
}

bool conn_established(struct conn *c) {
	if (!c)
		return false;
	return c->established;
}

const char *conn_method(struct conn *c) {
	return c->method;
}

const char *conn_host(struct conn *c) {
	return c->host;
}

const char *conn_path(struct conn *c) {
	return c->path;
}

static void conn_free(struct conn *conn) {
	if (!conn)
		return;
	free(conn->method);
	free(conn->host);
	free(conn->path);
	free(conn->buf);
	free(conn->tokens);
	free(conn);
}

void for_each_conn(struct exchg_client *cl,
		   int (*func)(struct conn *conn, void *private),
		   void *private) {
	struct conn *conn;
	LIST_FOREACH(conn, &cl->conn_list, list) {
		if (func(conn, private))
			return;
	}
}

int conn_printf(struct conn *conn, const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);

	int ret = ws_conn_vprintf(conn->ws.conn, fmt, ap);
	va_end(ap);
	return ret;
}

static void conn_offline(struct conn *conn) {
	struct exchg_context *ctx = conn->cl->ctx;

	LIST_REMOVE(conn, list);
	conn_free(conn);

	ctx->online = false;
	for (enum exchg_id id = 0; id < EXCHG_ALL_EXCHANGES; id++) {
		struct exchg_client *cl = ctx->clients[id];

		if (cl && !LIST_EMPTY(&cl->conn_list)) {
			ctx->online = true;
			return;
		}
	}
	if (ctx->running) {
		net_stop(ctx->net_context);
		ctx->running = false;
	}
}

void conn_close(struct conn *conn) {
	conn->disconnecting = true;
	if (conn->type == CONN_TYPE_WS) {
		if (conn->ws.conn) {
			ws_conn_close(conn->ws.conn);
		} else if (conn->retry) {
			timer_cancel(conn->retry);
			conn_offline(conn);
		}
		// else { we're inside the on_l2_disconnect() callback }
	} else
		http_conn_close(conn->http.req);
}

#ifndef LIST_FOREACH_SAFE
#define	LIST_FOREACH_SAFE(var, head, field, tmp)		\
	for ((var) = ((head)->lh_first);			\
	     (var) && ((tmp) = (var)->field.le_next, 1);	\
	     (var) = (tmp))
#endif

void exchg_teardown(struct exchg_client *cl) {
	// TODO: add a callback and call it here,
	// send order cancels, etc. Set a bit and
	// look at that bit in the main callback
	struct conn *conn, *tmp;
	LIST_FOREACH_SAFE(conn, &cl->conn_list, list, tmp)
		conn_close(conn);
}

static void put_response(char *in, size_t len) {
	fwrite(in, 1, len, stderr);
	fputc('\n', stderr);
}

static int conn_buf_add(struct conn *conn, char *in,
			size_t len) {
	if (len + conn->buf_pos > conn->buf_size) {
		size_t new_sz = 2 * (len+conn->buf_pos);
		char *buf = realloc(conn->buf, new_sz);
		if (!buf) {
			exchg_log("%s: OOM\n", __func__);
			return -1;
		}
		conn->buf = buf;
		conn->buf_size = new_sz;
	}
	memcpy(conn->buf + conn->buf_pos, in, len);
	conn->buf_pos += len;
	return 0;
}

static void conn_json_init(struct conn *conn) {
	jsmn_init(&conn->parser);
	conn->buf_pos = 0;
}

static int conn_parse_json(struct conn *conn, char *in,
			   size_t len, char **json) {
	char *data = in;
	size_t data_len = len;

	if (conn->buf_pos > 0) {
		if (conn_buf_add(conn, in, len))
			return -1;
		data = conn->buf;
		data_len = conn->buf_pos;
	}

	int numtoks;
	while ((numtoks = jsmn_parse(&conn->parser, data, data_len,
				     conn->tokens, conn->num_tokens)) == JSMN_ERROR_NOMEM) {
		int n = 2 * conn->num_tokens;
		jsmntok_t *toks = realloc(conn->tokens, n * sizeof(jsmntok_t));
		if (!toks) {
			exchg_log("%s: OOM\n", __func__);
			return -1;
		}
		conn->tokens = toks;
		conn->num_tokens = n;
	}

	if (numtoks == JSMN_ERROR_PART) {
		if (conn->buf_pos == 0)
			return conn_buf_add(conn, in, len);
		return 0;
	}
	if (unlikely(numtoks < 0)) {
		exchg_log("%s%s sent data that doesn't parse as JSON:\n",
			  conn->host, conn->path);
		put_response(data, data_len);
		return -1;
	}
	*json = data;
	conn_json_init(conn);
	return numtoks;
}

static void ws_on_error(void *p) {
	struct conn *conn = p;

	exchg_log("wss://%s%s error\n", conn->host, conn->path);
	conn->established = false;
	conn->disconnecting = true;
	if (conn->ws.ops->on_disconnect)
		conn->ws.ops->on_disconnect(conn->cl, conn, -1);
	conn_offline(conn);
}

static void ws_on_established(void *p) {
	struct conn *conn = p;

	exchg_log("wss://%s%s established\n", conn->host, conn->path);
	conn->established = true;
	conn_json_init(conn);
	if (conn->ws.ops->on_conn_established)
		conn->ws.ops->on_conn_established(conn->cl, conn);
}

static int ws_add_headers(void *p, struct websocket_conn *ws) {
	struct conn *conn = p;
	if (conn->ws.ops->add_headers)
		return conn->ws.ops->add_headers(conn->cl, conn);
	return 0;
}

static int ws_recv(void *p, char *in, size_t len) {
	struct conn *conn = p;
	char *json;
	int numtoks = conn_parse_json(conn, in, len, &json);

	if (numtoks < 0)
		return -1;
	if (numtoks == 0)
		return 0;

	// TODO: return code that says whether to try reconnecting or not
	if (conn->ws.ops->recv(conn->cl, conn, json,
			       numtoks, conn->tokens)) {
		conn->disconnecting = true;
		return -1;
	}
	return 0;
}

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*x))

static const int retry_seconds[] = {0, 1, 3, 10, 60, 300};

static void time_since(struct timespec *dst, const struct timespec *ts) {
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);

	time_t carry = now.tv_nsec < ts->tv_nsec ? 1 : 0;
	dst->tv_nsec = now.tv_nsec - ts->tv_nsec;
	if (carry)
		dst->tv_nsec += 1000000000;
	dst->tv_sec = now.tv_sec - ts->tv_sec - carry;
}

static inline void conn_next_retry_seconds(struct conn *conn) {
	int last_idx = ARRAY_SIZE(retry_seconds)-1;
	struct timespec since_last_connected;

	time_since(&since_last_connected, &conn->last_connected);
	if (since_last_connected.tv_sec > retry_seconds[last_idx])
		conn->retry_seconds_idx = 0;
	else if (conn->retry_seconds_idx < last_idx)
		conn->retry_seconds_idx++;
}

static inline int conn_retry_seconds(struct conn *conn) {
	if (conn->disconnecting)
		return -1;
	return retry_seconds[conn->retry_seconds_idx];
}

static void ws_reconnect(struct conn *conn);

static void reconnect_timer(void *p) {
	struct conn *conn = p;

	conn->retry = NULL;
	ws_reconnect(conn);
}

static void conn_add_retry_timer(struct conn *conn) {
	conn->retry = timer_new(conn->cl->ctx->net_context, reconnect_timer, conn,
				retry_seconds[conn->retry_seconds_idx]);
}

void exchg_data_disconnect(struct exchg_client *cl, struct conn *conn,
			   int num_pairs_gone, enum exchg_pair *pairs_gone)
{
	if (cl->ctx->callbacks.on_l2_disconnect)
		cl->ctx->callbacks.on_l2_disconnect(cl, conn_retry_seconds(conn),
						    num_pairs_gone, pairs_gone,
						    cl->ctx->user);
}

static void ws_reconnect(struct conn *conn) {
	do {
		clock_gettime(CLOCK_MONOTONIC, &conn->last_connected);
		conn->ws.conn = ws_dial(conn->cl->ctx->net_context, conn->host,
					conn->path, conn);
		if (conn->ws.conn)
			return;

		conn_next_retry_seconds(conn);
	} while (conn_retry_seconds(conn) == 0);

	conn_add_retry_timer(conn);
}

static void ws_on_closed(void *p) {
	struct conn *conn = p;

	conn_next_retry_seconds(conn);
	int reconnect_seconds = conn_retry_seconds(conn);

	conn->established = false;
	conn->ws.conn = NULL;
	if (conn->ws.ops->on_disconnect &&
	    conn->ws.ops->on_disconnect(conn->cl, conn, reconnect_seconds))
		conn->disconnecting = true;

	if (!conn->disconnecting) {
		if (reconnect_seconds == 0) {
			exchg_log("wss://%s%s closed. Reconnecting now\n",
				  conn->host, conn->path);
			ws_reconnect(conn);
		} else {
			exchg_log("wss://%s%s closed. Reconnecting in %d second%s\n",
				  conn->host, conn->path, reconnect_seconds,
				  reconnect_seconds > 1 ? "s" : "");
			conn_add_retry_timer(conn);
		}
	} else {
		conn_offline(conn);
	}
}

int conn_add_header(struct conn *conn, const unsigned char *name,
		    const unsigned char *val, size_t len) {
	if (conn->type == CONN_TYPE_HTTP)
		return http_conn_add_header(conn->http.req, name, val, len);
	else
		return ws_conn_add_header(conn->ws.conn, name, val, len);
}

static void http_on_error(void *p, const char *err) {
	struct conn *conn = p;
	conn->established = false;
	if (conn->http.ops->on_error)
		conn->http.ops->on_error(conn->cl, conn, err);
	conn_offline(conn);
}

static void http_on_established(void *p, int status) {
	struct conn *conn = p;

	if (status != 200)
		exchg_log("https://%s%s established (status %d)\n",
			  conn->host, conn->path, status);
	else
		exchg_log("https://%s%s established\n",
			  conn->host, conn->path);
	conn->established = true;
	conn_json_init(conn);
	if (conn->http.ops->on_established)
		conn->http.ops->on_established(conn->cl, conn, status);
}

static int http_add_headers(void *p, struct http_conn *req) {
	struct conn *conn = p;
	if (conn->http.ops->add_headers)
		return conn->http.ops->add_headers(conn->cl, conn);
	return 0;
}

int conn_http_body_sprintf(struct conn *conn, const char *fmt, ...) {
	va_list ap;
	int len;

	va_start(ap, fmt);
	len = http_conn_vsprintf(conn->http.req, fmt, ap);
	va_end(ap);
	return len;
}

char *conn_http_body(struct conn *conn) {
	return http_conn_body(conn->http.req);
}

size_t conn_http_body_len(struct conn *conn) {
	return http_conn_body_len(conn->http.req);
}

static int http_recv(void *p, char *in, size_t len) {
	struct conn *conn = p;
	char *json;
	int numtoks;

	if (unlikely(conn->http.print_data)) {
		put_response(in, len);
		return 0;
	}

	numtoks = conn_parse_json(conn, in, len, &json);
	if (numtoks < 0) {
		conn->http.print_data = true;
		return -1;
	}
	if (numtoks == 0)
		return 0;

	return conn->http.ops->recv(conn->cl, conn,
				    http_conn_status(conn->http.req),
				    json, numtoks, conn->tokens);
}

static void http_on_closed(void *p) {
	struct conn *conn = p;

	exchg_log("https://%s%s closed\n", conn->host, conn->path);
	conn->established = false;
	conn->disconnecting = true;
	if (conn->http.ops->on_closed)
		conn->http.ops->on_closed(conn->cl, conn);
	conn_offline(conn);
}

enum conn_type conn_type(struct conn *c) {
	return c->type;
}

static int conn_init(struct conn *conn, struct exchg_client *cl,
		     const char *method, const char *host, const char *path,
		     enum conn_type type, struct conn_http *http, struct conn_ws *ws) {
	if (type == CONN_TYPE_WS) {
		memset(conn, 0, sizeof(struct conn) + ws->ops->conn_data_size);
		memcpy(&conn->ws, ws, sizeof(*ws));
	} else {
		memset(conn, 0, sizeof(struct conn) + http->ops->conn_data_size);
		memcpy(&conn->http, http, sizeof(*http));
	}
	LIST_INSERT_HEAD(&cl->conn_list, conn, list);
	conn->cl = cl;
	conn->type = type;
	if (type == CONN_TYPE_HTTP) {
		conn->method = strdup(method);
		if (!conn->method) {
			exchg_log("%s: OOM\n", __func__);
			return -1;
		}
	}
	conn->host = strdup(host);
	if (!conn->host) {
		exchg_log("%s: OOM\n", __func__);
		return -1;
	}
	conn->path = strdup(path);
	if (!conn->path) {
		exchg_log("%s: OOM\n", __func__);
		return -1;
	}
	jsmn_init(&conn->parser);
	conn->tokens = malloc(sizeof(jsmntok_t) * 500);
	if (!conn->tokens) {
		exchg_log("%s: OOM\n", __func__);
		return -1;
	}
	conn->num_tokens = 500;
	clock_gettime(CLOCK_MONOTONIC, &conn->last_connected);
	return 0;
}

static struct conn *exchg_http_dial(const char *host, const char *path,
				    const struct exchg_http_ops *ops,
				    struct exchg_client *cl, const char *method) {
	struct conn *conn = malloc(sizeof(*conn) + ops->conn_data_size);
	if (!conn) {
		exchg_log("%s: OOM\n", __func__);
		return NULL;
	}
	struct http_conn *req = http_dial(cl->ctx->net_context, host,
					  path, method, conn);
	if (!req) {
		free(conn);
		return NULL;
	}
	struct conn_http h = {
		.ops = ops,
		.req = req,
	};
	if (conn_init(conn, cl, method, host, path, CONN_TYPE_HTTP, &h, NULL)) {
		// important to note that here, conn was at least
		// partially initialized by conn_init even though it
		// failed, so the eventual call to conn_free() will
		// not give nonsense. same goes for exchg_websocket_connect()
		http_conn_close(req);
		return NULL;
	}
	cl->ctx->online = true;
	return conn;
}

struct conn *exchg_http_get(const char *host, const char *path,
			    const struct exchg_http_ops *ops,
			    struct exchg_client *cl) {
	return exchg_http_dial(host, path, ops, cl, "GET");
}

struct conn *exchg_http_post(const char *host, const char *path,
			     const struct exchg_http_ops *ops,
			     struct exchg_client *cl) {
	return exchg_http_dial(host, path, ops, cl, "POST");
}

struct conn *exchg_http_delete(const char *host, const char *path,
			       const struct exchg_http_ops *ops,
			       struct exchg_client *cl) {
	return exchg_http_dial(host, path, ops, cl, "DELETE");
}

struct conn *exchg_websocket_connect(struct exchg_client *cl,
				     const char *host, const char *path,
				     const struct exchg_websocket_ops *ops) {
	struct conn *conn = malloc(sizeof(*conn) + ops->conn_data_size);
	if (!conn) {
		exchg_log("%s: OOM\n", __func__);
		return NULL;
	}
	struct websocket_conn *ws = ws_dial(cl->ctx->net_context, host, path, conn);
	if (!ws) {
		free(conn);
		return NULL;
	}

	struct conn_ws w = {
		.ops = ops,
		.conn = ws,
	};
	if (conn_init(conn, cl, NULL, host, path, CONN_TYPE_WS, NULL, &w)) {
		ws_conn_close(ws);
		return NULL;
	}
	cl->ctx->online = true;
	return conn;
}

int exchg_parse_info_on_established(struct exchg_client *cl,
				    struct conn *conn, int status) {
	if (status != 200)
		cl->get_info_error = -1;
	return 0;
}

void exchg_parse_info_on_error(struct exchg_client *cl, struct conn *conn,
			       const char *err) {
	cl->get_info_error = -1;
}

void exchg_parse_info_on_closed(struct exchg_client *cl, struct conn *conn) {
	cl->getting_info = false;
}

const struct exchg_pair_info *exchg_pair_info(struct exchg_client *cl,
					      enum exchg_pair pair) {
	if (!cl->pair_info_current)
		return NULL;
	return &cl->pair_info[pair];
}

int exchg_get_pair_info(struct exchg_client *cl) {
	// TODO: delete this part. If this is called again, maybe the
	// user really wants to fetch it again cus it thinks something
	// may have changed
	if (cl->pair_info_current)
		return 0;

	if (cl->get_info_error) {
		exchg_log("%s can't get pair info. Already failed once.",
			  cl->name);
		return -1;
	}

	if (!cl->getting_info) {
		cl->getting_info = true;
		return cl->get_pair_info(cl);
	}
	return 0;
}

bool exchg_pair_info_current(struct exchg_client *cl) {
	return cl->pair_info_current;
}

int exchg_get_balances(struct exchg_client *cl, void *req_private) {
	return cl->get_balances(cl, req_private);
}

void *conn_private(struct conn *c) {
	return c->private;
}

struct order_info *__exchg_new_order(struct exchg_client *cl, const struct exchg_order *order,
				     const struct exchg_place_order_opts *opts,
				     void *req_private, size_t private_size, int64_t id) {
	struct order_info *info = malloc(sizeof(*info) + private_size);
	if (!info) {
		exchg_log("%s: OOM\n", __func__);
		return NULL;
	}
	info->req_private = req_private;
	info->info.id = id;
	memcpy(&info->info.order, order, sizeof(*order));
	if (opts)
		memcpy(&info->info.opts, opts, sizeof(info->info.opts));
	else
		memset(&info->info.opts, 0, sizeof(info->info.opts));
	info->info.status = EXCHG_ORDER_UNSUBMITTED;
	info->info.cancelation_failed = false;
	memset(&info->info.filled_size, 0, sizeof(decimal_t));
	memset(&info->info.avg_price, 0, sizeof(decimal_t));
	info->info.err[0] = 0;
	g_hash_table_insert(cl->orders, &info->info.id, info);
	return info;
}

struct order_info *exchg_new_order(struct exchg_client *cl, const struct exchg_order *order,
				   const struct exchg_place_order_opts *opts, void *req_private,
				   size_t private_size) {
	// TODO: current_micros() is fine for now but a collision is not absolutely
	// out of the question. should fix that
	return __exchg_new_order(cl, order, opts, req_private,
				 private_size, current_micros());
}

struct order_info *exchg_order_lookup(struct exchg_client *cl, int64_t id) {
	return g_hash_table_lookup(cl->orders, &id);
}

void order_info_free(struct exchg_client *cl, struct order_info *info) {
	g_hash_table_remove(cl->orders, &info->info.id);
}

// We get order updates possibly on several channels.
// So only give an order update if it seems that the new
// message has more recent info than what was has been gotten so far
void exchg_order_update(struct exchg_client *cl, struct order_info *oi,
			enum exchg_order_status new_status, const decimal_t *new_size, bool cancel_failed) {
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

	if (new_size && decimal_cmp(&info->filled_size, new_size) < 0) {
		update = true;
		info->filled_size = *new_size;
	}
	if (!info->cancelation_failed && cancel_failed) {
		update = true;
		info->cancelation_failed = true;
	}

	if (likely(update && cl->ctx->callbacks.on_order_update))
		cl->ctx->callbacks.on_order_update(cl, info, cl->ctx->user, oi->private);
	if (order_status_done(info->status))
		order_info_free(cl, oi);
}

int64_t exchg_place_order(struct exchg_client *cl, const struct exchg_order *order,
			  const struct exchg_place_order_opts *opts, void *priv) {
	if (unlikely(cl->ctx->opts.dry_run)) {
		const char *action;
		const char *atfor;
		char sz[30], px[30];

		decimal_to_str(sz, &order->size);
		decimal_to_str(px, &order->price);

		if (order->side == EXCHG_SIDE_BUY) {
			action = "buy";
			atfor = "for";
		} else {
			action = "sell";
			atfor = "at";
		}
		printf("%s %s %s %s %s %s\n", cl->name, action,
		       sz, exchg_pair_to_str(order->pair), atfor, px);
		return 0;
	}
	return cl->place_order(cl, order, opts, priv);
}

int exchg_cancel_order(struct exchg_client *cl, int64_t id) {
	if (unlikely(cl->ctx->opts.dry_run)) {
		// kind of tough, but what should dry run do? remember
		// the orders placed and remove them here? maybe not worth it...
		printf("CANCEL order\n");
		return 0;
	}

	struct order_info *info = exchg_order_lookup(cl, id);

	if (unlikely(!info)) {
		exchg_log("Can't cancel %s order %"PRId64". ID not recognized\n",
			  cl->name, id);
		return -1;
	}
	return cl->cancel_order(cl, info);
}

int exchg_realloc_order_bufs(struct exchg_client *cl, int n) {
	struct exchg_limit_order *bids, *asks;
	bids = realloc(cl->update.bids, n * sizeof(struct exchg_limit_order));
	if (!bids) {
		exchg_log("%s(%d): OOM\n", __func__, n);
		return -1;
	}
	cl->update.bids = bids;
	asks = realloc(cl->update.asks, n * sizeof(struct exchg_limit_order));
	if (!asks) {
		exchg_log("%s(%d): OOM\n", __func__, n);
		return -1;
	}
	cl->update.asks = asks;
	cl->l2_update_size = n;
	return 0;
}

enum exchg_id exchg_id(struct exchg_client *cl) {
	return cl->id;
}

const char *exchg_name(struct exchg_client *cl) {
	return cl->name;
}

struct exchg_client *alloc_exchg_client(struct exchg_context *ctx,
					enum exchg_id id, int l2_update_size, size_t private_size) {
	if (ctx->clients[id]) {
		exchg_log("%s client already allocated\n", exchg_id_to_name(id));
		return NULL;
	}
	struct exchg_client *ret = malloc(sizeof(*ret) + private_size);
	if (!ret) {
		fprintf(stderr, "%s OOM\n", __func__);
		return NULL;
	}
	memset(ret, 0, sizeof(*ret) + private_size);

	ret->hmac_ctx = HMAC_CTX_new();
	if (!ret->hmac_ctx) {
		exchg_log("OOM\n");
		free(ret);
		return NULL;
	}
	ret->id = id;
	ret->ctx = ctx;
	// TODO: only really need this many for the first update. Should shrink the buffers after that.
	ret->l2_update_size = l2_update_size;
	ret->update.exchange_id = id;
	ret->update.bids = malloc(l2_update_size * sizeof(struct exchg_limit_order));
	ret->update.asks = malloc(l2_update_size * sizeof(struct exchg_limit_order));
	if (!ret->update.bids || !ret->update.asks) {
		exchg_log("%s: OOM\n", __func__);
		free(ret->update.bids);
		free(ret->update.asks);
		HMAC_CTX_free(ret->hmac_ctx);
		free(ret);
		return NULL;
	}
	ret->orders = g_hash_table_new_full(g_int64_hash, g_int64_equal,
					    NULL, free);
	LIST_INIT(&ret->conn_list);
	LIST_INIT(&ret->work);
	ctx->clients[id] = ret;
	return ret;
}

void free_exchg_client(struct exchg_client *cl) {
	struct work *w, *tmp_w;
	struct conn *c, *tmp_c;

	cl->ctx->clients[cl->id] = NULL;
	HMAC_CTX_free(cl->hmac_ctx);
	LIST_FOREACH_SAFE(c, &cl->conn_list, list, tmp_c) {
		LIST_REMOVE(c, list);
		conn_free(c);
	}
	LIST_FOREACH_SAFE(w, &cl->work, list, tmp_w) {
		LIST_REMOVE(w, list);
		free(w);
	}
	free(cl->apikey_public);
	OPENSSL_cleanse(cl->password, cl->password_len);
	free(cl->password);
	free(cl->update.bids);
	free(cl->update.asks);
	free(cl);
}

int exchg_num_bids(struct exchg_context *ctx, enum exchg_pair pair) {
	struct order_book *book = ctx->books[pair];
	if (!book)
		return 0;
	return order_book_num_bids(book);
}

int exchg_num_asks(struct exchg_context *ctx, enum exchg_pair pair) {
	struct order_book *book = ctx->books[pair];
	if (!book)
		return 0;
	return order_book_num_offers(book);
}

void exchg_foreach_bid(struct exchg_context *ctx,
		       enum exchg_pair pair,
		       int (*f)(const struct exchg_limit_order *o, void *user),
		       void *user) {
	struct order_book *book = ctx->books[pair];
	if (book)
		order_book_foreach_bid(book, f, user);
}

void exchg_foreach_ask(struct exchg_context *ctx, enum exchg_pair pair,
		       int (*f)(const struct exchg_limit_order *o, void *user),
		       void *user) {
	struct order_book *book = ctx->books[pair];
	if (book)
		order_book_foreach_offer(book, f, user);
}

bool exchg_best_bid(struct exchg_limit_order *dst, struct exchg_context *ctx,
		    enum exchg_id id, enum exchg_pair pair) {
	struct order_book *book = ctx->books[pair];
	if (book) {
		return order_book_best_bid(dst, book, id);
	} else {
		return false;
	}
}

bool exchg_best_ask(struct exchg_limit_order *dst,struct exchg_context *ctx,
		    enum exchg_id id, enum exchg_pair pair) {
	struct order_book *book = ctx->books[pair];
	if (book) {
		return order_book_best_ask(dst, book, id);
	} else {
		return false;
	}
}

static int alloc_book(struct exchg_context *ctx, enum exchg_pair pair) {
	if (!ctx->opts.track_book || ctx->books[pair])
		return 0;

	int max_depth[EXCHG_ALL_EXCHANGES];
	memset(max_depth, 0, sizeof(max_depth));
	max_depth[EXCHG_KRAKEN] = 1000;
	ctx->books[pair] = order_book_new(max_depth, ctx->opts.sort_by_nominal_price);
	if (!ctx->books[pair])
		return ENOMEM;
	return 0;
}

static int call_per_exchange(struct exchg_context *ctx, const char *caller,
			     int (*f)(struct exchg_client *, void *), enum exchg_id id, void *p) {
	if (0 <= id && id < EXCHG_ALL_EXCHANGES) {
		if (!ctx->clients[id]) {
			const char *name = exchg_id_to_name(id);
			exchg_log("%s called with id == %s, but %s "
				  "client not allocated\n",
				  caller, name, name);
			return -1;
		}
		return f(ctx->clients[id], p);
	}
	if (id == EXCHG_ALL_EXCHANGES) {
		int ret = 0;
		bool did_something = false;
		for (enum exchg_id id = 0; id < EXCHG_ALL_EXCHANGES; id++) {
			struct exchg_client *cl = ctx->clients[id];
			if (cl) {
				ret |= f(cl, p);
				did_something = true;
			}
		}
		if (!did_something) {
			exchg_log("%s called with no clients allocated\n", caller);
			return -1;
		}
		return ret ? -1 : 0;
	}
	exchg_log("%s: bad exchgange id given: %d\n", caller, id);
	return -1;
}

static int priv_ws_connect(struct exchg_client *cl, void *p) {
	return cl->priv_ws_connect(cl);
}

int exchg_private_ws_connect(struct exchg_context *ctx, enum exchg_id id) {
	return call_per_exchange(ctx, __func__, priv_ws_connect, id, NULL);
}

bool exchg_private_ws_online(struct exchg_client *cl) {
	return cl->priv_ws_online(cl);
}

static int l2_subscribe(struct exchg_client *cl, void *p) {
	enum exchg_pair pair = (enum exchg_pair)p;
	struct exchg_pair_info *pi = &cl->pair_info[pair];
	// TODO: free if ends up unused cus its not available
	int err = alloc_book(cl->ctx, pair);
	if (err)
		return err;
	err = exchg_get_pair_info(cl);
	if (err)
		return err;
	if (cl->get_info_error) {
		exchg_log("%s: Can't subscribe to L2 book data "
			  "due to error getting pair info\n", cl->name);
		return -1;
	}
	if (cl->pair_info_current && !pi->available) {
		exchg_log("pair %s not available on %s\n",
			  exchg_pair_to_str(pair), cl->name);
		return -1;
	}
	return cl->l2_subscribe(cl, pair);
}

int exchg_l2_subscribe(struct exchg_context *ctx, enum exchg_id id,
		       enum exchg_pair pair) {
	return call_per_exchange(ctx, __func__, l2_subscribe, id, (void *)pair);
}

static struct net_callbacks net_callbacks = {
	{
		.on_error = http_on_error,
		.on_established = http_on_established,
		.add_headers = http_add_headers,
		.recv = http_recv,
		.on_closed = http_on_closed,
	},
	{
		.on_error = ws_on_error,
		.on_established = ws_on_established,
		.add_headers = ws_add_headers,
		.recv = ws_recv,
		.on_closed = ws_on_closed,
	},
};

struct exchg_context *exchg_ctx(struct exchg_client *cl) {
	return cl->ctx;
}

struct exchg_client *exchg_alloc_client(struct exchg_context *ctx, enum exchg_id id) {
	switch (id) {
	case EXCHG_BITSTAMP:
		return alloc_bitstamp_client(ctx);
	case EXCHG_GEMINI:
		return alloc_gemini_client(ctx);
	case EXCHG_KRAKEN:
		return alloc_kraken_client(ctx);
	case EXCHG_COINBASE:
		return alloc_coinbase_client(ctx);
	default:
		exchg_log("%s: bad exchange id: %d\n", __func__, id);
		return NULL;
	}
}

struct exchg_context *exchg_new(struct exchg_callbacks *callbacks,
				const struct exchg_options *opts, void *user) {
	struct exchg_context *ctx = malloc(sizeof(*ctx));
	if (!ctx) {
		exchg_log("%s OOM\n", __func__);
		return NULL;
	}
	memset(ctx, 0, sizeof(*ctx));
	if (callbacks)
		memcpy(&ctx->callbacks, callbacks, sizeof(ctx->callbacks));
	if (opts)
		memcpy(&ctx->opts, opts, sizeof(*opts));
	ctx->user = user;
	ctx->net_context = net_new(&net_callbacks);
	if (!ctx->net_context) {
		free(ctx);
		return NULL;
	}
	return ctx;
}

void exchg_free(struct exchg_context *ctx) {
	if (!ctx)
		return;
	net_destroy(ctx->net_context);
	for (int i = 0; i < EXCHG_ALL_EXCHANGES; i++) {
		struct exchg_client *cl = ctx->clients[i];
		if (!cl)
			continue;
		cl->destroy(cl);
	}
	for (enum exchg_pair pair = 0; pair < EXCHG_NUM_PAIRS; pair++)
		order_book_free(ctx->books[pair]);
	free(ctx);
}

bool exchg_service(struct exchg_context *ctx) {
	if (unlikely(!ctx->online))
		return false;
	net_service(ctx->net_context);
	return true;
}

void exchg_run(struct exchg_context *ctx) {
	if (ctx->running) {
		exchg_log("%s called recursively. This is an error.\n", __func__);
		return;
	}
	if (!ctx->online)
		return;
	ctx->running = true;
	net_run(ctx->net_context);
}

void exchg_shutdown(struct exchg_context *ctx) {
	exchg_log("shutting down...\n");
	for (int i = 0; i < EXCHG_ALL_EXCHANGES; i++) {
		struct exchg_client *cl = ctx->clients[i];
		if (!cl)
			continue;
		exchg_teardown(cl);
	}
}

void exchg_blocking_shutdown(struct exchg_context *ctx) {
	if (!ctx->online)
		return;

	exchg_shutdown(ctx);
	exchg_run(ctx);
}

struct exchg_client *exchg_client(struct exchg_context *ctx,
				  enum exchg_id id) {
	if (id < 0 || id >= EXCHG_ALL_EXCHANGES)
		return NULL;
	return ctx->clients[id];
}

const char *exchg_id_to_name(enum exchg_id id) {
	switch (id) {
	case EXCHG_BITSTAMP:
		return "Bitstamp";
	case EXCHG_GEMINI:
		return "Gemini";
	case EXCHG_KRAKEN:
		return "Kraken";
	case EXCHG_COINBASE:
		return "Coinbase";
	default:
		return "<Invalid Exchange>";
	}
}

int exchg_set_password(struct exchg_client *cl,
		       size_t len, const char *password) {
	OPENSSL_cleanse(cl->password, cl->password_len);
	free(cl->password);
	cl->password = malloc(len+1);
	if (!cl->password) {
		exchg_log("%s: OOM\n", __func__);
		return -1;
	}
	memcpy(cl->password, password, len);
	cl->password[len] = 0;
	cl->password_len = len;
	return 0;
}

int exchg_set_keypair(struct exchg_client *cl,
		      size_t public_len, const unsigned char *public,
		      size_t private_len, const unsigned char *private) {
	cl->apikey_public = malloc(public_len+1);
	if (!cl->apikey_public) {
		exchg_log("%s: OOM\n", __func__);
		return -1;
	}
	memcpy(cl->apikey_public, public, public_len);
	cl->apikey_public[public_len] = 0;
	cl->apikey_public_len = public_len;
	if (cl->new_keypair(cl, private, private_len)) {
		free(cl->apikey_public);
		return -1;
	}
	return 0;
}

void exchg_vlog(const char *fmt, va_list ap) {
	struct timespec now;
	struct tm tm;
	char timestamp[60];
	char buf[1024];

	clock_gettime(CLOCK_REALTIME, &now);
	strftime(timestamp, sizeof(timestamp), "[%Y/%m/%d %T", localtime_r(&now.tv_sec, &tm));
	vsnprintf(buf, sizeof(buf), fmt, ap);
	fprintf(stderr, "%s.%.6ld] %s", timestamp, now.tv_nsec / 1000, buf);
}

void exchg_log(const char *fmt, ...) {
	va_list ap;

	va_start(ap, fmt);
	exchg_vlog(fmt, ap);
	va_end(ap);
}

int queue_work(struct exchg_client *cl,
	       bool (*f)(struct exchg_client *, void *), void *p) {
	struct work *w = malloc(sizeof(*w));
	if (!w) {
		exchg_log("%s: OOM\n", __func__);
		return -1;
	}
	w->cl = cl;
	w->f = f;
	w->p = p;
	LIST_INSERT_HEAD(&cl->work, w, list);
	return 0;
}

int queue_work_exclusive(struct exchg_client *cl,
			 bool (*f)(struct exchg_client *, void *), void *p) {
	struct work *w;
	LIST_FOREACH(w, &cl->work, list) {
		if (w->f == f && w->p == p)
			return 0;
	}
	return queue_work(cl, f, p);
}

void exchg_do_work(struct exchg_client *cl) {
	struct work *w, *tmp;

	LIST_FOREACH_SAFE(w, &cl->work, list, tmp) {
		if (w->f(w->cl, w->p)) {
			LIST_REMOVE(w, list);
			free(w);
		}
	}
}

void remove_work(struct exchg_client *cl,
		 bool (*f)(struct exchg_client *, void *), void *p) {
	struct work *w, *tmp;
	LIST_FOREACH_SAFE(w, &cl->work, list, tmp) {
		if (w->f == f && w->p == p) {
			LIST_REMOVE(w, list);
			free(w);
		}
	}
}
