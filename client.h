// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#ifndef CLIENT_H
#define CLIENT_H

#include <glib.h>
#include <jsmn/jsmn.h>
#include <libwebsockets.h>
#include <openssl/hmac.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/queue.h>

#include "exchg/decimal.h"
#include "exchg/currency.h"
#include "exchg/exchg.h"
#include "json-helpers.h"
#include "net-backend.h"
#include "order-book.h"

#define EXCH_DOWN (1U << 0)
#define EXCH_MAY_TRADE (1U << 1)
// TODO #define EXCH_SHUTTING_DOWN (1U << 2)

struct work {
	struct exchg_client *cl;
	bool (*f)(struct exchg_client *, void *);
	void *p;
	LIST_ENTRY(work) list;
};

void remove_work(struct exchg_client *,
		 bool (*f)(struct exchg_client *, void *), void *p);
int queue_work(struct exchg_client *,
	       bool (*f)(struct exchg_client *, void *), void *p);
int queue_work_exclusive(struct exchg_client *,
			 bool (*f)(struct exchg_client *, void *), void *p);
void exchg_do_work(struct exchg_client *cl);

struct conn;

enum conn_type {
	CONN_TYPE_HTTP,
	CONN_TYPE_WS,
};

struct order_info {
	struct exchg_order_info info;
	void *req_private;
	char private[];
};

static inline void *order_info_private(struct order_info *o) {
	return o->private;
}

struct exchg_client {
	enum exchg_id id;
	const char *name;
	struct exchg_context *ctx;
	int state;
	int (*get_pair_info)(struct exchg_client *cl);
	int (*l2_subscribe)(struct exchg_client *cl, enum exchg_pair pair);
	int (*get_balances)(struct exchg_client *cl, void *request_private);
	int64_t (*place_order)(struct exchg_client *cl, const struct exchg_order *,
			       const struct exchg_place_order_opts *,
			       void *request_private);
	int (*cancel_order)(struct exchg_client *cl, struct order_info *info);
	int (*new_keypair)(struct exchg_client *cl,
			   const unsigned char *key, size_t len);
	int (*priv_ws_connect)(struct exchg_client *cl);
	bool (*priv_ws_online)(struct exchg_client *cl);
	void (*destroy)(struct exchg_client *cl);
	LIST_HEAD(conn_list, conn) conn_list;
	HMAC_CTX *hmac_ctx;
	unsigned char *apikey_public;
	size_t apikey_public_len;
	char *password;
	size_t password_len;
	GHashTable *orders;
	bool getting_info;
	int get_info_error;
	bool pair_info_current;
	struct exchg_pair_info pair_info[EXCHG_NUM_PAIRS];
	int l2_update_size;
	struct exchg_l2_update update;
	LIST_HEAD(work_list, work) work;
	char private[];
};

static inline void *client_private(struct exchg_client *cl) {
	return cl->private;
}

static inline void exchg_update_init(struct exchg_client *cl) {
	cl->update.num_bids = 0;
	cl->update.num_asks = 0;
}

int exchg_realloc_order_bufs(struct exchg_client *cl, int n);

static inline void order_err_cpy(struct exchg_order_info *info, const char *json, jsmntok_t *tok) {
	if (tok)
		json_strncpy(info->err, json, tok, EXCHG_ORDER_ERR_SIZE);
	else
		strncpy(info->err, "<unknown>", EXCHG_ORDER_ERR_SIZE);
}

struct order_info *__exchg_new_order(struct exchg_client *cl, const struct exchg_order *order,
				     const struct exchg_place_order_opts *opts,
				     void *req_private, size_t private_size, int64_t id);
struct order_info *exchg_new_order(struct exchg_client *cl, const struct exchg_order *order,
				   const struct exchg_place_order_opts *opts, void *req_private,
				   size_t private_size);

static inline bool order_status_done(enum exchg_order_status status) {
	return status == EXCHG_ORDER_FINISHED || status == EXCHG_ORDER_CANCELED ||
		status == EXCHG_ORDER_ERROR;
}

void order_info_free(struct exchg_client *cl, struct order_info *info);
void exchg_order_update(struct exchg_client *cl, struct order_info *oi,
			enum exchg_order_status new_status, const decimal_t *new_size, bool cancel_failed);
struct order_info *exchg_order_lookup(struct exchg_client *cl, int64_t id);

__attribute__((format (printf, 3, 4)))
static inline void order_err_update(struct exchg_client *cl, struct order_info *oi,
				    const char *fmt, ...) {
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(oi->info.err, EXCHG_ORDER_ERR_SIZE, fmt, ap);
	exchg_order_update(cl, oi, EXCHG_ORDER_ERROR, NULL, false);
	va_end(ap);
}

struct exchg_context {
	struct exchg_options opts;
	int exchanges_online;
	struct exchg_callbacks callbacks;
	void *user;
	struct exchg_client *clients[EXCHG_ALL_EXCHANGES];
	struct order_book *books[EXCHG_NUM_PAIRS];
	struct exchg_net_context *net_context;
};

static inline void exchg_l2_update(struct exchg_client *cl,
				   enum exchg_pair pair) {
	struct exchg_context *ctx = cl->ctx;
	struct exchg_l2_update *upd = &cl->update;
	struct order_book *book = ctx->books[pair];

	if (book)
		order_book_add_update(book, upd);
	if (ctx->callbacks.on_l2_update)
		ctx->callbacks.on_l2_update(cl, pair, upd, ctx->user);
	if (book)
		order_book_update_finish(book, upd);
}

void exchg_data_disconnect(struct exchg_client *cl,
			   struct conn *conn,
			   int num_pairs_gone,
			   enum exchg_pair *pairs_gone);

static inline void exchg_on_balances(struct exchg_client *cl,
				     const decimal_t balances[EXCHG_NUM_CCYS],
				     void *req_private) {
	if (cl->ctx->callbacks.on_balances_recvd)
		cl->ctx->callbacks.on_balances_recvd(cl, balances,
						     cl->ctx->user, req_private);
}

static inline void exchg_on_pair_info(struct exchg_client *cl) {
	cl->pair_info_current = true;
	cl->get_info_error = 0;
	if (cl->ctx->callbacks.on_pair_info)
		cl->ctx->callbacks.on_pair_info(cl, cl->ctx->user);
}

static inline void exchg_on_event(struct exchg_client *cl, int type) {
	if (cl->ctx->callbacks.on_event)
		cl->ctx->callbacks.on_event(cl, type, cl->ctx->user);
}

static inline void exchg_book_clear(struct exchg_client *cl, enum exchg_pair pair) {
	struct order_book *book = cl->ctx->books[pair];

	if (book)
		order_book_clear(book, cl->id);
}

struct exchg_client *alloc_exchg_client(struct exchg_context *ctx,
					enum exchg_id id, int l2_update_size, size_t private_size);
// complete in progress stuff first
// otherwise you can get a user after free in http_get callback
void free_exchg_client(struct exchg_client *cl);

static inline void exchg_set_up(struct exchg_client *cl) {
	cl->state &= ~EXCH_DOWN;
	cl->ctx->exchanges_online = 1;
}

struct exchg_websocket_ops {
	int (*on_conn_established)(struct exchg_client *, struct conn *);
	int (*add_headers)(struct exchg_client *, struct conn *);
	int (*on_disconnect)(struct exchg_client *, struct conn *,
			     int reconnect_seconds);
	int (*recv)(struct exchg_client *, struct conn *,
		    char *js, int num_toks, jsmntok_t *toks);
	size_t conn_data_size;
};

bool conn_disconnecting(struct conn *c);
bool conn_established(struct conn *c);
const char *conn_method(struct conn *c);
const char *conn_host(struct conn *c);
const char *conn_path(struct conn *c);
enum conn_type conn_type(struct conn *c);

struct conn *exchg_websocket_connect(struct exchg_client *cl,
				     const char *host, const char *path,
				     const struct exchg_websocket_ops *ops);

int conn_printf(struct conn *conn, const char *fmt, ...)
	__attribute__((format (printf, 2, 3)));

int conn_http_body_sprintf(struct conn *conn, const char *fmt, ...)
	__attribute__((format (printf, 2, 3)));
char *conn_http_body(struct conn *conn);
size_t conn_http_body_len(struct conn *conn);

void *conn_private(struct conn *c);

void for_each_conn(struct exchg_client *cl,
		   int (*func)(struct conn *conn, void *private),
		   void *private);

int exchg_parse_info_on_established(struct exchg_client *cl,
				    struct conn *, int status);
void exchg_parse_info_on_error(struct exchg_client *cl, struct conn *,
			       const char *err);
void exchg_parse_info_on_closed(struct exchg_client *cl, struct conn *);

int conn_add_header(struct conn *, const unsigned char *name,
		    const unsigned char *val, size_t len);

struct exchg_http_ops {
	int (*add_headers)(struct exchg_client *, struct conn *);
	// TODO: remove status param
	int (*recv)(struct exchg_client *cl, struct conn *, int status,
		    char *js, int num_toks, jsmntok_t *toks);
	int (*on_established)(struct exchg_client *cl,
			      struct conn *, int status);
	void (*on_closed)(struct exchg_client *cl, struct conn *);
	void (*on_error)(struct exchg_client *cl, struct conn *, const char *err);
	size_t conn_data_size;
};

struct conn *exchg_http_get(const char *host, const char *path,
			    const struct exchg_http_ops *ops,
			    struct exchg_client *cl);
struct conn *exchg_http_post(const char *host, const char *path,
			     const struct exchg_http_ops *ops,
			     struct exchg_client *cl);
struct conn *exchg_http_delete(const char *host, const char *path,
			       const struct exchg_http_ops *ops,
			       struct exchg_client *cl);

void conn_close(struct conn *);

void exchg_log(const char *fmt, ...) __attribute__((format (printf, 1, 2)));

#endif
