// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#ifndef FAKE_NET_H
#define FAKE_NET_H

#include <openssl/hmac.h>
#include <stdbool.h>
#include <sys/queue.h>

#include "auth.h"
#include "client.h"
#include "exchg/exchg.h"
#include "exchg/test.h"

struct buf {
	char *buf;
	size_t len;
	size_t size;
};

struct http_req {
	int status;
	enum exchg_id id;
	void *user;
	struct exchg_net_context *ctx;
	struct exchg_test_event *read_event;
	struct buf body;
	void (*read)(struct http_req *req, struct exchg_test_event *ev, struct buf *buf);
	void (*write)(struct http_req *req);
	void (*add_header)(struct http_req *req, const unsigned char *name,
			   const unsigned char *val, size_t len);
	void (*destroy)(struct http_req *req);
	void *priv;
};

struct websocket {
	bool established;
	enum exchg_id id;
	LIST_ENTRY(websocket) list;
	void *user;
	struct exchg_net_context *ctx;
	void (*read)(struct websocket *, struct buf *buf, struct exchg_test_event *);
	void (*write)(struct websocket *, char *buf, size_t len);
	int (*matches)(struct websocket *, enum exchg_pair );
	void (*destroy)(struct websocket *);
	void *priv;
};

int buf_xsprintf(struct buf *buf, const char *fmt, ...)
	__attribute__((format (printf, 2, 3)));
void buf_xcpy(struct buf *buf, void *src, size_t len);

static inline void buf_clear(struct buf *buf) {
	buf->len = 0;
}

struct exchg_test_event *exchg_fake_queue_ws_event(
	struct websocket *w, enum exchg_test_event_type type, size_t private_size);
struct exchg_test_event *exchg_fake_queue_ws_event_tail(
	struct websocket *w, enum exchg_test_event_type type, size_t private_size);

void no_ws_write(struct websocket *, char *, size_t);

enum auth_status {
	AUTH_UNSET,
	AUTH_GOOD,
	AUTH_BAD,
};

struct auth_check {
	enum auth_status apikey_status;
	enum auth_status hmac_status;
	size_t payload_len;
	unsigned char *payload;
	size_t public_len;
	unsigned char *public;
	size_t private_len;
	unsigned char *private;
	int hmac_hex;
	enum hex_type hex_type;
	int hmac_len;
	char *hmac;
	HMAC_CTX *hmac_ctx;

};

struct auth_check *auth_check_alloc(size_t public_len, const unsigned char *public,
				    size_t private_len, const unsigned char *private,
				    int hmac_hex, enum hex_type type, const EVP_MD *md);
void auth_check_free(struct auth_check *);
void auth_check_set_public(struct auth_check *, const unsigned char *c, size_t len);
void auth_check_set_payload(struct auth_check *a, const unsigned char *c, size_t len);
void auth_check_set_hmac(struct auth_check *a, const unsigned char *c, size_t len);

void no_http_write(struct http_req *req);
void no_http_add_header(struct http_req *req, const unsigned char *name,
			const unsigned char *val, size_t len);

struct test_event {
	enum conn_type conn_type;
	union {
		struct http_req *http;
		struct websocket *ws;
	} conn;
	struct exchg_test_event event;
	TAILQ_ENTRY(test_event) list;
	char private[];
};

void *test_event_private(struct exchg_test_event *event);

struct exchg_net_context {
	struct net_callbacks *callbacks;
	LIST_HEAD(ws_list, websocket) ws_list;
	TAILQ_HEAD(events, test_event) events;
	decimal_t balances[EXCHG_ALL_EXCHANGES][EXCHG_NUM_CCYS];
	int next_order_id;
	exchg_test_callback_t callback;
	void *cb_private;
	// TODO: char error[100];
};

struct websocket *fake_websocket_alloc(struct exchg_net_context *ctx, void *user);
struct http_req *fake_http_req_alloc(struct exchg_net_context *ctx, enum exchg_id exchange,
				     enum exchg_test_event_type type, void *private);
void fake_http_req_free(struct http_req *);

void on_order_placed(struct exchg_net_context *ctx, enum exchg_id id,
		     struct exchg_order_info *ack);

#endif
