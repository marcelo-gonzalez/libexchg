// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#ifndef NET_BACKEND_H
#define NET_BACKEND_H

#include <stdarg.h>
#include <stdbool.h>

struct exchg_net_context;

struct http_conn;

struct http_callbacks {
	void (*on_error)(void *p, const char *err);
	void (*on_established)(void *p, int status);
	int (*add_headers)(void *p, struct http_conn *);
	int (*recv)(void *p, char *in, size_t len);
	void (*on_closed)(void *p);
};

struct websocket_conn;

struct websocket_conn_callbacks {
	void (*on_error)(void *p);
	void (*on_established)(void *p);
	int (*add_headers)(void *p, struct websocket_conn *);
	int (*recv)(void *p, char *in, size_t len);
	void (*on_closed)(void *p);
};

struct net_callbacks {
	struct http_callbacks http;
	struct websocket_conn_callbacks ws;
};

extern struct exchg_net_context *net_new(struct net_callbacks *c);
extern void net_service(struct exchg_net_context *);
extern void net_run(struct exchg_net_context *);
extern void net_stop(struct exchg_net_context *);
extern void net_destroy(struct exchg_net_context *);

int http_conn_add_header(struct http_conn *req, const unsigned char *name,
			 const unsigned char *val, size_t len);

int http_conn_vsprintf(struct http_conn *req, const char *fmt, va_list ap);
char *http_conn_body(struct http_conn *req);
size_t http_conn_body_len(struct http_conn *req);

struct http_conn *http_dial(struct exchg_net_context *,
			    const char *host, const char *path,
			    const char *method, void *private);
int http_conn_status(struct http_conn *);

void http_conn_close(struct http_conn *req);

extern int ws_conn_vprintf(struct websocket_conn *, const char *fmt, va_list ap);

int ws_conn_add_header(struct websocket_conn *req, const unsigned char *name,
		       const unsigned char *val, size_t len);

void ws_conn_close(struct websocket_conn *ws);

struct websocket_conn *ws_dial(struct exchg_net_context *, const char *host,
			       const char *path, void *private);

struct timer;

struct timer *timer_new(struct exchg_net_context *, void (*)(void *), void *, int seconds);
// it is a bug to call this inside the timer callback
void timer_cancel(struct timer *t);
#endif
