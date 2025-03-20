// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#ifndef NET_BACKEND_H
#define NET_BACKEND_H

#include <sys/types.h>

struct exchg_net_context;

struct http_conn;

extern const int _net_write_buf_padding;

struct http_callbacks {
        void (*on_error)(void *p, const char *err);
        void (*on_established)(void *p, int status);
        int (*add_headers)(void *p, struct http_conn *);
        int (*recv)(void *p, char *in, size_t len);
        // if len > 0, buf must be preceded by _net_write_buf_padding
        void (*write)(void *p, char **buf, size_t *len);
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

// `arg` is only used by the test exchg_net_context and is cast in that case to
// exchg_test_options *.
extern struct exchg_net_context *net_new(struct net_callbacks *c, void *arg);
extern void net_service(struct exchg_net_context *);
extern void net_run(struct exchg_net_context *);
extern void net_stop(struct exchg_net_context *);
extern void net_destroy(struct exchg_net_context *);

int http_conn_add_header(struct http_conn *req, const unsigned char *name,
                         const unsigned char *val, size_t len);

void http_conn_want_write(struct http_conn *req);

struct http_conn *http_dial(struct exchg_net_context *, const char *host,
                            const char *path, const char *method,
                            void *private);
int http_conn_status(struct http_conn *);

void http_conn_close(struct http_conn *req);

// buf must be preceded by _net_write_buf_padding
extern int ws_conn_write(struct websocket_conn *, const char *buf, size_t len);

int ws_conn_add_header(struct websocket_conn *req, const unsigned char *name,
                       const unsigned char *val, size_t len);

void ws_conn_close(struct websocket_conn *ws);

struct websocket_conn *ws_dial(struct exchg_net_context *, const char *host,
                               const char *path, void *private);

struct timer;

struct timer *timer_new(struct exchg_net_context *, void (*)(void *), void *,
                        int seconds);
// it is a bug to call this inside the timer callback
void timer_cancel(struct timer *t);
#endif
