// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#include <glib.h>
#include <libwebsockets.h>
#include <stdbool.h>

#include "net-backend.h"

struct websocket_conn {
        struct lws *wsi;
        char *host;
        char *path;
        void *user;
        unsigned char **headers_start;
        unsigned char *headers_end;
};

const int _net_write_buf_padding = LWS_PRE;

int ws_conn_write(struct websocket_conn *ws, const char *buf, size_t len)
{
        if (lws_write(ws->wsi, (unsigned char *)buf, len, LWS_WRITE_TEXT) <
            len) {
                // TODO: exchg_log() should be accessible here without including
                // exchg.h
                fprintf(stderr, "lws_write() error writing %zu bytes:\n%s\n",
                        len, buf);
                return -1;
        }
        return len;
}

int ws_conn_add_header(struct websocket_conn *ws, const unsigned char *name,
                       const unsigned char *val, size_t len)
{
        if (lws_add_http_header_by_name(ws->wsi, name, val, len,
                                        ws->headers_start, ws->headers_end)) {
                fprintf(stderr, "lws_add_http_header_by_name() error\n");
                return -1;
        }
        return 0;
}

void ws_conn_close(struct websocket_conn *ws)
{
        lws_set_timeout(ws->wsi, PENDING_TIMEOUT_USER_OK, LWS_TO_KILL_ASYNC);
}

static int websocket_callback(struct lws *wsi, enum lws_callback_reasons reason,
                              void *user, void *in, size_t len)
{
        const struct net_callbacks *c = lws_context_user(lws_get_context(wsi));
        const struct websocket_conn_callbacks *ops = &c->ws;
        struct websocket_conn *ws = user;

        switch (reason) {
        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
                lwsl_err("Websocket Connection Error: %s%s: %s\n", ws->host,
                         ws->path, in ? (char *)in : "(null)");
                ops->on_error(ws->user);
                free(ws->host);
                free(ws->path);
                free(ws);
                break;
        case LWS_CALLBACK_CLIENT_ESTABLISHED:
                ops->on_established(ws->user);
                break;
        case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
                ws->headers_start = (unsigned char **)in;
                ws->headers_end = *ws->headers_start + len;
                return ops->add_headers(ws->user, ws);
        case LWS_CALLBACK_CLIENT_RECEIVE:
                return ops->recv(ws->user, in, len);
        case LWS_CALLBACK_WS_PEER_INITIATED_CLOSE:
                // TODO
                break;
        case LWS_CALLBACK_CLIENT_CLOSED:
                ops->on_closed(ws->user);
                free(ws->host);
                free(ws->path);
                free(ws);
                return 0;
        default:
                break;
        }
        return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static int prepare_http_client_read(struct lws *wsi)
{
        char buffer[1024 + LWS_PRE];
        char *p = buffer + LWS_PRE;
        int len = sizeof(buffer) - LWS_PRE;
        return lws_http_client_read(wsi, &p, &len);
}

struct http_conn {
        struct lws *wsi;
        char *host;
        char *path;
        int status;
        bool want_write;
        unsigned char **headers_start;
        unsigned char *headers_end;
        void *user;
};

int http_conn_status(struct http_conn *req) { return req->status; }

int http_conn_add_header(struct http_conn *req, const unsigned char *name,
                         const unsigned char *val, size_t len)
{
        if (lws_add_http_header_by_name(req->wsi, name, val, len,
                                        req->headers_start, req->headers_end)) {
                fprintf(stderr, "lws_add_http_header_by_name() error\n");
                return -1;
        }
        return 0;
}

void http_conn_close(struct http_conn *req)
{
        lws_set_timeout(req->wsi, PENDING_TIMEOUT_USER_OK, LWS_TO_KILL_ASYNC);
}

void http_conn_want_write(struct http_conn *req) { req->want_write = true; }

static int http_callback(struct lws *wsi, enum lws_callback_reasons reason,
                         void *user, void *in, size_t len)
{
        const struct net_callbacks *c = lws_context_user(lws_get_context(wsi));
        const struct http_callbacks *http = &c->http;
        struct http_conn *req = user;
        char *body;
        size_t body_len;
        int ret;

        switch (reason) {
        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
                lwsl_err("HTTP CONNECTION ERROR: %s%s: %s\n", req->host,
                         req->path, in ? (char *)in : "(null)");
                http->on_error(req->user, (char *)in);
                free(req->host);
                free(req->path);
                free(req);
                break;
        case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
                req->status = lws_http_client_http_response(wsi);
                http->on_established(req->user, req->status);
                break;
        case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
                if (req->want_write) {
                        lws_client_http_body_pending(wsi, 1);
                        lws_callback_on_writable(wsi);
                }
                req->headers_start = (unsigned char **)in;
                req->headers_end = *req->headers_start + len;
                return http->add_headers(req->user, req);
        case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE:
                http->write(req->user, &body, &body_len);
                if (lws_write(req->wsi, (unsigned char *)body, body_len,
                              LWS_WRITE_TEXT) < body_len) {
                        lwsl_err("%s%s: write error\n", req->host, req->path);
                        ret = -1;
                } else {
                        ret = 0;
                }
                lws_client_http_body_pending(wsi, 0);
                return ret;
        case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
                return prepare_http_client_read(wsi);
        case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
                return http->recv(req->user, in, len);
                // TODO: not always called. to trigger, remove ssl global init
                // in context_create_info, or set hostname to garbage
        case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
                http->on_closed(req->user);
                free(req->host);
                free(req->path);
                free(req);
                break;
        default:
                break;
        }
        return lws_callback_http_dummy(wsi, reason, user, in, len);
}

struct lws_protocols protocols[] = {
    {
        "ws",
        websocket_callback,
    },
    {
        "http",
        http_callback,
    },
    {},
};

struct exchg_net_context {
        GMainLoop *loop;
        struct lws_context *ctx;
};

struct http_conn *http_dial(struct exchg_net_context *ctx, const char *host,
                            const char *path, const char *method, void *private)
{
        struct http_conn *req = malloc(sizeof(*req));
        if (!req) {
                fprintf(stderr, "OOM: %s\n", __func__);
                return NULL;
        }
        memset(req, 0, sizeof(*req));

        struct lws_client_connect_info info = {
            .context = ctx->ctx,
            .port = 443,
            .address = host,
            .path = path,
            .method = method,
            .host = host,
            .origin = host,
            .ssl_connection = LCCSCF_USE_SSL,
            .protocol = "http",
            .userdata = req,
            .pwsi = &req->wsi,
        };
        req->host = strdup(host);
        req->path = strdup(path);
        req->user = private;
        if (!req->host || !req->path) {
                fprintf(stderr, "OOM: %s\n", __func__);
                free(req->host);
                free(req->path);
                free(req);
                return NULL;
        }
        if (!lws_client_connect_via_info(&info)) {
                fprintf(
                    stderr,
                    "lws_client_connect_via_info() error connecting to %s%s\n",
                    host, path);
                free(req);
                return NULL;
        }
        return req;
}

struct websocket_conn *ws_dial(struct exchg_net_context *ctx, const char *host,
                               const char *path, void *private)
{
        struct websocket_conn *ws = malloc(sizeof(*ws));
        if (!ws) {
                fprintf(stderr, "OOM: %s\n", __func__);
                return NULL;
        }
        memset(ws, 0, sizeof(*ws));
        struct lws_client_connect_info info = {
            .context = ctx->ctx,
            .port = 443,
            .address = host,
            .path = path,
            .host = host,
            .origin = host,
            .ssl_connection = LCCSCF_USE_SSL,
            .protocol = "ws",
            .userdata = ws,
            .pwsi = &ws->wsi,
        };
        if (!lws_client_connect_via_info(&info)) {
                free(ws);
                fprintf(stderr, "websocket connection to %s%s failed\n", host,
                        path);
                return NULL;
        }
        ws->user = private;
        ws->host = strdup(host);
        ws->path = strdup(path);
        if (!ws->host || !ws->path) {
                fprintf(stderr, "OOM: %s\n", __func__);
                free(ws->host);
                free(ws->path);
                free(ws);
                return NULL;
        }
        return ws;
}

void net_service(struct exchg_net_context *ctx)
{
        g_main_context_iteration(NULL, TRUE);
}

void net_run(struct exchg_net_context *ctx) { g_main_loop_run(ctx->loop); }

void net_stop(struct exchg_net_context *ctx) { g_main_loop_quit(ctx->loop); }

void net_destroy(struct exchg_net_context *ctx)
{
        lws_context_destroy(ctx->ctx);
        g_main_loop_unref(ctx->loop);
        free(ctx);
}

struct exchg_net_context *net_new(struct net_callbacks *c)
{
        struct exchg_net_context *ret = malloc(sizeof(*ret));
        if (!ret) {
                fprintf(stderr, "OOM: %s\n", __func__);
                return NULL;
        }
        ret->loop = g_main_loop_new(NULL, false);

        struct lws_context_creation_info info = {
            .options =
                LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT | LWS_SERVER_OPTION_GLIB,
            .port = CONTEXT_PORT_NO_LISTEN,
            .protocols = protocols,
            .foreign_loops = (void **)&ret->loop,
            .user = c,
        };
        lws_set_log_level(LLL_WARN | LLL_ERR, NULL);
        ret->ctx = lws_create_context(&info);
        if (!ret->ctx) {
                g_main_loop_unref(ret->loop);
                free(ret);
                fprintf(stderr, "lws_create_context failed\n");
                return NULL;
        }
        return ret;
}

struct timer {
        GSource *source;
        void (*f)(void *);
        void *p;
};

gboolean timeout_callback(void *p)
{
        struct timer *t = p;

        t->f(t->p);
        g_source_unref(t->source);
        free(t);
        return FALSE;
}

struct timer *timer_new(struct exchg_net_context *ctx, void (*f)(void *),
                        void *p, int seconds)
{
        struct timer *t = malloc(sizeof(*t));
        if (!t) {
                fprintf(stderr, "%s: OOM\n", __func__);
                return NULL;
        }
        t->f = f;
        t->p = p;
        t->source = g_timeout_source_new_seconds(seconds);
        g_source_set_callback(t->source, timeout_callback, t, NULL);
        g_source_attach(t->source, NULL);
        return t;
}

void timer_cancel(struct timer *t)
{
        g_source_destroy(t->source);
        g_source_unref(t->source);
        free(t);
}
