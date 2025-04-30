// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "auth.h"
#include "net-backend.h"

#include "fake-bitstamp.h"
#include "fake-coinbase.h"
#include "fake-gemini.h"
#include "fake-kraken.h"
#include "fake-net.h"
#include "util.h"

const int _net_write_buf_padding = 16;

static void buf_init(struct buf *buf, size_t size)
{
        if (buf_alloc(buf, size, 0))
                exit(1);
}

void http_conn_want_write(struct http_conn *req) {}

static int ws_matches(struct websocket_conn *ws, struct exchg_test_event *ev)
{
        return ev->type == EXCHG_EVENT_BOOK_UPDATE && ws->established &&
               ws->id == ev->id && ws->matches(ws, ev->data.book.pair);
}

void exchg_test_set_callback(struct exchg_net_context *ctx,
                             exchg_test_callback_t cb, void *private)
{
        ctx->callback = cb;
        ctx->cb_private = private;
}

static const char *event_str(enum exchg_test_event_type type)
{
        switch (type) {
        case EXCHG_EVENT_HTTP_PREP:
                return "HTTP_PREP";
        case EXCHG_EVENT_WS_PREP:
                return "WS_PREP";
        case EXCHG_EVENT_BOOK_UPDATE:
                return "BOOK_UPDATE";
        case EXCHG_EVENT_ORDER_PLACED:
                return "ORDER_PLACED";
        case EXCHG_EVENT_ORDER_CANCELED:
                return "ORDER_CANCELED";
        case EXCHG_EVENT_ORDER_ACK:
                return "ORDER_ACK";
        case EXCHG_EVENT_ORDER_CANCEL_ACK:
                return "ORDER_CANCEL_ACK";
        case EXCHG_EVENT_PAIRS_DATA:
                return "PAIRS_DATA";
        case EXCHG_EVENT_BALANCES:
                return "BALANCES";
        case EXCHG_EVENT_WS_PROTOCOL:
                return "WS_PROTOCOL";
        case EXCHG_EVENT_HTTP_PROTOCOL:
                return "HTTP_PROTOCOL";
        case EXCHG_EVENT_WS_CLOSE:
                return "WS_CLOSE";
        case EXCHG_EVENT_HTTP_CLOSE:
                return "HTTP_CLOSE";
        case EXCHG_EVENT_TIMER:
                return "TIMER";
        default:
                return "<Unknown Type : Internal Error>";
        }
}

void exchg_test_event_print(struct exchg_test_event *ev)
{
        const char *exchange;

        switch (ev->id) {
        case EXCHG_BITSTAMP:
                exchange = "Bitstamp";
                break;
        case EXCHG_GEMINI:
                exchange = "Gemini";
                break;
        case EXCHG_KRAKEN:
                exchange = "Kraken";
                break;
        case EXCHG_COINBASE:
                exchange = "Coinbase";
                break;
        default:
                exchange = "<No Exchange>";
                break;
        }

        printf("event: %s %s\n", exchange, event_str(ev->type));
}

static void set_matching_ws(struct exchg_net_context *ctx,
                            struct test_event *ev)
{
        struct websocket_conn *ws;
        LIST_FOREACH(ws, &ctx->ws_list, list)
        {
                if (ws_matches(ws, &ev->event)) {
                        ev->conn.ws = ws;

                        struct test_event *e;
                        TAILQ_FOREACH(e, &ctx->events, list)
                        {
                                if (ws_matches(ws, &e->event)) {
                                        e->conn.ws = ws;
                                }
                        }
                        break;
                }
        }
}

void exchg_test_add_events(struct exchg_net_context *ctx, int n,
                           struct exchg_test_event *events)
{
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

int exchg_test_l2_queue_order(struct exchg_test_l2_updates *u, bool is_bid,
                              decimal_t *price, decimal_t *size)
{
        if (is_bid) {
                if (u->num_bids >= u->bid_cap) {
                        int new_cap = u->bid_cap * 2 + 1;
                        struct exchg_test_l2_update *bids =
                            realloc(u->bids, sizeof(*u->bids) * new_cap);
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
                        struct exchg_test_l2_update *asks =
                            realloc(u->asks, sizeof(*u->asks) * new_cap);
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

void exchg_test_add_l2_events(struct exchg_net_context *ctx, int n,
                              struct exchg_test_str_l2_updates *msgs)
{
        for (int i = 0; i < n; i++) {
                struct exchg_test_str_l2_updates *o = &msgs[i];
                struct test_event *event = xzalloc(sizeof(*event));
                struct exchg_test_event *e = &event->event;

                event->conn_type = CONN_TYPE_WS;
                e->id = o->id;
                e->type = EXCHG_EVENT_BOOK_UPDATE;
                e->data.book.pair = o->pair;

                for (struct exchg_test_str_l2_update *s = &o->bids[0]; s->price;
                     s++) {
                        decimal_t price, size;
                        decimal_from_str(&price, s->price);
                        decimal_from_str(&size, s->size);
                        if (exchg_test_l2_queue_order(&e->data.book, true,
                                                      &price, &size)) {
                                exchg_log("%s: OOM\n", __func__);
                                return;
                        }
                }
                for (struct exchg_test_str_l2_update *s = &o->asks[0]; s->price;
                     s++) {
                        decimal_t price, size;
                        decimal_from_str(&price, s->price);
                        decimal_from_str(&size, s->size);
                        if (exchg_test_l2_queue_order(&e->data.book, false,
                                                      &price, &size)) {
                                exchg_log("%s: OOM\n", __func__);
                                return;
                        }
                }
                set_matching_ws(ctx, event);
                TAILQ_INSERT_TAIL(&ctx->events, event, list);
        }
}

static struct test_event *test_event_container(struct exchg_test_event *event)
{
        return (
            struct test_event *)((void *)event -
                                 (void *)&((struct test_event *)NULL)->event);
}

void *test_event_private(struct exchg_test_event *event)
{
        return test_event_container(event)->private;
}

struct test_event *event_alloc(struct websocket_conn *w,
                               enum exchg_test_event_type type,
                               size_t private_size)
{
        struct test_event *event = xzalloc(sizeof(*event) + private_size);
        struct exchg_test_event *e = &event->event;

        event->conn_type = CONN_TYPE_WS;
        event->conn.ws = w;
        e->id = w->id;
        e->type = type;
        return event;
}

struct exchg_test_event *
exchg_fake_queue_ws_event(struct websocket_conn *w,
                          enum exchg_test_event_type type, size_t private_size)
{
        struct test_event *event = event_alloc(w, type, private_size);
        struct test_event *last = NULL, *tmp;

        TAILQ_FOREACH(tmp, &w->ctx->events, list)
        {
                if (tmp->event.type == EXCHG_EVENT_WS_PROTOCOL &&
                    tmp->conn.ws == w)
                        last = tmp;
        }
        if (last)
                TAILQ_INSERT_AFTER(&w->ctx->events, last, event, list);
        else
                TAILQ_INSERT_HEAD(&w->ctx->events, event, list);
        return &event->event;
}

struct exchg_test_event *
exchg_fake_queue_ws_event_tail(struct websocket_conn *w,
                               enum exchg_test_event_type type,
                               size_t private_size)
{
        struct test_event *event = event_alloc(w, type, private_size);

        TAILQ_INSERT_TAIL(&w->ctx->events, event, list);
        return &event->event;
}

struct exchg_test_event *exchg_fake_queue_ws_event_before(
    struct websocket_conn *w, enum exchg_test_event_type type,
    size_t private_size, struct exchg_test_event *before)
{
        struct test_event *event = event_alloc(w, type, private_size);

        TAILQ_INSERT_BEFORE(test_event_container(before), event, list);
        return &event->event;
}

struct exchg_test_event *exchg_fake_queue_ws_event_after(
    struct websocket_conn *w, enum exchg_test_event_type type,
    size_t private_size, struct exchg_test_event *after)
{
        struct test_event *event = event_alloc(w, type, private_size);

        TAILQ_INSERT_AFTER(&w->ctx->events, test_event_container(after), event,
                           list);
        return &event->event;
}

struct exchg_net_context *net_new(struct net_callbacks *c)
{
        struct exchg_net_context *ctx = xzalloc(sizeof(*ctx));
        TAILQ_INIT(&ctx->events);
        LIST_INIT(&ctx->ws_list);
        LIST_INIT(&ctx->http_list);
        ctx->callbacks = c;
        return ctx;
}

static void free_event(struct exchg_net_context *ctx, struct test_event *ev)
{
        TAILQ_REMOVE(&ctx->events, ev, list);
        if (ev->event.type == EXCHG_EVENT_BOOK_UPDATE) {
                free(ev->event.data.book.bids);
                free(ev->event.data.book.asks);
        } else if (ev->event.type == EXCHG_EVENT_ORDER_ACK) {
                struct exchg_order_info *info = &ev->event.data.order_ack;
                struct test_order *o, *tmp;
                if (info->status == EXCHG_ORDER_ERROR ||
                    info->status == EXCHG_ORDER_FINISHED ||
                    info->status == EXCHG_ORDER_CANCELED) {
                        LIST_FOREACH_SAFE(
                            o, &ctx->servers[ev->event.id].order_list, list,
                            tmp)
                        {
                                if (o->info.id == info->id) {
                                        LIST_REMOVE(o, list);
                                        free(o);
                                        break;
                                }
                        }
                }
        }
        free(ev);
}

struct test_order *on_order_placed(struct exchg_net_context *ctx,
                                   enum exchg_id id,
                                   struct exchg_order_info *ack,
                                   size_t private_size)
{
        struct exchg_test_event event = {
            .id = id,
            .type = EXCHG_EVENT_ORDER_PLACED,
            .data.order_placed =
                {
                    .id = ++ctx->next_order_id,
                    .order = ack->order,
                    .opts = ack->opts,
                    .fill_size = ack->order.size,
                },
        };
        struct exchg_test_order_placed *placed = &event.data.order_placed;
        if (ctx->callback)
                ctx->callback(ctx, &event, ctx->cb_private);
        if (placed->error)
                ack->status = EXCHG_ORDER_ERROR;
        else if (decimal_cmp(&placed->fill_size, &ack->order.size) >= 0)
                ack->status = EXCHG_ORDER_FINISHED;
        else if (ack->opts.immediate_or_cancel)
                ack->status = EXCHG_ORDER_CANCELED;
        else
                ack->status = EXCHG_ORDER_OPEN;
        ack->filled_size = placed->fill_size;
        ack->id = placed->id;

        struct test_order *t = xzalloc(sizeof(*t) + private_size);
        t->info = *ack;
        LIST_INSERT_HEAD(&ctx->servers[id].order_list, t, list);
        return t;
}

bool on_order_canceled(struct exchg_net_context *ctx, enum exchg_id id,
                       struct test_order *o)
{
        struct exchg_test_event event = {.id = id,
                                         .type = EXCHG_EVENT_ORDER_CANCELED,
                                         .data.order_canceled = {
                                             .info = o->info,
                                             .succeed = true,
                                         }};
        if (ctx->callback)
                ctx->callback(ctx, &event, ctx->cb_private);
        if (event.data.order_canceled.succeed)
                o->info.status = EXCHG_ORDER_CANCELED;
        return event.data.order_canceled.succeed;
}

struct timer {
        void (*f)(void *);
        void *p;
        struct exchg_net_context *ctx;
};

static bool service(struct exchg_net_context *ctx)
{
        int ret;
        struct buf buf;
        struct test_event *ev, *e, *tmp;
        struct exchg_test_event *event = NULL;
        struct websocket_conn_callbacks *ws = &ctx->callbacks->ws;
        struct http_callbacks *http = &ctx->callbacks->http;
        struct http_conn *http_conn;
        struct websocket_conn *wsock;
        char *body;
        size_t body_len;

        ev = TAILQ_FIRST(&ctx->events);
        if (ev)
                event = &ev->event;

        if (ctx->callback)
                ctx->callback(ctx, event, ctx->cb_private);

        if (TAILQ_EMPTY(&ctx->events)) {
                exchg_log("test: no events left to service\n");
                return false;
        }

        ev = TAILQ_FIRST(&ctx->events);
        event = &ev->event;

        switch (ev->conn_type) {
        case CONN_TYPE_WS:
                wsock = ev->conn.ws;
                if (!wsock) {
                        set_matching_ws(ctx, ev);
                        wsock = ev->conn.ws;
                }
                if (!wsock) {
                        exchg_log("test: event with no matching websocket:\n"
                                  "%s %d\n",
                                  exchg_id_to_name(event->id), event->type);
                        break;
                }
                switch (event->type) {
                case EXCHG_EVENT_WS_PREP:
                        ws->on_established(wsock->user);
                        wsock->established = true;
                        TAILQ_FOREACH(e, &ctx->events, list)
                        {
                                if (e != ev && ws_matches(wsock, &e->event))
                                        e->conn.ws = wsock;
                        }
                        break;
                case EXCHG_EVENT_WS_CLOSE:
                        TAILQ_FOREACH_SAFE(e, &ctx->events, list, tmp)
                        {
                                if (e != ev && e->conn_type == CONN_TYPE_WS &&
                                    e->conn.ws == ev->conn.ws) {
                                        free_event(ctx, e);
                                }
                        }
                        LIST_REMOVE(wsock, list);
                        ws->on_closed(wsock->user);
                        wsock->destroy(wsock);
                        break;
                default:
                        buf_init(&buf, 1 << 10);
                        wsock->read(wsock, &buf, event);
                        ws->recv(wsock->user, buf_start(&buf), buf.len);
                        buf_free(&buf);
                        break;
                }
                break;
        case CONN_TYPE_HTTP:
                http_conn = ev->conn.http;
                switch (event->type) {
                case EXCHG_EVENT_HTTP_PREP:
                        ret = http->add_headers(http_conn->user, http_conn);
                        // TODO: if (ret) close(req);
                        http->write(http_conn->user, &body, &body_len);
                        http_conn->write(http_conn, body, body_len);
                        if (!ret)
                                http->on_established(http_conn->user,
                                                     http_conn->status);
                        // callback to fill in here
                        break;
                case EXCHG_EVENT_HTTP_CLOSE:
                        TAILQ_FOREACH_SAFE(e, &ctx->events, list, tmp)
                        {
                                if (e != ev && e->conn_type == CONN_TYPE_HTTP &&
                                    e->conn.http == ev->conn.http) {
                                        free_event(ctx, e);
                                }
                        }
                        LIST_REMOVE(http_conn, list);
                        http->on_closed(http_conn->user);
                        http_conn->destroy(http_conn);
                        break;
                default:
                        buf_init(&buf, 1 << 10);
                        http_conn->read(http_conn, event, &buf);
                        http->recv(http_conn->user, buf_start(&buf), buf.len);
                        buf_free(&buf);
                        http_conn_close(http_conn);
                        http_conn->read_event = NULL;
                        break;
                }
                break;
        case CONN_TYPE_NONE:
                if (event->type != EXCHG_EVENT_TIMER) {
                        exchg_log(
                            "test: internal error: CONN_TYPE_NONE event with"
                            " type != TIMER: %s\n",
                            event_str(event->type));
                        break;
                }
                struct timer *t = test_event_private(event);
                t->f(t->p);
                break;
        }
        free_event(ctx, ev);
        return true;
}

void net_service(struct exchg_net_context *ctx) { service(ctx); }

void timer_cancel(struct timer *t)
{
        // can I copy the linux container_of() macro? can't put GPL stuff in
        // this MIT licenced code but it's so small... better safe than sorry
        struct test_event *e =
            (struct test_event
                 *)((void *)t - (void *)&((struct test_event *)NULL)->private);
        free_event(t->ctx, e);
}

struct timer *timer_new(struct exchg_net_context *ctx, void (*f)(void *),
                        void *p, int seconds)
{
        struct test_event *e = xzalloc(sizeof(*e) + sizeof(struct timer));

        e->conn_type = CONN_TYPE_NONE;
        e->event.id = -1;
        e->event.type = EXCHG_EVENT_TIMER;
        struct timer *t = (struct timer *)e->private;
        t->f = f;
        t->p = p;
        t->ctx = ctx;
        TAILQ_INSERT_HEAD(&ctx->events, e, list);
        return t;
}

void net_run(struct exchg_net_context *ctx)
{
        ctx->running = true;
        while (ctx->running && service(ctx)) {
        }

        if (!TAILQ_EMPTY(&ctx->events)) {
                struct test_event *e;
                exchg_log("test: net_stop() called with events left!:\n");
                TAILQ_FOREACH(e, &ctx->events, list)
                {
                        exchg_test_event_print(&e->event);
                }
        }
}

void net_stop(struct exchg_net_context *ctx) { ctx->running = false; }

void net_destroy(struct exchg_net_context *ctx)
{
        struct test_event *e, *etmp;
        struct http_conn *h, *htmp;
        struct websocket_conn *w, *wtmp;
        struct test_order *o, *otmp;

        TAILQ_FOREACH_SAFE(e, &ctx->events, list, etmp) { free_event(ctx, e); }
        LIST_FOREACH_SAFE(w, &ctx->ws_list, list, wtmp) { w->destroy(w); }
        LIST_FOREACH_SAFE(h, &ctx->http_list, list, htmp) { h->destroy(h); }
        for (enum exchg_id id = 0; id < EXCHG_ALL_EXCHANGES; id++) {
                LIST_FOREACH_SAFE(o, &ctx->servers[id].order_list, list, otmp)
                {
                        LIST_REMOVE(o, list);
                        free(o);
                }
        }
        free(ctx);
}

void no_ws_write(struct websocket_conn *w, const char *buf, size_t len) {}

void no_http_add_header(struct http_conn *req, const unsigned char *name,
                        const unsigned char *val, size_t len)
{
}

void no_http_write(struct http_conn *req, const char *body, size_t len) {}

int http_conn_add_header(struct http_conn *req, const unsigned char *name,
                         const unsigned char *val, size_t len)
{
        req->add_header(req, name, val, len);
        return 0;
}

void fake_http_conn_free(struct http_conn *req)
{
        free(req->host);
        free(req->path);
        free(req);
}

struct http_conn *fake_http_conn_alloc(struct exchg_net_context *ctx,
                                       enum exchg_id exchange,
                                       enum exchg_test_event_type type,
                                       void *private)
{
        struct http_conn *req = xzalloc(sizeof(*req));
        struct test_event *prep_event = xzalloc(sizeof(*prep_event));
        struct test_event *read_event = xzalloc(sizeof(*read_event));
        struct exchg_test_event *prep_ev = &prep_event->event;
        struct exchg_test_event *read_ev = &read_event->event;

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
        LIST_INSERT_HEAD(&ctx->http_list, req, list);
        return req;
}

struct http_conn *http_dial(struct exchg_net_context *ctx, const char *host,
                            const char *path, const char *method, void *private)
{
        struct http_conn *http;

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

        http->host = xstrdup(host);
        http->path = xstrdup(path);
        return http;
}

int http_conn_status(struct http_conn *req) { return req->status; }

void http_conn_close(struct http_conn *http)
{
        struct test_event *event;
        struct exchg_test_event *ev;

        TAILQ_FOREACH(event, &http->ctx->events, list)
        {
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

int ws_conn_write(struct websocket_conn *ws, const char *buf, size_t len)
{
        ws->write(ws, buf, len);
        return len;
}

int ws_conn_add_header(struct websocket_conn *req, const unsigned char *name,
                       const unsigned char *val, size_t len)
{
        // TODO
        return 0;
}

void ws_conn_close(struct websocket_conn *ws)
{
        struct test_event *event;
        struct exchg_test_event *ev;

        TAILQ_FOREACH(event, &ws->ctx->events, list)
        {
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

struct websocket_conn *fake_websocket_alloc(struct exchg_net_context *ctx,
                                            void *user)
{
        struct websocket_conn *s = xzalloc(sizeof(*s));
        s->user = user;
        s->ctx = ctx;
        LIST_INSERT_HEAD(&ctx->ws_list, s, list);
        return s;
}

void ws_conn_free(struct websocket_conn *ws)
{
        free(ws->host);
        free(ws->path);
        free(ws);
}

struct websocket_conn *fake_websocket_get(struct exchg_net_context *ctx,
                                          const char *host, const char *path)
{
        struct websocket_conn *ws;
        LIST_FOREACH(ws, &ctx->ws_list, list)
        {
                if (!strcmp(ws->host, host) &&
                    (!path || !strcmp(ws->path, path)))
                        return ws;
        }
        return NULL;
}

struct websocket_conn *ws_dial(struct exchg_net_context *ctx, const char *host,
                               const char *path, void *private)
{
        struct websocket_conn *ws;
        enum exchg_id exchange;

        if (!strcmp(host, "api.gemini.com")) {
                exchange = EXCHG_GEMINI;
                ws = gemini_ws_dial(ctx, path, private);
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
                fprintf(
                    stderr,
                    "client attempted to contact unknown websocket host: %s\n",
                    host);
                return NULL;
        }

        if (!ws)
                return NULL;

        struct test_event *event = xzalloc(sizeof(*event));
        struct exchg_test_event *ev = &event->event;
        event->conn_type = CONN_TYPE_WS;
        event->conn.ws = ws;
        ev->id = exchange;
        ev->type = EXCHG_EVENT_WS_PREP;
        TAILQ_INSERT_HEAD(&ctx->events, event, list);
        ws->host = xstrdup(host);
        ws->path = xstrdup(path);
        ws->id = exchange;
        return ws;
}

decimal_t *exchg_test_balances(struct exchg_net_context *ctx, enum exchg_id id)
{
        return ctx->servers[id].balances;
}

struct auth_check *auth_check_alloc(size_t public_len,
                                    const unsigned char *public,
                                    size_t private_len,
                                    const unsigned char *private, int hmac_hex,
                                    enum hex_type type, const char *hmac_digest)
{
        struct auth_check *a = xzalloc(sizeof(*a));
        a->public_len = public_len;
        a->public = xzalloc(public_len);
        memcpy(a->public, public, public_len);

        if (hmac_ctx_alloc(&a->hmac_ctx, hmac_digest)) {
                fprintf(stderr, "%s: hmac alloc failure!\n", __func__);
                exit(1);
        }
        if (hmac_ctx_setkey(&a->hmac_ctx, private, private_len)) {
                fprintf(stderr, "%s: hmac set key failure!\n", __func__);
                exit(1);
        }
        a->hmac_hex = hmac_hex;
        a->hex_type = type;
        a->apikey_status = AUTH_UNSET;
        a->hmac_status = AUTH_UNSET;
        return a;
}

void auth_check_free(struct auth_check *a)
{
        free(a->hmac);
        free(a->payload);
        free(a->public);
        hmac_ctx_free(&a->hmac_ctx);
        free(a);
}

static void hmac_verify(struct auth_check *a)
{
        if (a->apikey_status != AUTH_GOOD || !a->payload || !a->hmac)
                return;

        char hmac[HMAC_TEXT_LEN_MAX];
        size_t hmac_len;
        int err;
        if (a->hmac_hex)
                err = hmac_ctx_hex(&a->hmac_ctx, a->payload, a->payload_len,
                                   hmac, &hmac_len, a->hex_type);
        else
                err = hmac_ctx_b64(&a->hmac_ctx, a->payload, a->payload_len,
                                   hmac, &hmac_len);
        if (err) {
                fprintf(stderr, "hmac failure!\n");
                exit(1);
        }
        if (hmac_len != a->hmac_len || memcmp(hmac, a->hmac, hmac_len)) {
                a->hmac_status = AUTH_BAD;
                return;
        }
        a->hmac_status = AUTH_GOOD;
}

void auth_check_set_public(struct auth_check *a, const unsigned char *c,
                           size_t len)
{
        if (len != a->public_len || memcmp(c, a->public, a->public_len))
                a->apikey_status = AUTH_BAD;
        else
                a->apikey_status = AUTH_GOOD;
        hmac_verify(a);
}

void auth_check_set_payload(struct auth_check *a, const unsigned char *c,
                            size_t len)
{
        a->payload = xdupwithnull(c, len);
        a->payload_len = len;
        hmac_verify(a);
}

void auth_check_set_hmac(struct auth_check *a, const unsigned char *c,
                         size_t len)
{
        a->hmac = (char *)xdupwithnull(c, len);
        a->hmac_len = len;
        hmac_verify(a);
}
