// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <time.h>

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

const char *exchg_test_event_to_str(enum exchg_test_event_type type)
{
        switch (type) {
        case EXCHG_EVENT_HTTP_ESTABLISHED:
                return "HTTP_ESTABLISHED";
        case EXCHG_EVENT_WS_ESTABLISHED:
                return "WS_ESTABLISHED";
        case EXCHG_EVENT_BOOK_UPDATE:
                return "BOOK_UPDATE";
        case EXCHG_EVENT_ORDER_PLACED:
                return "ORDER_PLACED";
        case EXCHG_EVENT_ORDER_EDITED:
                return "ORDER_EDITED";
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
        case EXCHG_EVENT_FROM_FILE:
                return "FROM_FILE";
        default:
                return "<Unknown Type : Internal Error>";
        }
}

static bool set_ws_if_matches(struct test_event *ev, struct websocket_conn *ws)
{
        bool ws_set = false;
        if (!ev->conn.ws && ev->conn_type == CONN_TYPE_WS &&
            ws->id == ev->event.id && ws->established) {
                switch (ev->event.type) {
                case EXCHG_EVENT_WS_ESTABLISHED:
                        ws_set = ws->conn_id ==
                                 ev->event.data.ws_established.conn_id;
                        break;
                case EXCHG_EVENT_WS_CLOSE:
                        ws_set = ws->conn_id == ev->event.data.ws_close.conn_id;
                        break;
                default:
                        ws_set = ws->matches(ws, &ev->event);
                }
        }
        if (ws_set)
                ev->conn.ws = ws;
        return ws_set;
}

static void find_matching_ws(struct exchg_net_context *ctx,
                             struct test_event *ev)
{
        struct websocket_conn *ws;
        LIST_FOREACH(ws, &ctx->ws_list, list)
        {
                if (set_ws_if_matches(ev, ws))
                        break;
        }
}

int tree_print_events(void *key, void *value, void *data)
{
        struct test_event *e = key;
        fprintf(stderr, "timestamp: %" PRId64 ": %s, ", e->timestamp,
                exchg_test_event_to_str(e->event.type));
        return false;
}

static void print_events(struct test_events *events)
{
        fprintf(stderr,
                "TEST EVENTS: current time %" PRId64 " num events: %d:\n",
                events->current_time, g_tree_nnodes(events->events));
        g_tree_foreach(events->events, tree_print_events, NULL);
        fprintf(stderr, "\n");
}

static void next_event_time(struct test_events *events, int64_t *timestamp)
{
        int64_t ms_20 = 20000;
        events->next_time += ms_20;
        *timestamp = events->next_time;
}

static void advance_clock(struct test_events *events, int64_t current)
{
        events->current_time = current;
        if (current > events->next_time)
                events->next_time = current;
}

static struct test_event *ws_event_alloc(struct exchg_net_context *ctx,
                                         struct websocket_conn *w,
                                         enum exchg_id id,
                                         enum exchg_test_event_type type,
                                         size_t private_size)
{
        struct test_events *events = &ctx->events;
        struct test_event *e = xzalloc(sizeof(*e) + private_size);

        next_event_time(events, &e->timestamp);
        e->moveable =
            type == EXCHG_EVENT_BOOK_UPDATE || type == EXCHG_EVENT_FROM_FILE;
        e->conn_type = CONN_TYPE_WS;
        e->event.type = type;
        e->event.id = id;
        if (w) {
                e->conn.ws = w;
        } else {
                find_matching_ws(ctx, e);
        }
        g_tree_insert(events->events, e, NULL);
        events->seq++;
        return e;
}

static struct test_event *http_event_alloc(struct exchg_net_context *ctx,
                                           struct http_conn *h,
                                           enum exchg_test_event_type type,
                                           size_t private_size)
{
        struct test_events *events = &ctx->events;
        struct test_event *e = xzalloc(sizeof(*e) + private_size);

        next_event_time(events, &e->timestamp);

        e->conn_type = CONN_TYPE_HTTP;
        e->conn.http = h;
        e->event.id = h->id;
        e->event.type = type;
        g_tree_insert(events->events, e, NULL);
        events->seq++;
        return e;
}

void exchg_test_add_events(struct exchg_net_context *ctx, int n,
                           struct exchg_test_event *events)
{
        for (int i = 0; i < n; i++) {
                if (events[i].type != EXCHG_EVENT_BOOK_UPDATE &&
                    events[i].type != EXCHG_EVENT_WS_CLOSE &&
                    events[i].type != EXCHG_EVENT_FROM_FILE) {
                        fprintf(
                            stderr,
                            "only can add json file, websocket close and book "
                            "updates for now\n");
                        continue;
                }
                struct test_event *e =
                    ws_event_alloc(ctx, NULL, events[i].id, events[i].type, 0);
                memcpy(&e->event, &events[i], sizeof(events[i]));
        }
}

// TODO: void ret
int exchg_test_l2_queue_order(struct exchg_test_l2_updates *u, bool is_bid,
                              const decimal_t *price, const decimal_t *size)
{
        if (is_bid) {
                if (u->num_bids >= u->bid_cap) {
                        int new_cap = u->bid_cap * 2 + 1;
                        struct exchg_test_l2_update *bids =
                            xzrealloc(u->bids, sizeof(*u->bids) * u->bid_cap,
                                      sizeof(*u->bids) * new_cap);
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
                            xzrealloc(u->asks, sizeof(*u->asks) * u->ask_cap,
                                      sizeof(*u->asks) * new_cap);
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
                struct test_event *event = ws_event_alloc(
                    ctx, NULL, o->id, EXCHG_EVENT_BOOK_UPDATE, 0);
                struct exchg_test_event *e = &event->event;

                e->data.book.pair = o->pair;

                for (struct exchg_test_str_l2_update *s = &o->bids[0]; s->price;
                     s++) {
                        decimal_t price, size;
                        decimal_from_str(&price, s->price);
                        decimal_from_str(&size, s->size);
                        exchg_test_l2_queue_order(&e->data.book, true, &price,
                                                  &size);
                }
                for (struct exchg_test_str_l2_update *s = &o->asks[0]; s->price;
                     s++) {
                        decimal_t price, size;
                        decimal_from_str(&price, s->price);
                        decimal_from_str(&size, s->size);
                        exchg_test_l2_queue_order(&e->data.book, false, &price,
                                                  &size);
                }
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

int64_t test_event_timestamp(struct exchg_test_event *event)
{
        return test_event_container(event)->timestamp;
}

struct exchg_test_event *
exchg_fake_queue_ws_event(struct websocket_conn *w,
                          enum exchg_test_event_type type, size_t private_size)
{
        struct test_event *event =
            ws_event_alloc(w->ctx, w, w->id, type, private_size);

        return &event->event;
}

static int test_event_cmp(const void *k1, const void *k2)
{
        const struct test_event *event1 = k1;
        const struct test_event *event2 = k2;

        if (k1 == k2)
                return 0;

        if (event1->timestamp < event2->timestamp)
                return -1;
        if (event1->timestamp > event2->timestamp)
                return 1;

        if (k1 < k2)
                return -1;
        if (k1 > k2)
                return 1;
        return 0;
}

static void test_event_free(struct test_event *ev)
{
        if (ev->event.type == EXCHG_EVENT_BOOK_UPDATE) {
                free(ev->event.data.book.bids);
                free(ev->event.data.book.asks);
        }
        free(ev);
}

static void test_events_new(struct test_events *events)
{
        events->events = g_tree_new(test_event_cmp);
        time_t t = time(NULL);
        events->current_time = t * 1000000;
        events->next_time = events->current_time;
}

int tree_collect_events(void *key, void *value, void *data)
{
        GPtrArray *to_free = data;
        g_ptr_array_add(to_free, key);
        return false;
}

static void free_event(struct test_events *events, struct test_event *ev)
{
        events->seq++;
        g_tree_remove(events->events, ev);
        test_event_free(ev);
}

static void test_events_free(struct test_events *events)
{
        GPtrArray *to_free =
            g_ptr_array_sized_new(g_tree_nnodes(events->events));
        g_tree_foreach(events->events, tree_collect_events, to_free);
        for (int i = 0; i < to_free->len; i++) {
                free_event(events, g_ptr_array_index(to_free, i));
        }
        g_ptr_array_unref(to_free);
        g_tree_unref(events->events);
}

struct exchg_net_context *net_new(struct net_callbacks *c, void *arg)
{
        const struct exchg_test_options *options = arg;
        struct exchg_net_context *ctx = xzalloc(sizeof(*ctx));
        if (options)
                memcpy(&ctx->options, options, sizeof(*options));
        test_events_new(&ctx->events);
        LIST_INIT(&ctx->ws_list);
        LIST_INIT(&ctx->http_list);
        ctx->callbacks = c;
        ctx->servers[EXCHG_COINBASE].fill_order = coinbase_fill_order;
        return ctx;
}

bool on_order_edited(struct exchg_net_context *ctx, enum exchg_id id,
                     struct test_order *o, const decimal_t *new_price,
                     const decimal_t *new_size)
{
        struct exchg_test_event event = {
            .id = id,
            .type = EXCHG_EVENT_ORDER_EDITED,
            .data.order_edited =
                {
                    .id = o->info.id,
                    .new_price = new_price,
                    .new_size = new_size,
                },
        };

        if (ctx->options.event_cb)
                ctx->options.event_cb(ctx, &event, ctx->options.callback_user);

        return !event.data.order_edited.error;
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
                    .avg_price = ack->order.price,
                },
        };
        struct exchg_test_order_placed *placed = &event.data.order_placed;
        if (ctx->options.event_cb)
                ctx->options.event_cb(ctx, &event, ctx->options.callback_user);

        ack->filled_size = placed->fill_size;
        ack->avg_price = placed->avg_price;
        if (placed->error) {
                ack->status = EXCHG_ORDER_ERROR;
        } else if (decimal_cmp(&placed->fill_size, &ack->order.size) >= 0) {
                ack->status = EXCHG_ORDER_FINISHED;
        } else {
                if (decimal_is_zero(&placed->fill_size))
                        decimal_zero(&ack->avg_price);
                if (ack->opts.immediate_or_cancel)
                        ack->status = EXCHG_ORDER_CANCELED;
                else
                        ack->status = EXCHG_ORDER_OPEN;
        }

        // TODO: decide what to do if the user changes the exchange. Would be
        // weird but might be a valid thing to test. For now we dont even check
        // it.
        ack->id = placed->id;

        struct test_order *t = xzalloc(sizeof(*t) + private_size);
        t->info = *ack;
        LIST_INSERT_HEAD(&ctx->servers[id].order_list, t, list);
        return t;
}

int exchg_test_fill_order(struct exchg_net_context *ctx, enum exchg_id id,
                          int64_t order_id, const decimal_t *total_fill)
{
        struct test_order *o, *order = NULL;
        LIST_FOREACH(o, &ctx->servers[id].order_list, list)
        {
                if (o->info.id == order_id) {
                        order = o;
                        break;
                }
        }
        if (!order) {
                exchg_log("test: %s: order ID %" PRId64 " on %s not found\n",
                          __func__, order_id, exchg_id_to_name(id));
                return -1;
        }
        if (decimal_cmp(total_fill, &order->info.filled_size) <= 0) {
                exchg_log("test: %s: order ID %" PRId64
                          " on %s already filled more than requested amount\n",
                          __func__, order_id, exchg_id_to_name(id));
                return -1;
        }
        int cmp = decimal_cmp(total_fill, &order->info.order.size);
        if (cmp > 0) {
                exchg_log("test: %s: truncating filled amount greater "
                          "than total order size.\n",
                          __func__);
                order->info.filled_size = order->info.order.size;
        } else {
                order->info.filled_size = *total_fill;
        }
        if (cmp >= 0) {
                order->info.status = EXCHG_ORDER_FINISHED;
        }

        struct test_server *server = &ctx->servers[id];
        if (server->fill_order)
                return server->fill_order(ctx, order, total_fill);

        struct test_event *e =
            ws_event_alloc(ctx, NULL, id, EXCHG_EVENT_ORDER_ACK, 0);

        e->event.data.order_ack = o->info;
        return 0;
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
        if (ctx->options.event_cb)
                ctx->options.event_cb(ctx, &event, ctx->options.callback_user);
        if (event.data.order_canceled.succeed)
                o->info.status = EXCHG_ORDER_CANCELED;
        return event.data.order_canceled.succeed;
}

struct timer {
        void (*f)(void *);
        void *p;
        struct exchg_net_context *ctx;
};

static void orphan_ws_event(struct exchg_net_context *ctx, struct test_event *e)
{
        struct test_events *events = &ctx->events;
        g_tree_remove(events->events, e);
        if (!e->moveable || e->seq == events->seq) {
                exchg_log("test: dropping event with no matching websocket:\n"
                          "%s: %s\n",
                          exchg_id_to_name(e->event.id),
                          exchg_test_event_to_str(e->event.type));
                test_event_free(e);
                return;
        }
        e->seq = events->seq;
        next_event_time(events, &e->timestamp);
        g_tree_insert(events->events, e, NULL);
}

struct find_orphaned_ws {
        struct websocket_conn *wsock;
        GPtrArray *orphaned_events;
};

int tree_orphaned_events(void *key, void *value, void *data)
{
        struct find_orphaned_ws *find = data;
        struct test_event *e = key;
        if (e->conn_type == CONN_TYPE_WS && e->conn.ws == find->wsock)
                g_ptr_array_add(find->orphaned_events, e);
        return false;
}

static void free_websocket(struct exchg_net_context *ctx,
                           struct websocket_conn *w)
{
        struct test_events *events = &ctx->events;
        struct websocket_conn_callbacks *ws = &ctx->callbacks->ws;

        struct find_orphaned_ws find = {
            .wsock = w,
            .orphaned_events =
                g_ptr_array_sized_new(g_tree_nnodes(events->events)),
        };
        g_tree_foreach(events->events, tree_orphaned_events, &find);
        for (int i = 0; i < find.orphaned_events->len; i++) {
                free_event(events, g_ptr_array_index(find.orphaned_events, i));
        }
        g_ptr_array_unref(find.orphaned_events);

        LIST_REMOVE(w, list);
        ws->on_closed(w->user);
        w->destroy(w);
}

static struct test_event *next_event(struct exchg_net_context *ctx)
{
        struct test_event *ev = NULL;
        GTreeNode *first = g_tree_node_first(ctx->events.events);

        if (first)
                ev = g_tree_node_key(first);

        if (ctx->options.event_cb)
                ctx->options.event_cb(ctx, ev ? &ev->event : NULL,
                                      ctx->options.callback_user);

        if (!ev) {
                first = g_tree_node_first(ctx->events.events);
                if (first) {
                        ev = g_tree_node_key(first);
                        if (ctx->options.event_cb)
                                ctx->options.event_cb(
                                    ctx, &ev->event,
                                    ctx->options.callback_user);
                }
        }
        if (ev)
                advance_clock(&ctx->events, ev->timestamp);
        return ev;
}

static bool service(struct exchg_net_context *ctx)
{
        int ret;
        struct buf buf;
        struct exchg_test_event *event = NULL;
        struct websocket_conn_callbacks *ws = &ctx->callbacks->ws;
        struct http_callbacks *http = &ctx->callbacks->http;
        struct http_conn *http_conn;
        struct websocket_conn *wsock;
        char *body;
        size_t body_len;

        struct test_event *ev = next_event(ctx);
        if (!ev) {
                exchg_log("test: no events left to service\n");
                return false;
        }
        event = &ev->event;

        switch (ev->conn_type) {
        case CONN_TYPE_WS:
                wsock = ev->conn.ws;
                if (!wsock) {
                        find_matching_ws(ctx, ev);
                        wsock = ev->conn.ws;
                }
                if (!wsock) {
                        orphan_ws_event(ctx, ev);
                        return true;
                }
                switch (event->type) {
                case EXCHG_EVENT_WS_ESTABLISHED:
                        ws->on_established(wsock->user);
                        wsock->established = true;
                        break;
                case EXCHG_EVENT_WS_CLOSE:
                        free_event(&ctx->events, ev);
                        free_websocket(ctx, wsock);
                        return true;
                case EXCHG_EVENT_FROM_FILE:
                        buf_init(&buf, 1 << 10);
                        if (!buf_read_file(&buf,
                                           event->data.from_file.filename)) {
                                if (ws->recv(wsock->user, buf_start(&buf),
                                             buf.len))
                                        ws_conn_close(wsock);
                        } else {
                                fprintf(stderr,
                                        "test: skipping FROM_FILE event (%s) "
                                        "due to read error",
                                        event->data.from_file.filename);
                        }
                        break;
                default:
                        buf_init(&buf, 1 << 10);
                        wsock->read(wsock, &buf, event);
                        if (ws->recv(wsock->user, buf_start(&buf), buf.len))
                                ws_conn_close(wsock);
                        buf_free(&buf);
                        break;
                }
                break;
        case CONN_TYPE_HTTP:
                // ->conn.http should be valid beacause no other events are
                // queued after EXCHG_EVENT_HTTP_CLOSE, since http_event_alloc()
                // is only called for other event types in
                // fake_http_conn_alloc() on dialing. If that changes, do
                // something like free_websocket()
                http_conn = ev->conn.http;
                switch (event->type) {
                case EXCHG_EVENT_HTTP_ESTABLISHED:
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
                            exchg_test_event_to_str(event->type));
                        break;
                }
                struct timer *t = test_event_private(event);
                t->f(t->p);
                break;
        }
        free_event(&ctx->events, ev);
        return true;
}

bool net_service(struct exchg_net_context *ctx) { return service(ctx); }

void timer_cancel(struct timer *t)
{
        // can I copy the linux container_of() macro? can't put GPL stuff in
        // this MIT licenced code but it's so small... better safe than sorry
        struct test_event *e =
            (struct test_event
                 *)((void *)t - (void *)&((struct test_event *)NULL)->private);
        free_event(&t->ctx->events, e);
}

struct timer *timer_new(struct exchg_net_context *ctx, void (*f)(void *),
                        void *p, int seconds)
{
        struct test_events *events = &ctx->events;
        struct test_event *e = xzalloc(sizeof(*e) + sizeof(struct timer));

        e->timestamp = events->current_time + seconds * 1000000;
        e->conn_type = CONN_TYPE_NONE;
        e->event.id = -1;
        e->event.type = EXCHG_EVENT_TIMER;

        struct timer *t = (struct timer *)e->private;
        t->f = f;
        t->p = p;
        t->ctx = ctx;
        g_tree_insert(events->events, e, NULL);
        events->seq++;
        return t;
}

void net_run(struct exchg_net_context *ctx)
{
        ctx->running = true;
        while (ctx->running && service(ctx)) {
        }

        if (g_tree_nnodes(ctx->events.events) > 0) {
                exchg_log("test: net_stop() called with events left!:\n");
                print_events(&ctx->events);
        }
}

void net_stop(struct exchg_net_context *ctx) { ctx->running = false; }

void net_destroy(struct exchg_net_context *ctx)
{
        struct http_conn *h, *htmp;
        struct websocket_conn *w, *wtmp;
        struct test_order *o, *otmp;

        test_events_free(&ctx->events);
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

        req->id = exchange;
        req->status = 200;
        req->user = private;
        req->ctx = ctx;

        http_event_alloc(ctx, req, EXCHG_EVENT_HTTP_ESTABLISHED, 0);
        req->read_event = &http_event_alloc(ctx, req, type, 0)->event;

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
        if (http->closed)
                return;

        http->closed = true;
        http_event_alloc(http->ctx, http, EXCHG_EVENT_HTTP_CLOSE, 0);
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
        if (ws->closed)
                return;
        ws->closed = true;

        struct test_event *e =
            ws_event_alloc(ws->ctx, ws, ws->id, EXCHG_EVENT_WS_CLOSE, 0);

        struct exchg_test_websocket_event event_data = {
            .conn_id = ws->conn_id,
            .host = ws->host,
            .path = ws->path,
        };
        e->event.data.ws_close = event_data;
}

struct websocket_conn *fake_websocket_alloc(enum exchg_id id,
                                            struct exchg_net_context *ctx,
                                            void *user)
{
        struct websocket_conn *s = xzalloc(sizeof(*s));
        s->user = user;
        s->ctx = ctx;
        s->id = id;
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

        ws->host = xstrdup(host);
        ws->path = xstrdup(path);
        ws->id = exchange;
        ws->conn_id = ctx->next_conn_id++;

        struct test_event *e = ws_event_alloc(ws->ctx, ws, exchange,
                                              EXCHG_EVENT_WS_ESTABLISHED, 0);

        struct exchg_test_websocket_event event_data = {
            .conn_id = ws->conn_id,
            .host = host,
            .path = path,
        };
        e->event.data.ws_established = event_data;

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
                                   hmac, sizeof(hmac), &hmac_len, a->hex_type);
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
