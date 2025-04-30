// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#include <glib.h>
#include <jsmn/jsmn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "auth.h"
#include "exchg/exchg.h"
#include "fake-gemini.h"
#include "fake-net.h"
#include "json-helpers.h"
#include "net-backend.h"
#include "util.h"

struct gemini_websocket {
        enum exchg_pair pair;
        int sequence;
        int first_sent;
};

static void gemini_write_orders(struct buf *buf, struct gemini_websocket *g,
                                struct exchg_test_l2_updates *up,
                                enum exchg_side side)
{
        struct exchg_test_l2_update *orders;
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
                buf_xsprintf(buf,
                             "{\"type\": \"change\", \"reason\": \"%s\""
                             ", \"price\": \"%s\", "
                             "\"remaining\": \"%s\", \"side\": \"%s\"}, ",
                             reason, price, size, sidestr);
        }
}

static int get_counter(void)
{
        static int x;
        return ++x;
}

static void gemini_ws_read(struct websocket_conn *ws, struct buf *buf,
                           struct exchg_test_event *msg)
{
        struct gemini_websocket *g = ws->priv;
        buf_xsprintf(buf,
                     "{\"type\": \"update\", \"event_id\": %d, "
                     "\"socket_sequence\": %d, \"events\": [",
                     get_counter(), g->sequence++);
        gemini_write_orders(buf, g, &msg->data.book, EXCHG_SIDE_BUY);
        gemini_write_orders(buf, g, &msg->data.book, EXCHG_SIDE_SELL);
        buf_xsprintf(buf, "]}");
}

static void gemini_ws_destroy(struct websocket_conn *w)
{
        free(w->priv);
        ws_conn_free(w);
}

static int gemini_ws_matches(struct websocket_conn *w,
                             struct exchg_test_event *ev)
{
        struct gemini_websocket *g = w->priv;
        if (ev->type == EXCHG_EVENT_BOOK_UPDATE) {
                return g->pair == ev->data.book.pair;
        }
        return 0;
}

enum order_event_type {
        ORDER_ACCEPTED,
        ORDER_REJECTED,
        ORDER_BOOKED,
        ORDER_FILL,
        ORDER_CANCELLED,
        ORDER_CLOSED,
};

struct gemini_ack {
        enum order_event_type type;
        int64_t client_oid;
};

static void events_read(struct websocket_conn *ws, struct buf *buf,
                        struct exchg_test_event *msg)
{
        if (msg->type == EXCHG_EVENT_WS_PROTOCOL) {
                // there are more fields but we just parse this for now so
                // whatever
                buf_xsprintf(buf, "{\"type\": \"subscription_ack\"}");
                return;
        }
        if (msg->type != EXCHG_EVENT_ORDER_ACK) {
                exchg_log("Gemini test: don't know what to do with order event "
                          "type %d"
                          " on order events websocket",
                          msg->type);
                return;
        }

        struct exchg_order_info *ack = &msg->data.order_ack;
        struct gemini_ack *g = test_event_private(msg);
        const char *type = "";
        const char *is_live = "true";
        const char *reason = "";

        switch (g->type) {
        case ORDER_ACCEPTED:
                type = "accepted";
                break;
        case ORDER_REJECTED:
                type = "rejected";
                is_live = "false";
                reason = "\"reason\": \"TestErrorBadThingHappened\"";
                break;
        case ORDER_BOOKED:
                type = "booked";
                break;
        case ORDER_FILL:
                type = "fill";
                break;
        case ORDER_CANCELLED:
                type = "cancelled";
                is_live = "false";
                break;
        case ORDER_CLOSED:
                type = "closed";
                is_live = "false";
                break;
        }
        char size[30];

        decimal_to_str(size, &ack->filled_size);
        buf_xsprintf(buf,
                     "[{\"type\": \"%s\", \"executed_amount\": \"%s\", "
                     "\"client_order_id\": %" PRId64
                     ", \"order_id\": \"%" PRId64 "\", \"is_live\": %s, %s}]",
                     type, size, g->client_oid, ack->id, is_live, reason);
}

static int events_matches(struct websocket_conn *w, struct exchg_test_event *ev)
{
        return 0;
}

struct websocket_conn *order_events_dial(struct exchg_net_context *ctx,
                                         void *private)
{
        struct websocket_conn *s = fake_websocket_alloc(ctx, private);
        s->read = events_read;
        s->write = no_ws_write;
        s->matches = events_matches;
        s->destroy = ws_conn_free;
        exchg_fake_queue_ws_event(s, EXCHG_EVENT_WS_PROTOCOL, 0);
        return s;
}

struct websocket_conn *gemini_ws_dial(struct exchg_net_context *ctx,
                                      const char *path, void *private)
{
        if (!strcmp(path, "/v1/order/events"))
                return order_events_dial(ctx, private);

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

        struct websocket_conn *s = fake_websocket_alloc(ctx, private);
        s->read = gemini_ws_read;
        s->write = no_ws_write;
        s->matches = gemini_ws_matches;
        s->destroy = gemini_ws_destroy;
        struct gemini_websocket *g = xzalloc(sizeof(struct gemini_websocket));
        g->pair = pair;
        s->priv = g;
        return s;
}

static void balances_read(struct http_conn *req, struct exchg_test_event *ev,
                          struct buf *buf)
{
        struct auth_check *a = req->priv;

        if (a->hmac_status == AUTH_GOOD) {
                buf_xsprintf(buf, "[");
                for (enum exchg_currency c = 0; c < EXCHG_NUM_CCYS; c++) {
                        decimal_t *balance =
                            &req->ctx->servers[EXCHG_GEMINI].balances[c];
                        if (!decimal_is_positive(balance))
                                continue;
                        char s[30];
                        decimal_to_str(s, balance);
                        buf_xsprintf(
                            buf,
                            "{ \"type\": \"exchange\", \"currency\": \"%s\", "
                            "\"amount\": \"%s\", \"available\": \"%s\", "
                            "\"availableForWithdrawal\": \"%s\" }, ",
                            exchg_ccy_to_upper(c), s, s, s);
                }
                buf_xsprintf(buf, "]");
        } else if (a->hmac_status == AUTH_BAD) {
                buf_xsprintf(
                    buf,
                    "{ \"result\": \"error\", \"reason\": \"InvalidSignature\","
                    "\"message\": \"InvalidSignature\" }");
        } else {
                buf_xsprintf(buf, "{}");
        }
}

static void auth_add_header(struct auth_check *a, const unsigned char *name,
                            const unsigned char *val, size_t len)
{
        if (!strcmp((char *)name, "X-GEMINI-APIKEY:")) {
                auth_check_set_public(a, val, len);
        } else if (!strcmp((char *)name, "X-GEMINI-PAYLOAD:")) {
                auth_check_set_payload(a, val, len);
        } else if (!strcmp((char *)name, "X-GEMINI-SIGNATURE:")) {
                auth_check_set_hmac(a, val, len);
        }
}

static void balances_add_header(struct http_conn *req,
                                const unsigned char *name,
                                const unsigned char *val, size_t len)
{
        auth_add_header((struct auth_check *)req->priv, name, val, len);
}

static void balances_free(struct http_conn *req)
{
        auth_check_free((struct auth_check *)req->priv);
        fake_http_conn_free(req);
}

static struct http_conn *balances_dial(struct exchg_net_context *ctx,
                                       const char *path, const char *method,
                                       void *private)
{
        if (strcmp(method, "POST")) {
                fprintf(stderr, "Gemini bad method for %s: %s\n", path, method);
                return NULL;
        }

        struct http_conn *req = fake_http_conn_alloc(
            ctx, EXCHG_GEMINI, EXCHG_EVENT_BALANCES, private);
        req->read = balances_read;
        req->add_header = balances_add_header;
        req->write = no_http_write;
        req->destroy = balances_free;
        req->priv = auth_check_alloc(strlen(exchg_test_gemini_public),
                                     (unsigned char *)exchg_test_gemini_public,
                                     strlen(exchg_test_gemini_private),
                                     (unsigned char *)exchg_test_gemini_private,
                                     1, HEX_LOWER, "SHA384");
        return req;
}

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*x))

struct http_place_order {
        int64_t client_oid;
        struct auth_check *auth;
        jsmn_parser parser;
        jsmntok_t toks[200];
};

static void place_order_read(struct http_conn *req, struct exchg_test_event *ev,
                             struct buf *buf)
{
        struct http_place_order *p = req->priv;
        struct exchg_order_info *ack = &ev->data.order_ack;

        if (p->auth->hmac_status == AUTH_GOOD) {
                char price[30];
                char original_size[30];
                char remaining_size[30];
                char filled_size[30];
                decimal_t remaining;
                const char *is_live, *is_canceled;

                // TODO: EXCHG_ORDER_ERROR
                if (ack->status == EXCHG_ORDER_FINISHED ||
                    ack->status == EXCHG_ORDER_CANCELED)
                        is_live = "false";
                else
                        is_live = "true";
                if (ack->status == EXCHG_ORDER_CANCELED)
                        is_canceled = "true";
                else
                        is_canceled = "false";

                decimal_to_str(price, &ack->order.price);
                decimal_to_str(original_size, &ack->order.size);
                decimal_to_str(filled_size, &ack->filled_size);
                decimal_subtract(&remaining, &ack->order.size,
                                 &ack->filled_size);
                decimal_to_str(remaining_size, &remaining);
                buf_xsprintf(
                    buf,
                    "{ \"order_id\": \"%" PRId64 "\", \"id\": \"%" PRId64
                    "\", \"symbol\": \"%s\", "
                    "\"exchange\": \"gemini\", \"avg_execution_price\": \"%s\""
                    ", \"side\": \"%s\", \"type\": \"exchange limit\", "
                    "\"timestamp\": \"161"
                    "1872750\", \"timestampms\": 1611872750275, \"is_live\": "
                    "%s, \"i"
                    "s_cancelled\": %s, \"is_hidden\": false, \"was_forced\": "
                    "false"
                    ", \"executed_amount\": \"%s\", \"client_order_id\": "
                    "\"%" PRId64 "\", "
                    "\"options\": [ \"immediate-or-cancel\" ], \"price\": "
                    "\"%s\", "
                    "\"original_amount\": \"%s\", \"remaining_amount\": \"%s\" "
                    "}\n",
                    ack->id, ack->id, exchg_pair_to_str(ack->order.pair), price,
                    ack->order.side == EXCHG_SIDE_BUY ? "buy" : "sell", is_live,
                    is_canceled, filled_size, p->client_oid, price,
                    original_size, remaining_size);
        } else if (p->auth->hmac_status == AUTH_BAD) {
                buf_xsprintf(
                    buf,
                    "{ \"result\": \"error\", \"reason\": \"InvalidSignature\","
                    "\"message\": \"InvalidSignature\" }");
        } else {
                buf_xsprintf(buf, "{}");
        }
}

static void ack_init(struct exchg_test_event *ev, enum order_event_type type,
                     struct test_order *order, int64_t client_oid)
{
        struct exchg_order_info *ack = &ev->data.order_ack;
        struct gemini_ack *g = test_event_private(ev);
        memcpy(ack, &order->info, sizeof(order->info));

        g->type = type;
        g->client_oid = client_oid;

        switch (type) {
        case ORDER_ACCEPTED:
                decimal_zero(&ack->filled_size);
                ack->status = EXCHG_ORDER_PENDING;
                break;
        case ORDER_REJECTED:
                decimal_zero(&ack->filled_size);
                ack->status = EXCHG_ORDER_ERROR;
                break;
        case ORDER_BOOKED:
        case ORDER_FILL:
                ack->status = EXCHG_ORDER_PENDING;
        case ORDER_CANCELLED:
        case ORDER_CLOSED:
                break;
        }
}

static void place_order_add_header(struct http_conn *req,
                                   const unsigned char *name,
                                   const unsigned char *val, size_t len)
{
        struct http_place_order *o = req->priv;
        struct exchg_order_info *ack = &req->read_event->data.order_ack;

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

        bool got_price = false;
        bool got_size = false;
        bool got_pair = false;
        bool got_side = false;

        int key_idx = 1;
        for (int i = 0; i < o->toks[0].size; i++) {
                jsmntok_t *key = &o->toks[key_idx];
                jsmntok_t *val = key + 1;

                if (json_streq(json, key, "client_order_id")) {
                        if (json_get_int64(&o->client_oid, json, val)) {
                                sprintf(problem, "bad order id");
                                goto bad;
                        }
                        key_idx += 2;
                } else if (json_streq(json, key, "symbol")) {
                        if (json_get_pair(&ack->order.pair, json, val)) {
                                sprintf(problem, "bad currency");
                                goto bad;
                        }
                        got_pair = true;
                        key_idx += 2;
                } else if (json_streq(json, key, "amount")) {
                        if (json_get_decimal(&ack->order.size, json, val)) {
                                sprintf(problem, "bad amount");
                                goto bad;
                        }
                        got_size = true;
                        key_idx += 2;
                } else if (json_streq(json, key, "price")) {
                        if (json_get_decimal(&ack->order.price, json, val)) {
                                sprintf(problem, "bad price");
                                goto bad;
                        }
                        got_price = true;
                        key_idx += 2;
                } else if (json_streq(json, key, "side")) {
                        if (json_streq(json, val, "buy")) {
                                ack->order.side = EXCHG_SIDE_BUY;
                        } else if (json_streq(json, val, "sell")) {
                                ack->order.side = EXCHG_SIDE_SELL;
                        } else {
                                sprintf(problem, "bad side");
                                goto bad;
                        }
                        got_side = true;
                        key_idx += 2;
                } else if (json_streq(json, key, "options")) {
                        if (val->type != JSMN_ARRAY) {
                                sprintf(problem, "bad options");
                                goto bad;
                        }
                        for (int j = 1; j <= val->size; j++) {
                                jsmntok_t *option = val + j;
                                if (json_streq(json, option,
                                               "immediate-or-cancel")) {
                                        ack->opts.immediate_or_cancel = true;
                                        break;
                                }
                        }
                } else {
                        // TODO: also parse immediate-or-cancel option
                        key_idx = json_skip(n, o->toks, key_idx + 1);
                }
        }
        if (o->client_oid == -1) {
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

        struct test_order *order =
            on_order_placed(req->ctx, EXCHG_GEMINI, ack, sizeof(int64_t));
        *(int64_t *)test_order_private(order) = o->client_oid;

        struct websocket_conn *ws =
            fake_websocket_get(req->ctx, "api.gemini.com", "/v1/order/events");
        if (!ws)
                return;

        struct exchg_test_event *accepted = exchg_fake_queue_ws_event(
            ws, EXCHG_EVENT_ORDER_ACK, sizeof(struct gemini_ack));
        struct exchg_test_event *last = exchg_fake_queue_ws_event_after(
            ws, EXCHG_EVENT_ORDER_ACK, sizeof(struct gemini_ack), accepted);

        ack_init(accepted, ORDER_ACCEPTED, order, o->client_oid);
        if (ack->status == EXCHG_ORDER_FINISHED)
                ack_init(last, ORDER_CLOSED, order, o->client_oid);
        else if (ack->status == EXCHG_ORDER_CANCELED)
                ack_init(last, ORDER_CANCELLED, order, o->client_oid);
        else if (ack->status == EXCHG_ORDER_ERROR)
                ack_init(last, ORDER_REJECTED, order, o->client_oid);
        else if (ack->status == EXCHG_ORDER_OPEN)
                ack_init(last, ORDER_BOOKED, order, o->client_oid);
        else {
                exchg_log(
                    "gemini test internal error: unexpected order status %d\n",
                    ack->status);
                exit(1);
        }
        if (ack->status != EXCHG_ORDER_ERROR &&
            decimal_is_positive(&ack->filled_size)) {
                struct exchg_test_event *fill = exchg_fake_queue_ws_event_after(
                    ws, EXCHG_EVENT_ORDER_ACK, sizeof(struct gemini_ack),
                    accepted);
                ack_init(fill, ORDER_FILL, order, o->client_oid);
        }
        return;

bad:
        fprintf(stderr, "%s: %s:\n", __func__, problem);
        fwrite(json, 1, len, stderr);
        fputc('\n', stderr);
        g_free(json);
}

static void place_order_free(struct http_conn *req)
{
        struct http_place_order *o = req->priv;
        auth_check_free(o->auth);
        free(o);
        fake_http_conn_free(req);
}

static struct http_conn *place_order_dial(struct exchg_net_context *ctx,
                                          const char *path, const char *method,
                                          void *private)
{
        if (strcmp(method, "POST")) {
                fprintf(stderr, "Gemini bad method for %s: %s\n", path, method);
                return NULL;
        }

        struct http_conn *req = fake_http_conn_alloc(
            ctx, EXCHG_GEMINI, EXCHG_EVENT_ORDER_ACK, private);
        req->read = place_order_read;
        req->add_header = place_order_add_header;
        req->write = no_http_write;
        req->destroy = place_order_free;

        struct http_place_order *o = xzalloc(sizeof(*o));
        o->auth = auth_check_alloc(strlen(exchg_test_gemini_public),
                                   (unsigned char *)exchg_test_gemini_public,
                                   strlen(exchg_test_gemini_private),
                                   (unsigned char *)exchg_test_gemini_private,
                                   1, HEX_LOWER, "SHA384");
        req->priv = o;
        return req;
}

struct cancel_order {
        struct auth_check *auth;
        char err[100];
};

static void cancel_order_read(struct http_conn *req,
                              struct exchg_test_event *ev, struct buf *buf)
{
        struct cancel_order *c = req->priv;
        if (c->auth->hmac_status == AUTH_GOOD) {
                if (c->err[0])
                        buf_xsprintf(
                            buf,
                            "{\"result\": \"error\", \"reason\": \"%s\","
                            " \"message\": \"%s\"}",
                            c->err, c->err);
                else
                        buf_xsprintf(buf, "{\"is_cancelled\":\"true\"}");
        } else if (c->auth->hmac_status == AUTH_BAD) {
                buf_xsprintf(
                    buf,
                    "{ \"result\": \"error\", \"reason\": \"InvalidSignature\","
                    "\"message\": \"InvalidSignature\" }");
        } else {
                buf_xsprintf(buf, "{}");
        }
}

static void cancel_order_add_header(struct http_conn *req,
                                    const unsigned char *name,
                                    const unsigned char *val, size_t len)
{
        struct cancel_order *cancel = req->priv;
        auth_add_header(cancel->auth, name, val, len);
        if (strcmp((char *)name, "X-GEMINI-PAYLOAD:"))
                return;

        const char *problem = "";
        jsmn_parser parser;
        jsmntok_t toks[100];
        char *json = (char *)g_base64_decode((char *)val, &len);

        jsmn_init(&parser);
        int n = jsmn_parse(&parser, json, len, toks, ARRAY_SIZE(toks));
        if (n < 1) {
                problem = "JSON parsing error";
                goto bad;
        }
        if (toks[0].type != JSMN_OBJECT) {
                problem = "non-object json";
                goto bad;
        }

        int64_t order_id = -1;
        int key_idx = 1;
        for (int i = 0; i < toks[0].size; i++) {
                jsmntok_t *key = &toks[key_idx];
                jsmntok_t *val = key + 1;

                if (json_streq(json, key, "order_id")) {
                        if (json_get_int64(&order_id, json, val)) {
                                problem = "bad order_id";
                                goto bad;
                        }
                }

                key_idx = json_skip(n, toks, key_idx + 1);
        }

        struct test_order *o;
        LIST_FOREACH(o, &req->ctx->servers[EXCHG_GEMINI].order_list, list)
        {
                if (o->info.id == order_id) {
                        if (decimal_cmp(&o->info.filled_size,
                                        &o->info.order.size) >= 0) {
                                req->status = 404;
                                snprintf(cancel->err, sizeof(cancel->err),
                                         "order id %" PRId64 " not recognized",
                                         order_id);
                        } else if (!on_order_canceled(req->ctx, EXCHG_GEMINI,
                                                      o)) {
                                req->status = 503;
                                snprintf(cancel->err, sizeof(cancel->err),
                                         "Service Unavailable");
                        } else {
                                if (o->info.status == EXCHG_ORDER_OPEN) {
                                        o->info.status = EXCHG_ORDER_CANCELED;
                                }
                                struct websocket_conn *ws = fake_websocket_get(
                                    req->ctx, "api.gemini.com",
                                    "/v1/order/events");
                                if (!ws)
                                        return;
                                struct exchg_test_event *cancel =
                                    exchg_fake_queue_ws_event(
                                        ws, EXCHG_EVENT_ORDER_ACK,
                                        sizeof(struct gemini_ack));
                                ack_init(cancel, ORDER_CANCELLED, o,
                                         *(int64_t *)test_order_private(o));
                                decimal_zero(
                                    &cancel->data.order_ack.filled_size);
                        }
                        g_free(json);
                        return;
                }
        }

        g_free(json);
        snprintf(cancel->err, sizeof(cancel->err),
                 "order id %" PRId64 " not recognized", order_id);
        req->status = 404;
        return;

bad:
        fprintf(stderr, "%s: %s:\n", __func__, problem);
        fwrite(json, 1, len, stderr);
        fputc('\n', stderr);
        g_free(json);
}

static void cancel_order_free(struct http_conn *req)
{
        struct cancel_order *c = req->priv;

        auth_check_free(c->auth);
        free(c);
        fake_http_conn_free(req);
}

static struct http_conn *cancel_order_dial(struct exchg_net_context *ctx,
                                           const char *path, const char *method,
                                           void *private)
{
        if (strcmp(method, "POST")) {
                fprintf(stderr, "Gemini bad method for %s: %s\n", path, method);
                return NULL;
        }

        struct http_conn *req = fake_http_conn_alloc(
            ctx, EXCHG_GEMINI, EXCHG_EVENT_ORDER_CANCEL_ACK, private);
        req->read = cancel_order_read;
        req->add_header = cancel_order_add_header;
        req->write = no_http_write;
        req->destroy = cancel_order_free;
        struct cancel_order *c = xzalloc(sizeof(*c));
        c->auth = auth_check_alloc(strlen(exchg_test_gemini_public),
                                   (unsigned char *)exchg_test_gemini_public,
                                   strlen(exchg_test_gemini_private),
                                   (unsigned char *)exchg_test_gemini_private,
                                   1, HEX_LOWER, "SHA384");
        req->priv = c;
        return req;
}

struct http_conn *gemini_http_dial(struct exchg_net_context *ctx,
                                   const char *path, const char *method,
                                   void *private)
{
        if (!strcmp(path, "/v1/balances"))
                return balances_dial(ctx, path, method, private);
        if (!strcmp(path, "/v1/order/new"))
                return place_order_dial(ctx, path, method, private);
        if (!strcmp(path, "/v1/order/cancel"))
                return cancel_order_dial(ctx, path, method, private);
        fprintf(stderr, "Gemini bad path: %s\n", path);
        return NULL;
}
