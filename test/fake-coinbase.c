// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#include <jsmn/jsmn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "exchg/exchg.h"
#include "fake-coinbase.h"
#include "fake-net.h"
#include "json-helpers.h"
#include "util.h"

extern char _binary_test_json_coinbase_products_json_start[];
extern char _binary_test_json_coinbase_products_json_end[];

static void products_read(struct http_conn *req, struct exchg_test_event *ev,
                          struct buf *buf)
{
        size_t size = _binary_test_json_coinbase_products_json_end -
                      _binary_test_json_coinbase_products_json_start;
        buf_xcpy(buf, _binary_test_json_coinbase_products_json_start, size);
}

static struct http_conn *products_dial(struct exchg_net_context *ctx,
                                       const char *path, const char *method,
                                       void *private)
{
        if (strcmp(method, "GET")) {
                fprintf(stderr, "Coinbase bad method for %s: %s\n", path,
                        method);
                return NULL;
        }

        struct http_conn *req = fake_http_conn_alloc(
            ctx, EXCHG_COINBASE, EXCHG_EVENT_PAIRS_DATA, private);
        req->read = products_read;
        req->write = no_http_write;
        req->add_header = no_http_add_header;
        req->destroy = fake_http_conn_free;
        return req;
}

static void accounts_read(struct http_conn *req, struct exchg_test_event *ev,
                          struct buf *buf)
{
        buf_xsprintf(buf, "[");
        for (enum exchg_currency c = 0; c < EXCHG_NUM_CCYS; c++) {
                char s[30];
                decimal_t *balance =
                    &req->ctx->servers[EXCHG_COINBASE].balances[c];
                decimal_to_str(s, balance);
                buf_xsprintf(
                    buf,
                    "{\"id\": \"234-abc-def%d\", \"currency\": \"%s\", "
                    "\"balance\": \"%s\", \"hold\": \"0.00\", \"available\": "
                    "\"%s\", "
                    "\"profile_id\": \"234-abc-zyx%d\", \"trading_enabled\": "
                    "true}, ",
                    c, exchg_ccy_to_upper(c), s, s, c);
        }
        buf_xsprintf(buf, "]");
}

static struct http_conn *accounts_dial(struct exchg_net_context *ctx,
                                       const char *path, const char *method,
                                       void *private)
{
        if (strcmp(method, "GET")) {
                fprintf(stderr, "Coinbase bad method for %s: %s\n", path,
                        method);
                return NULL;
        }

        struct http_conn *req = fake_http_conn_alloc(
            ctx, EXCHG_COINBASE, EXCHG_EVENT_BALANCES, private);
        req->read = accounts_read;
        req->write = no_http_write;
        // TODO: check auth stuff
        req->add_header = no_http_add_header;
        req->destroy = fake_http_conn_free;
        return req;
}

static const char *coinbase_pair_to_str(enum exchg_pair p)
{
        switch (p) {
        case EXCHG_PAIR_BTCUSD:
                return "BTC-USD";
        case EXCHG_PAIR_ETHUSD:
                return "ETH-USD";
        case EXCHG_PAIR_ETHBTC:
                return "ETH-BTC";
        case EXCHG_PAIR_ZECUSD:
                return "ZEC-USD";
        case EXCHG_PAIR_ZECBTC:
                return "ZEC-BTC";
        case EXCHG_PAIR_BCHUSD:
                return "BCH-USD";
        case EXCHG_PAIR_BCHBTC:
                return "BCH-BTC";
        case EXCHG_PAIR_LTCUSD:
                return "LTC-USD";
        case EXCHG_PAIR_LTCBTC:
                return "LTC-BTC";
        case EXCHG_PAIR_DAIUSD:
                return "DAI-USD";
        case EXCHG_PAIR_NEARUSD:
                return "NEAR-USD";
        default:
                return NULL;
        }
}

static int coinbase_str_to_pair(enum exchg_pair *dst, const char *json,
                                jsmntok_t *tok)
{
        if (json_streq(json, tok, "LTC-BTC")) {
                *dst = EXCHG_PAIR_LTCBTC;
                return 0;
        } else if (json_streq(json, tok, "BCH-BTC")) {
                *dst = EXCHG_PAIR_BCHBTC;
                return 0;
        } else if (json_streq(json, tok, "DAI-USD")) {
                *dst = EXCHG_PAIR_DAIUSD;
                return 0;
        } else if (json_streq(json, tok, "LTC-USD")) {
                *dst = EXCHG_PAIR_LTCUSD;
                return 0;
        } else if (json_streq(json, tok, "BTC-USD")) {
                *dst = EXCHG_PAIR_BTCUSD;
                return 0;
        } else if (json_streq(json, tok, "ETH-BTC")) {
                *dst = EXCHG_PAIR_ETHBTC;
                return 0;
        } else if (json_streq(json, tok, "ZEC-BTC")) {
                *dst = EXCHG_PAIR_ZECBTC;
                return 0;
        } else if (json_streq(json, tok, "ETH-USD")) {
                *dst = EXCHG_PAIR_ETHUSD;
                return 0;
        } else if (json_streq(json, tok, "ZEC-USD")) {
                *dst = EXCHG_PAIR_ZECUSD;
                return 0;
        } else if (json_streq(json, tok, "BCH-USD")) {
                *dst = EXCHG_PAIR_BCHUSD;
                return 0;
        } else if (json_streq(json, tok, "NEAR-USD")) {
                *dst = EXCHG_PAIR_NEARUSD;
                return 0;
        } else
                return -1;
}

struct order_ids {
        char server_oid[37];
        char client_oid[37];
};

static void orders_read(struct http_conn *req, struct exchg_test_event *ev,
                        struct buf *buf)
{
        struct order_ids *ids = req->priv;
        struct exchg_order_info *ack = &ev->data.order_ack;
        char cost_str[30], fee_str[30];
        char price_str[30], size_str[30];

        if (!ids->server_oid[0])
                return;

        write_prices(price_str, size_str, cost_str, fee_str, &ack->order.price,
                     &ack->order.size, 26, 6);
        buf_xsprintf(
            buf,
            "{\"id\": \"%s\", "
            "\"price\": \"%s\", \"size\": \"%s\", \"product_id\": \"%s\", "
            "\"side\": \"%s\", \"stp\": \"dc\", \"type\": \"limit\", "
            "\"time_in_force\": \"IOC\", \"post_only\": false, "
            "\"created_at\": \"2016-12-08T20:02:28.53864Z\","
            "\"fill_fees\": \"0\", \"filled_size\": \"0\", "
            "\"executed_value\": \"0\", \"status\": \"pending\", "
            "\"settled\": false }",
            ids->server_oid, price_str, size_str,
            coinbase_pair_to_str(ack->order.pair),
            ack->order.side == EXCHG_SIDE_BUY ? "buy" : "sell");
}

enum ack_type {
        ACK_DONE,
        ACK_OPEN,
        ACK_MATCH,
        ACK_RECV,
};

struct ack_msg {
        enum ack_type type;
        struct order_ids ids;
        struct test_order *order;
};

struct coinbase_websocket {
        struct coinbase_channel {
                bool l2_subbed;
                bool user_subbed;
                bool first_l2_sent;
        } channels[EXCHG_NUM_PAIRS];
        jsmn_parser parser;
        jsmntok_t toks[100];
};

static void ack_init(struct exchg_test_event *e, enum ack_type type,
                     struct test_order *o)
{
        struct ack_msg *ack = test_event_private(e);
        struct order_ids *ids = test_order_private(o);

        memcpy(&e->data.order_ack, &o->info, sizeof(o->info));

        ack->type = type;
        memcpy(&ack->ids, ids, sizeof(*ids));
        ack->order = o;
}

static void generate_order_acks(struct exchg_net_context *ctx,
                                struct exchg_test_event *read_event,
                                struct test_order *o)
{
        struct websocket_conn *ws =
            fake_websocket_get(ctx, "ws-feed.pro.coinbase.com", NULL);
        if (!ws)
                return;
        struct coinbase_websocket *cb = ws->priv;
        struct exchg_test_event *recvd = exchg_fake_queue_ws_event(
            ws, EXCHG_EVENT_ORDER_ACK, sizeof(struct ack_msg));

        ack_init(recvd, ACK_RECV, o);
        recvd->data.order_ack.status = EXCHG_ORDER_PENDING;
        decimal_zero(&recvd->data.order_ack.filled_size);

        if (!cb->channels[o->info.order.pair].user_subbed)
                return;

        struct exchg_test_event *last = exchg_fake_queue_ws_event(
            ws, EXCHG_EVENT_ORDER_ACK, sizeof(struct ack_msg));
        if (o->info.status == EXCHG_ORDER_FINISHED ||
            o->info.status == EXCHG_ORDER_CANCELED)
                ack_init(last, ACK_DONE, o);
        else if (o->info.status == EXCHG_ORDER_OPEN)
                ack_init(last, ACK_OPEN, o);
        else {
                exchg_log("Coinbase test: Don't know how to generate order "
                          "update with"
                          " status %d for now\n",
                          o->info.status);
                exit(1);
        }

        if (decimal_is_positive(&o->info.filled_size)) {
                struct exchg_test_event *match = exchg_fake_queue_ws_event(
                    ws, EXCHG_EVENT_ORDER_ACK, sizeof(struct ack_msg));
                ack_init(match, ACK_MATCH, o);
                match->data.order_ack.status = EXCHG_ORDER_PENDING;
        }
}

static void write_oid(char *dst, uint64_t id)
{
        char n[17];

        int len = sprintf(n, "%" PRIx64, id);
        dst += sprintf(dst, "00000000-0000-0000-");
        for (int i = 0; i < 4; i++) {
                char c = '0';
                if (len - 16 + i >= 0)
                        c = n[len - 16 + i];
                *dst = c;
                dst++;
        }
        *dst = '-';
        dst++;
        int i;
        for (i = 0; i < 12 - len; i++)
                dst += sprintf(dst, "0");
        int twelve_left = 0;
        if (len > 12)
                twelve_left = len - 12;
        memcpy(dst, &n[twelve_left], len - twelve_left);
        dst[len - twelve_left] = 0;
}

static void orders_write(struct http_conn *req, const char *body, size_t len)
{
        const char *problem = "";
        jsmn_parser parser;
        jsmntok_t toks[100];
        struct exchg_order_info *ack = &req->read_event->data.order_ack;

        if (len < 1) {
                fprintf(stderr, "no body given with POST to "
                                "https://api.pro.coinbase.com/orders\n");
                return;
        }

        jsmn_init(&parser);
        int num_toks = jsmn_parse(&parser, body, len, toks, 100);
        if (num_toks < 0) {
                problem = "could not parse JSON";
                goto bad;
        }
        if (toks[0].type != JSMN_OBJECT) {
                problem = "non-object JSON message";
                goto bad;
        }

        bool got_pair = false;
        bool got_price = false;
        bool got_size = false;
        bool got_side = false;

        jsmntok_t *client_oid = NULL;
        int key_idx = 1;
        for (int i = 0; i < toks[0].size; i++) {
                jsmntok_t *key = &toks[key_idx];
                jsmntok_t *value = key + 1;

                if (json_streq(body, key, "price")) {
                        if (json_get_decimal(&ack->order.price, body, value)) {
                                problem = "bad price";
                                goto bad;
                        }
                        got_price = true;
                } else if (json_streq(body, key, "size")) {
                        if (json_get_decimal(&ack->order.size, body, value)) {
                                problem = "bad size";
                                goto bad;
                        }
                        got_size = true;
                } else if (json_streq(body, key, "side")) {
                        if (json_streq(body, value, "buy"))
                                ack->order.side = EXCHG_SIDE_BUY;
                        else if (json_streq(body, value, "sell"))
                                ack->order.side = EXCHG_SIDE_SELL;
                        else {
                                problem = "bad side";
                                goto bad;
                        }
                        got_side = true;
                } else if (json_streq(body, key, "product_id")) {
                        if (coinbase_str_to_pair(&ack->order.pair, body,
                                                 value)) {
                                problem = "bad product_id";
                                goto bad;
                        }
                        got_pair = true;
                } else if (json_streq(body, key, "client_oid")) {
                        if (value->type != JSMN_STRING) {
                                problem = "bad client_oid";
                                goto bad;
                        }
                        if (value->end - value->start != 36) {
                                problem = "bad \"client_oid\"";
                                goto bad;
                        }
                        client_oid = value;
                } else if (json_streq(body, key, "time_in_force")) {
                        if (json_streq(body, value, "IOC"))
                                ack->opts.immediate_or_cancel = true;
                }

                key_idx = json_skip(num_toks, toks, key_idx + 1);
        }

        if (!got_pair) {
                problem = "missing product_id";
                goto bad;
        }
        if (!got_size) {
                problem = "missing size";
                goto bad;
        }
        if (!got_side) {
                problem = "missing side";
                goto bad;
        }
        if (!got_price) {
                problem = "missing price";
                goto bad;
        }

        struct test_order *o = on_order_placed(req->ctx, EXCHG_COINBASE, ack,
                                               sizeof(struct order_ids));
        if (!client_oid) {
                exchg_log(
                    "FIXME: Coinbase test code requires a \"client_oid\" to"
                    " be present for now, but received an order request "
                    "without one:\n");
                json_fprintln(stderr, body, &toks[0]);
                exit(1);
        }
        struct order_ids *ids = test_order_private(o);
        memcpy(ids->client_oid, &body[client_oid->start], 36);
        write_oid(ids->server_oid, ack->id);

        struct order_ids *req_ids = req->priv;
        memcpy(req_ids, ids, sizeof(*ids));
        generate_order_acks(req->ctx, req->read_event, o);
        return;

bad:
        fprintf(stderr, "%s: %s:\n", __func__, problem);
        fwrite(body, 1, len, stderr);
        fputc('\n', stderr);
}

static void orders_destroy(struct http_conn *req)
{
        free(req->priv);
        fake_http_conn_free(req);
}

static struct http_conn *orders_dial(struct exchg_net_context *ctx,
                                     const char *path, const char *method,
                                     void *private)
{
        if (strcmp(method, "POST")) {
                fprintf(stderr, "Coinbase bad method for %s: %s\n", path,
                        method);
                return NULL;
        }

        struct http_conn *req = fake_http_conn_alloc(
            ctx, EXCHG_COINBASE, EXCHG_EVENT_ORDER_ACK, private);
        req->read = orders_read;
        req->write = orders_write;
        // TODO: check auth stuff
        req->add_header = no_http_add_header;
        req->destroy = orders_destroy;
        req->priv = xzalloc(sizeof(struct order_ids));
        return req;
}

struct order_cancel {
        char client_oid[37];
        char msg[100];
};

static void cancel_order_read(struct http_conn *req,
                              struct exchg_test_event *ev, struct buf *buf)
{
        struct order_cancel *cancel = req->priv;

        if (cancel->msg[0]) {
                buf_xsprintf(buf, "{\"message\": \"%s\"}", cancel->msg);
        } else {
                buf_xsprintf(buf, "\"%s\"", cancel->client_oid);
        }
}

static void cancel_order_free(struct http_conn *req)
{
        free(req->priv);
        fake_http_conn_free(req);
}

static bool cancel_order(struct exchg_net_context *ctx, struct test_order *o)
{
        if (!on_order_canceled(ctx, EXCHG_COINBASE, o))
                return false;

        struct test_event *last = NULL;
        bool send_done = true;

        // TODO: check ongoing orders
        if (send_done) {
                struct websocket_conn *ws =
                    fake_websocket_get(ctx, "ws-feed.pro.coinbase.com", NULL);
                if (!ws)
                        return true;
                struct coinbase_websocket *cb = ws->priv;

                if (!cb->channels[o->info.order.pair].user_subbed)
                        return true;

                struct exchg_test_event *cancel;
                if (last)
                        cancel = exchg_fake_queue_ws_event(
                            ws, EXCHG_EVENT_ORDER_ACK, sizeof(struct ack_msg));
                else
                        cancel = exchg_fake_queue_ws_event(
                            ws, EXCHG_EVENT_ORDER_ACK, sizeof(struct ack_msg));
                ack_init(cancel, ACK_DONE, o);
                cancel->data.order_ack.status = EXCHG_ORDER_CANCELED;
        }
        return true;
}

static void cancel_order_write(struct http_conn *req, const char *body,
                               size_t len)
{
        struct order_cancel *cancel = req->priv;

        if (strlen(req->path) < strlen("/orders/client:") + 36) {
                req->status = 400;
                snprintf(cancel->msg, sizeof(cancel->msg), "Bad order id");
                return;
        }

        struct test_order *o;
        memcpy(cancel->client_oid, req->path + strlen("/orders/client:"), 36);
        cancel->client_oid[36] = 0;
        LIST_FOREACH(o, &req->ctx->servers[EXCHG_COINBASE].order_list, list)
        {
                struct order_ids *ids = test_order_private(o);
                if (!strcmp(cancel->client_oid, ids->client_oid)) {
                        if (decimal_cmp(&o->info.filled_size,
                                        &o->info.order.size) >= 0) {
                                req->status = 404;
                                snprintf(cancel->msg, sizeof(cancel->msg),
                                         "order id %s not recognized",
                                         ids->client_oid);
                        } else if (!cancel_order(req->ctx, o)) {
                                req->status = 503;
                                snprintf(cancel->msg, sizeof(cancel->msg),
                                         "Service Unavailable");
                        }
                        return;
                }
        }
        req->status = 400;
        snprintf(cancel->msg, sizeof(cancel->msg), "Unrecognized order id");
}

static struct http_conn *cancel_order_dial(struct exchg_net_context *ctx,
                                           const char *path, const char *method,
                                           void *private)
{
        if (strcmp(method, "DELETE")) {
                exchg_log("Coinbase bad method for %s: %s\n", path, method);
                return NULL;
        }

        struct order_cancel *cancel = xzalloc(sizeof(*cancel));
        struct http_conn *req = fake_http_conn_alloc(
            ctx, EXCHG_COINBASE, EXCHG_EVENT_ORDER_CANCEL_ACK, private);
        req->read = cancel_order_read;
        req->write = cancel_order_write;
        // TODO: check auth stuff
        req->add_header = no_http_add_header;
        req->destroy = cancel_order_free;
        req->priv = cancel;
        return req;
}

struct http_conn *coinbase_http_dial(struct exchg_net_context *ctx,
                                     const char *path, const char *method,
                                     void *private)
{
        if (!strcmp(path, "/products"))
                return products_dial(ctx, path, method, private);
        else if (!strcmp(path, "/accounts"))
                return accounts_dial(ctx, path, method, private);
        else if (!strcmp(path, "/orders"))
                return orders_dial(ctx, path, method, private);
        else if (!strncmp(path, "/orders/client:", strlen("/orders/client:")))
                return cancel_order_dial(ctx, path, method, private);
        else {
                exchg_log("Coinbase bad HTTP path: %s\n", path);
                return NULL;
        }
}

struct coinbase_proto {
        bool new_l2;
        bool new_user;
        bool new_l2_sub[EXCHG_NUM_PAIRS];
        bool new_user_sub[EXCHG_NUM_PAIRS];
};

static void proto_read(struct buf *buf, struct coinbase_proto *p)
{
        buf_xsprintf(buf, "{\"type\":\"subscriptions\",\"channels\":[");
        if (p->new_l2) {
                buf_xsprintf(buf, "{\"name\":\"level2\",\"product_ids\":[");
                for (enum exchg_pair pair = 0; pair < EXCHG_NUM_PAIRS; pair++) {
                        if (p->new_l2_sub[pair]) {
                                buf_xsprintf(buf, "\"%s\", ",
                                             coinbase_pair_to_str(pair));
                        }
                }
                buf_xsprintf(buf, "]}, ");
        }
        if (p->new_user) {
                buf_xsprintf(buf, "{\"name\":\"user\",\"product_ids\":[");
                for (enum exchg_pair pair = 0; pair < EXCHG_NUM_PAIRS; pair++) {
                        if (p->new_user_sub[pair]) {
                                buf_xsprintf(buf, "\"%s\", ",
                                             coinbase_pair_to_str(pair));
                        }
                }
                buf_xsprintf(buf, "]}, ");
        }
        buf_xsprintf(buf, "]}");
}

static void ack_read(struct buf *buf, struct exchg_test_event *msg)
{
        struct exchg_order_info *ack = &msg->data.order_ack;
        struct ack_msg *coinbase_ack = test_event_private(msg);
        const char *type_str;

        switch (coinbase_ack->type) {
        case ACK_DONE:
                type_str = "done";
                break;
        case ACK_OPEN:
                type_str = "open";
                break;
        case ACK_RECV:
                type_str = "received";
                break;
        case ACK_MATCH:
                type_str = "match";
                break;
        default:
                exchg_log("%s: bad type: %d\n", __func__, coinbase_ack->type);
                exit(1);
        }

        static int sequence;
        char cost_str[30], fee_str[30];
        char price_str[30], size_str[30];

        write_prices(price_str, size_str, cost_str, fee_str, &ack->order.price,
                     &ack->filled_size, 50, 6);

        buf_xsprintf(buf,
                     "{\"type\": \"%s\", \"side\": \"%s\", "
                     "\"product_id\": \"%s\", \"time\": "
                     "\"2021-08-31T13:13:28.295379Z\", "
                     "\"sequence\": \"%d\", \"profile_id\": \"1234-abc\", "
                     "\"user_id\": \"5678-def\", "
                     "",
                     type_str,
                     ack->order.side == EXCHG_SIDE_BUY ? "buy" : "sell",
                     coinbase_pair_to_str(ack->order.pair), sequence++);
        if (coinbase_ack->type == ACK_DONE || coinbase_ack->type == ACK_OPEN ||
            coinbase_ack->type == ACK_RECV) {
                buf_xsprintf(buf, "\"order_id\": \"%s\", ",
                             coinbase_ack->ids.server_oid);
        } else {
                buf_xsprintf(buf,
                             "\"trade_id\": \"%" PRId64 "\", "
                             "\"maker_order_id\": "
                             "\"00000000-abcd-0000-0000-abcdabcdabcd\", "
                             "\"taker_order_id\": \"%s\", ",
                             ack->id, coinbase_ack->ids.server_oid);
        }
        if (coinbase_ack->type == ACK_RECV) {
                buf_xsprintf(buf, "\"order_type\": \"limit\", ");
        }
        if (coinbase_ack->type == ACK_RECV || coinbase_ack->type == ACK_MATCH) {
                buf_xsprintf(buf, "\"size\": \"%s\", ", size_str);
        }
        buf_xsprintf(buf, "\"price\": \"%s\", ", price_str);

        if (coinbase_ack->type == ACK_MATCH) {
                buf_xsprintf(buf,
                             "\"taker_profile_id\": \"1234-abc\", "
                             "\"taker_user_id\": \"5678-def\", "
                             "\"taker_fee_rate\": \"%s\"",
                             fee_str);
        }
        if (coinbase_ack->type == ACK_DONE || coinbase_ack->type == ACK_OPEN) {
                if (ack->status == EXCHG_ORDER_FINISHED ||
                    ack->status == EXCHG_ORDER_CANCELED) {
                        const char *reason;
                        if (ack->status == EXCHG_ORDER_FINISHED)
                                reason = "filled";
                        else
                                reason = "canceled";
                        buf_xsprintf(buf, "\"reason\": \"%s\", ", reason);
                }
                char rem[30];
                decimal_t remaining;
                decimal_subtract(&remaining, &ack->order.size,
                                 &ack->filled_size);
                decimal_to_str(rem, &remaining);
                buf_xsprintf(buf, "\"remaining_size\": \"%s\",", rem);
        }
        if (coinbase_ack->type == ACK_RECV) {
                buf_xsprintf(buf, "\"client_oid\": \"%s\", ",
                             coinbase_ack->ids.client_oid);
        }
        buf_xsprintf(buf, "}");
}

static void ws_read(struct websocket_conn *ws, struct buf *buf,
                    struct exchg_test_event *msg)
{
        if (msg->type == EXCHG_EVENT_WS_PROTOCOL) {
                proto_read(buf,
                           (struct coinbase_proto *)test_event_private(msg));
                return;
        }
        if (msg->type == EXCHG_EVENT_ORDER_ACK) {
                ack_read(buf, msg);
                return;
        }
        if (msg->type != EXCHG_EVENT_BOOK_UPDATE)
                return;

        struct coinbase_websocket *cb = ws->priv;
        struct exchg_test_l2_updates *b = &msg->data.book;
        if (b->num_bids < 1 && b->num_asks < 1)
                return;
        const char *id = coinbase_pair_to_str(b->pair);
        if (!id)
                return;

        buf_xsprintf(
            buf, "{\"type\": \"%s\", \"product_id\": \"%s\", ",
            cb->channels[b->pair].first_l2_sent ? "l2update" : "snapshot", id);

        if (!cb->channels[b->pair].first_l2_sent) {
                cb->channels[b->pair].first_l2_sent = true;
                if (b->num_asks > 0)
                        buf_xsprintf(buf, "\"asks\":[");
                for (int i = 0; i < b->num_asks; i++) {
                        char price[30], size[30];
                        decimal_to_str(price, &b->asks[i].price);
                        decimal_to_str(size, &b->asks[i].size);
                        buf_xsprintf(buf, "[\"%s\",\"%s\"],", price, size);
                }
                if (b->num_asks > 0)
                        buf_xsprintf(buf, "], ");
                if (b->num_bids > 0)
                        buf_xsprintf(buf, "\"bids\":[");
                for (int i = 0; i < b->num_bids; i++) {
                        char price[30], size[30];
                        decimal_to_str(price, &b->bids[i].price);
                        decimal_to_str(size, &b->bids[i].size);
                        buf_xsprintf(buf, "[\"%s\",\"%s\"],", price, size);
                }
                if (b->num_bids > 0)
                        buf_xsprintf(buf, "]");
                buf_xsprintf(buf, "}");
        } else {
                buf_xsprintf(buf, "\"changes\":[");
                for (int i = 0; i < b->num_asks; i++) {
                        char price[30], size[30];
                        decimal_to_str(price, &b->asks[i].price);
                        decimal_to_str(size, &b->asks[i].size);
                        buf_xsprintf(buf, "[\"sell\",\"%s\",\"%s\"],", price,
                                     size);
                }
                for (int i = 0; i < b->num_bids; i++) {
                        char price[30], size[30];
                        decimal_to_str(price, &b->bids[i].price);
                        decimal_to_str(size, &b->bids[i].size);
                        buf_xsprintf(buf, "[\"buy\",\"%s\",\"%s\"],", price,
                                     size);
                }
                buf_xsprintf(buf,
                             "], \"time\": \"2021-08-02T13:18:40.348975Z\"}");
        }
}

static void ws_write(struct websocket_conn *w, const char *json, size_t len)
{
        struct coinbase_websocket *c = w->priv;
        const char *problem = "";

        jsmn_init(&c->parser);
        int r = jsmn_parse(&c->parser, json, len, c->toks, 100);
        if (r < 0) {
                problem = "could not parse JSON";
                goto bad;
        }
        if (c->toks[0].type != JSMN_OBJECT) {
                problem = "non-object JSON message";
                goto bad;
        }

        bool level2_global = false;
        bool user_global = false;
        bool global_pair[EXCHG_NUM_PAIRS];
        bool l2_pair_sub[EXCHG_NUM_PAIRS];
        bool user_pair_sub[EXCHG_NUM_PAIRS];

        memset(global_pair, 0, sizeof(l2_pair_sub));
        memset(l2_pair_sub, 0, sizeof(l2_pair_sub));
        memset(user_pair_sub, 0, sizeof(user_pair_sub));

        int key_idx = 1;
        for (int i = 0; i < c->toks[0].size; i++) {
                jsmntok_t *key = &c->toks[key_idx];
                jsmntok_t *value = key + 1;

                if (json_streq(json, key, "type")) {
                        if (!json_streq(json, value, "subscribe")) {
                                problem = "bad \"type\" field";
                                goto bad;
                        }
                        key_idx += 2;
                } else if (json_streq(json, key, "product_ids")) {
                        if (value->type != JSMN_ARRAY) {
                                problem = "non array product_ids";
                                goto bad;
                        }
                        jsmntok_t *product = value + 1;
                        for (int j = 0; j < value->size; j++, product++) {
                                enum exchg_pair pair;
                                if (coinbase_str_to_pair(&pair, json,
                                                         product)) {
                                        problem = "bad product_ids";
                                        goto bad;
                                }
                                global_pair[pair] = true;
                        }
                        key_idx = json_skip(r, c->toks, key_idx + 1);
                } else if (json_streq(json, key, "channels")) {
                        if (value->type != JSMN_ARRAY) {
                                problem = "non array \"channels\"";
                                goto bad;
                        }
                        key_idx += 2;
                        int n = value->size;
                        for (int j = 0; j < n; j++) {
                                jsmntok_t *channel = &c->toks[key_idx];

                                if (channel->type == JSMN_STRING) {
                                        if (json_streq(json, channel, "level2"))
                                                level2_global = true;
                                        else if (json_streq(json, channel,
                                                            "user"))
                                                user_global = true;
                                        key_idx++;
                                        continue;
                                }
                                if (channel->type != JSMN_OBJECT) {
                                        problem = "non object or string "
                                                  "\"channels\" element";
                                        goto bad;
                                }
                                bool parsing_level2 = false;
                                bool parsing_user = false;
                                bool pair_included[EXCHG_NUM_PAIRS];

                                memset(pair_included, 0, sizeof(pair_included));
                                key_idx++;
                                for (int k = 0; k < channel->size; k++) {
                                        key = &c->toks[key_idx];
                                        value = key + 1;

                                        if (json_streq(json, key, "name")) {
                                                if (json_streq(json, value,
                                                               "level2")) {
                                                        parsing_level2 = true;
                                                        parsing_user = false;
                                                } else if (json_streq(json,
                                                                      value,
                                                                      "user")) {
                                                        parsing_user = true;
                                                        parsing_level2 = false;
                                                } else {
                                                        problem =
                                                            "unknown channel "
                                                            "name";
                                                        goto bad;
                                                }
                                        } else if (json_streq(json, key,
                                                              "product_ids")) {
                                                if (value->type != JSMN_ARRAY) {
                                                        problem = "non array "
                                                                  "product_ids";
                                                        goto bad;
                                                }
                                                jsmntok_t *product = value + 1;
                                                for (int j = 0; j < value->size;
                                                     j++, product++) {
                                                        enum exchg_pair pair;
                                                        if (coinbase_str_to_pair(
                                                                &pair, json,
                                                                product)) {
                                                                problem =
                                                                    "bad "
                                                                    "channels:"
                                                                    "product_"
                                                                    "ids";
                                                                goto bad;
                                                        }
                                                        pair_included[pair] =
                                                            true;
                                                }
                                        }
                                        key_idx =
                                            json_skip(r, c->toks, key_idx + 1);
                                }
                                for (enum exchg_pair pair = 0;
                                     pair < EXCHG_NUM_PAIRS; pair++) {
                                        if (parsing_level2 &&
                                            pair_included[pair])
                                                l2_pair_sub[pair] = true;
                                        else if (parsing_user &&
                                                 pair_included[pair])
                                                user_pair_sub[pair] = true;
                                }
                        }
                } else {
                        key_idx = json_skip(r, c->toks, key_idx + 1);
                }
        }

        bool new_l2 = false;
        bool new_user = false;
        bool new_l2_sub[EXCHG_NUM_PAIRS];
        bool new_user_sub[EXCHG_NUM_PAIRS];

        memset(new_l2_sub, 0, sizeof(new_l2_sub));
        memset(new_user_sub, 0, sizeof(new_user_sub));

        for (enum exchg_pair pair = 0; pair < EXCHG_NUM_PAIRS; pair++) {
                struct coinbase_channel *chan = &c->channels[pair];

                l2_pair_sub[pair] |= global_pair[pair] && level2_global;
                if (!chan->l2_subbed && l2_pair_sub[pair]) {
                        new_l2 = true;
                        new_l2_sub[pair] = true;
                        chan->l2_subbed = true;
                }
                user_pair_sub[pair] |= global_pair[pair] && user_global;
                if (!chan->user_subbed && user_pair_sub[pair]) {
                        new_user = true;
                        new_user_sub[pair] = true;
                        chan->user_subbed = true;
                }
        }
        if (new_l2 || new_user) {
                struct coinbase_proto *cp = test_event_private(
                    exchg_fake_queue_ws_event(w, EXCHG_EVENT_WS_PROTOCOL,
                                              sizeof(struct coinbase_proto)));
                memcpy(cp->new_l2_sub, new_l2_sub, sizeof(new_l2_sub));
                memcpy(cp->new_user_sub, new_user_sub, sizeof(new_user_sub));
                cp->new_l2 = new_l2;
                cp->new_user = new_user;
        }
        return;

bad:
        fprintf(stderr, "%s: %s:\n", __func__, problem);
        fwrite(json, 1, len, stderr);
        fputc('\n', stderr);
}

static int ws_matches(struct websocket_conn *w, struct exchg_test_event *ev)
{
        struct coinbase_websocket *c = w->priv;
        if (ev->type == EXCHG_EVENT_BOOK_UPDATE) {
                enum exchg_pair p = ev->data.book.pair;
                return c->channels[p].l2_subbed;
        }
        return 0;
}

static void ws_destroy(struct websocket_conn *w)
{
        free(w->priv);
        ws_conn_free(w);
}

struct websocket_conn *coinbase_ws_dial(struct exchg_net_context *ctx,
                                        const char *path, void *private)
{
        struct websocket_conn *s = fake_websocket_alloc(ctx, private);
        s->read = ws_read;
        s->write = ws_write;
        s->matches = ws_matches;
        s->destroy = ws_destroy;
        struct coinbase_websocket *cb = xzalloc(sizeof(*cb));
        s->priv = cb;
        return s;
}
