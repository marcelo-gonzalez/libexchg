// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#include <jsmn/jsmn.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uuid.h>

#include "exchg/exchg.h"
#include "fake-coinbase.h"
#include "fake-net.h"
#include "json-helpers.h"
#include "util.h"

static void products_read(struct http_conn *req, struct exchg_test_event *ev,
                          struct buf *buf)
{
        if (!req->ctx->options.coinbase_info_file) {
                fprintf(stderr, "test: no coinbase_info_file set in "
                                "exchg_test_options. Please set it\n");
                exit(1);
        }
        if (buf_read_file(buf, req->ctx->options.coinbase_info_file)) {
                fprintf(stderr,
                        "test: reading coinbase_info_file failed. Aborting\n");
                exit(1);
        }
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
        buf_xsprintf(buf, "{\"accounts\": [");
        for (enum exchg_currency c = 0; c < EXCHG_NUM_CCYS; c++) {
                char s[30];
                decimal_t *balance =
                    &req->ctx->servers[EXCHG_COINBASE].balances[c];
                decimal_to_str(s, balance);
                buf_xsprintf(
                    buf,
                    "{\"uuid\": \"234-abc-def%d\", \"currency\": \"%s\", "
                    "\"available_balance\": {\"value\": \"%s\","
                    "\"currency\": \"%s\"}, \"active\": true, "
                    "\"type\": \"%s\"}, ",
                    c, exchg_ccy_to_upper(c), s, exchg_ccy_to_upper(c),
                    c == EXCHG_CCY_USD ? "ACCOUNT_TYPE_FIAT"
                                       : "ACCOUNT_TYPE_CRYPTO");
        }
        buf_xsprintf(buf, "]}");
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
        uuid_t server_oid;
        uuid_t client_oid;
};

struct placed_order {
        struct order_ids ids;
        char *configuration;
        char error_msg[128];
};

static void orders_read(struct http_conn *req, struct exchg_test_event *ev,
                        struct buf *buf)
{
        struct placed_order *p = req->priv;
        struct exchg_order_info *ack = &ev->data.order_ack;
        char cost_str[30], fee_str[30];
        char price_str[30], size_str[30];
        char order_id[37], client_oid[37];

        if (p->error_msg[0]) {
                buf_xsprintf(buf,
                             "{\"error\": \"TEST_BAD_REQUEST\", "
                             "\"message\": \"%s\", \"error_details\": \"Test "
                             "error details\"}",
                             p->error_msg);
                return;
        }
        if (!p->configuration) {
                fprintf(stderr,
                        "%s: coinbase test internal error. order config not "
                        "saved\n",
                        __func__);
                exit(1);
        }
        if (ack->status == EXCHG_ORDER_ERROR) {
                buf_xsprintf(buf,
                             "{\"success\": false, \"error_response\": "
                             "{\"error\": \"TEST_FAILURE_REASON\", "
                             "\"message\": \"test error message\", "
                             "\"error_details\": \"Some test error details\"}, "
                             "\"order_configuration\": ");
                buf_xcpy(buf, p->configuration, strlen(p->configuration));
                buf_xsprintf(buf, "}");
                return;
        }
        write_prices(price_str, size_str, cost_str, fee_str, &ack->order.price,
                     &ack->order.size, 60, 6);
        uuid_unparse(p->ids.server_oid, order_id);
        uuid_unparse(p->ids.client_oid, client_oid);
        buf_xsprintf(
            buf,
            "{\"success\": true, \"success_response\": {\"order_id\": \"%s\", "
            "\"product_id\": \"%s\", \"side\": \"%s\", \"client_order_id\": "
            "\"%s\"}, \"order_configuration\": ",
            order_id, coinbase_pair_to_str(ack->order.pair),
            ack->order.side == EXCHG_SIDE_BUY ? "BUY" : "SELL", client_oid);
        buf_xcpy(buf, p->configuration, strlen(p->configuration));
        buf_xsprintf(buf, "}");
}

struct coinbase_public_websocket {
        struct coinbase_channel {
                bool l2_subbed;
                bool user_subbed;
                bool first_l2_sent;
        } channels[EXCHG_NUM_PAIRS];
        int sequence_num;
        jsmn_parser parser;
        jsmntok_t toks[100];
};

enum cancel_type {
        CANCEL_NONE,
        CANCEL_USER,
        CANCEL_SERVER,
};

struct coinbase_order_status {
        const char *status;
        struct order_ids ids;
        decimal_t outstanding_hold_amount;
        decimal_t total_value_after_fees;
        decimal_t total_fees;
        enum cancel_type cancel;
        const char *reject_reason;
};

static void coinbase_fee(decimal_t *cost, decimal_t *fee,
                         const decimal_t *price, const decimal_t *size)
{
        calc_fee_cost(cost, fee, price, size, 100, 6);
}

static struct exchg_test_event *new_user_channel_ack(struct websocket_conn *ws,
                                                     struct test_order *o,
                                                     bool zero_fill)
{
        struct exchg_test_event *event = exchg_fake_queue_ws_event(
            ws, EXCHG_EVENT_ORDER_ACK, sizeof(struct coinbase_order_status));
        struct coinbase_order_status *order_status = test_order_private(o);
        struct coinbase_order_status *ack = test_event_private(event);
        memcpy(ack, order_status, sizeof(*ack));
        memcpy(&event->data.order_ack, &o->info, sizeof(o->info));

        decimal_t *filled = &event->data.order_ack.filled_size;
        decimal_t *avg_price = &event->data.order_ack.avg_price;
        if (zero_fill) {
                decimal_zero(filled);
                decimal_zero(avg_price);
        } else if (decimal_is_positive(filled) && decimal_is_zero(avg_price)) {
                *avg_price = o->info.order.price;
        }
        return event;
}

static void push_user_channel_final_update(struct websocket_conn *ws,
                                           struct test_order *o)
{
        struct coinbase_order_status *order_status = test_order_private(o);
        struct exchg_test_event *event;
        struct coinbase_order_status *ack;

        switch (o->info.status) {
        case EXCHG_ORDER_CANCELED:
                if (order_status->cancel == CANCEL_USER) {
                        event = new_user_channel_ack(ws, o, false);
                        ack = test_event_private(event);
                        ack->status = "CANCEL_QUEUED";
                        memcpy(order_status, ack, sizeof(*ack));
                } else {
                        order_status->cancel = CANCEL_SERVER;
                }
                event = new_user_channel_ack(ws, o, false);
                ack = test_event_private(event);
                ack->status = "CANCELLED";
                coinbase_fee(&ack->total_value_after_fees, &ack->total_fees,
                             &o->info.avg_price, &o->info.filled_size);
                memcpy(order_status, ack, sizeof(*ack));
                break;
        case EXCHG_ORDER_ERROR:
                event = new_user_channel_ack(ws, o, false);
                ack = test_event_private(event);
                ack->status = "ERROR"; // TODO
                ack->reject_reason = "Test reject reason";
                coinbase_fee(&ack->total_value_after_fees, &ack->total_fees,
                             &o->info.avg_price, &o->info.filled_size);
                memcpy(order_status, ack, sizeof(*ack));
                break;
        case EXCHG_ORDER_FINISHED:
                break;
        default:
                fprintf(stderr, "test: coinbase: bad status %d passed to %s\n",
                        o->info.status, __func__);
                exit(1);
                break;
        }
        if (decimal_is_positive(&order_status->outstanding_hold_amount)) {
                event = new_user_channel_ack(ws, o, false);
                ack = test_event_private(event);
                decimal_zero(&ack->outstanding_hold_amount);
                coinbase_fee(&ack->total_value_after_fees, &ack->total_fees,
                             &o->info.avg_price, &o->info.filled_size);
                memcpy(order_status, ack, sizeof(*ack));
        }
}

struct order_values {
        decimal_t total_value_after_fees;
        decimal_t total_fees;
        decimal_t filled_cost;
        decimal_t unfilled_cost;
};

static void calc_values(struct order_values *values,
                        const struct exchg_order_info *info)
{
        decimal_t remaining;
        decimal_subtract(&remaining, &info->order.size, &info->filled_size);
        if (decimal_is_negative(&remaining)) {
                fprintf(
                    stderr,
                    "test: coinbase: zeroing remaining filled amount larger "
                    "than order size\n");
                decimal_zero(&remaining);
        }
        decimal_t scratch;
        coinbase_fee(&values->filled_cost, &values->total_fees,
                     &info->avg_price, &info->filled_size);
        coinbase_fee(&values->unfilled_cost, &scratch, &info->order.price,
                     &remaining);
        decimal_add(&values->total_value_after_fees, &values->filled_cost,
                    &values->unfilled_cost);
}

// `values` must be initialized with calc_values() first
static void calc_new_hold_amount(decimal_t *outstanding_hold_amount,
                                 const struct order_values *values,
                                 const struct exchg_order_info *info)
{
        if (info->order.side == EXCHG_SIDE_BUY)
                decimal_subtract(outstanding_hold_amount,
                                 &values->total_value_after_fees,
                                 &values->filled_cost);
        else
                decimal_subtract(outstanding_hold_amount, &info->order.size,
                                 &info->filled_size);
        if (decimal_is_negative(outstanding_hold_amount)) {
                decimal_zero(outstanding_hold_amount);
        }
}

static void edit_order(struct exchg_net_context *ctx, struct test_order *o,
                       const decimal_t *price, const decimal_t *size)
{
        struct websocket_conn *ws = fake_websocket_get(
            ctx, "advanced-trade-ws-user.coinbase.com", NULL);
        if (!ws) {
                o->info.order.price = *price;
                o->info.order.size = *size;
                return;
        }

        bool size_changed = decimal_cmp(size, &o->info.order.size);
        bool price_changed = decimal_cmp(price, &o->info.order.price);

        if (!size_changed && !price_changed)
                return;

        struct exchg_order_info new_info = o->info;
        new_info.order.price = *price;
        new_info.order.size = *size;

        struct order_values values;
        decimal_t new_hold;
        calc_values(&values, &new_info);
        calc_new_hold_amount(&new_hold, &values, &new_info);

        struct coinbase_order_status *order_status = test_order_private(o);
        static struct exchg_test_event *event = NULL;
        if (decimal_cmp(&new_hold, &order_status->outstanding_hold_amount)) {
                event = new_user_channel_ack(ws, o, false);
                struct coinbase_order_status *ack = test_event_private(event);

                ack->outstanding_hold_amount = new_hold;
                order_status->outstanding_hold_amount = new_hold;
        }

        o->info.order.price = *price;
        o->info.order.size = *size;

        event = new_user_channel_ack(ws, o, false);
        struct coinbase_order_status *ack = test_event_private(event);
        ack->total_value_after_fees = values.total_value_after_fees;
        order_status->total_value_after_fees = values.total_value_after_fees;
}

static struct exchg_test_event *
push_user_channel_fill(struct websocket_conn *ws, struct test_order *o)
{

        struct coinbase_order_status *order_status = test_order_private(o);
        struct exchg_test_event *event = new_user_channel_ack(ws, o, false);
        struct coinbase_order_status *ack = test_event_private(event);

        if (o->info.status == EXCHG_ORDER_FINISHED)
                ack->status = "FILLED";

        struct order_values values;
        calc_values(&values, &o->info);
        ack->total_fees = values.total_fees;
        ack->total_value_after_fees = values.total_value_after_fees;

        memcpy(order_status, ack, sizeof(*ack));

        // do we get another one if it's partially filled, like we do at the end
        // if it's fully filled?
        struct exchg_test_event *drop_hold_event =
            new_user_channel_ack(ws, o, false);
        struct coinbase_order_status *drop_hold_ack =
            test_event_private(drop_hold_event);

        calc_new_hold_amount(&drop_hold_ack->outstanding_hold_amount, &values,
                             &o->info);

        memcpy(order_status, drop_hold_ack, sizeof(*drop_hold_ack));
        return drop_hold_event;
}

static struct exchg_test_event *
push_user_channel_acks(struct websocket_conn *ws, struct test_order *o)
{
        decimal_t scratch;
        struct exchg_test_event *received = new_user_channel_ack(ws, o, true);
        struct coinbase_order_status *order_status = test_order_private(o);
        struct coinbase_order_status *ack = test_event_private(received);

        ack->status = "PENDING";
        ack->reject_reason = "";
        coinbase_fee(&ack->total_value_after_fees, &scratch,
                     &o->info.order.price, &o->info.order.size);
        memcpy(order_status, ack, sizeof(*ack));

        struct exchg_test_event *open = new_user_channel_ack(ws, o, true);
        struct coinbase_order_status *open_ack = test_event_private(open);

        open_ack->status = "OPEN";
        if (o->info.order.side == EXCHG_SIDE_BUY)
                open_ack->outstanding_hold_amount =
                    open_ack->total_value_after_fees;
        else
                open_ack->outstanding_hold_amount = o->info.order.size;

        memcpy(order_status, open_ack, sizeof(*open_ack));
        return open;
}

static void receive_order(struct exchg_net_context *ctx, struct test_order *o,
                          const struct order_ids *ids)
{
        struct coinbase_order_status *status = test_order_private(o);
        memcpy(&status->ids, ids, sizeof(*ids));

        struct websocket_conn *ws = fake_websocket_get(
            ctx, "advanced-trade-ws-user.coinbase.com", NULL);
        if (!ws)
                return;

        push_user_channel_acks(ws, o);

        if (!decimal_is_zero(&o->info.filled_size)) {
                push_user_channel_fill(ws, o);
        }

        if (o->info.status == EXCHG_ORDER_FINISHED ||
            o->info.status == EXCHG_ORDER_CANCELED ||
            o->info.status == EXCHG_ORDER_ERROR) {
                push_user_channel_final_update(ws, o);
        }
}

static void copy_str(char *dst, const char *src, size_t len)
{
        strncpy(dst, src, len);
        dst[len - 1] = 0;
}

static int parse_order_config(const char *body, int num_toks, jsmntok_t *toks,
                              int idx, struct exchg_order_info *ack,
                              bool *got_price, bool *got_size,
                              struct placed_order *p)
{
        if (toks[idx].type != JSMN_OBJECT) {
                copy_str(p->error_msg, "non-object order_configuration",
                         sizeof(p->error_msg));
                return -1;
        }
        if (toks[idx].size != 1) {
                copy_str(p->error_msg, "expected one order_configuration key",
                         sizeof(p->error_msg));
                return -1;
        }

        int key_idx = idx + 1;
        jsmntok_t *key = &toks[key_idx];
        jsmntok_t *value = key + 1;

        if (json_streq(body, key, "sor_limit_ioc")) {
                ack->opts.immediate_or_cancel = true;
        } else if (json_streq(body, key, "limit_limit_gtc")) {
                ack->opts.immediate_or_cancel = false;
        } else {
                copy_str(p->error_msg, "unexpected order_configuration key",
                         sizeof(p->error_msg));
                return -1;
        }

        if (value->type != JSMN_OBJECT) {
                copy_str(p->error_msg, "non-object order_configuration",
                         sizeof(p->error_msg));
                return -1;
        }
        key_idx += 2;
        int n = value->size;
        for (int i = 0; i < n; i++) {
                key = &toks[key_idx];
                value = key + 1;
                if (json_streq(body, key, "limit_price")) {
                        if (json_get_decimal(&ack->order.price, body, value)) {
                                copy_str(p->error_msg, "bad price",
                                         sizeof(p->error_msg));
                                return -1;
                        }
                        *got_price = true;
                } else if (json_streq(body, key, "base_size")) {
                        if (json_get_decimal(&ack->order.size, body, value)) {
                                copy_str(p->error_msg, "bad size",
                                         sizeof(p->error_msg));
                                return -1;
                        }
                        *got_size = true;
                }
                key_idx = json_skip(num_toks, toks, key_idx + 1);
        }
        return 0;
}

static int parse_json_uuid(uuid_t id, const char *json, jsmntok_t *value)
{
        // uuid_parse_range() would work without needing to strdup() but is not
        // available on macos
        char *val;
        if (json_strdup(&val, json, value) < 0) {
                fprintf(stderr, "test: coinbase: %s: OOM\n", __func__);
                exit(1);
        }
        int ret = uuid_parse(val, id);
        free(val);
        return ret;
}

static void orders_write(struct http_conn *req, const char *body, size_t len)
{
        jsmn_parser parser;
        jsmntok_t toks[100];
        // copy it since when we call on_order_placed(), we don't want to change
        // anything in this event's data, since updates will be sent on the
        // websocket
        struct exchg_order_info ack = req->read_event->data.order_ack;
        struct placed_order *p = req->priv;
        char *configuration = NULL;

        if (len < 1) {
                fprintf(stderr, "no body given with POST to "
                                "https://api.pro.coinbase.com/orders\n");
                return;
        }

        jsmn_init(&parser);
        int num_toks = jsmn_parse(&parser, body, len, toks, 100);
        if (num_toks <= 0) {
                copy_str(p->error_msg, "could not parse JSON",
                         sizeof(p->error_msg));
                goto bad;
        }
        if (toks[0].type != JSMN_OBJECT) {
                copy_str(p->error_msg, "non-object JSON message",
                         sizeof(p->error_msg));
                goto bad;
        }

        bool got_pair = false;
        bool got_price = false;
        bool got_size = false;
        bool got_side = false;
        bool got_client_oid = false;

        uuid_t client_oid;
        int key_idx = 1;
        for (int i = 0; i < toks[0].size; i++) {
                jsmntok_t *key = &toks[key_idx];
                jsmntok_t *value = key + 1;

                if (json_streq(body, key, "order_configuration")) {
                        if (parse_order_config(body, num_toks, toks,
                                               key_idx + 1, &ack, &got_price,
                                               &got_size, p)) {
                                goto bad;
                        }
                        if (__json_strdup(&configuration, body, value) < 0) {
                                fprintf(stderr, "%s: OOM\n", __func__);
                                exit(1);
                        }
                } else if (json_streq(body, key, "side")) {
                        if (json_streq(body, value, "BUY"))
                                ack.order.side = EXCHG_SIDE_BUY;
                        else if (json_streq(body, value, "SELL"))
                                ack.order.side = EXCHG_SIDE_SELL;
                        else {
                                copy_str(p->error_msg, "bad side",
                                         sizeof(p->error_msg));
                                goto bad;
                        }
                        got_side = true;
                } else if (json_streq(body, key, "product_id")) {
                        if (coinbase_str_to_pair(&ack.order.pair, body,
                                                 value)) {
                                copy_str(p->error_msg, "bad product_id",
                                         sizeof(p->error_msg));
                                goto bad;
                        }
                        got_pair = true;
                } else if (json_streq(body, key, "client_order_id")) {
                        if (value->type != JSMN_STRING) {
                                copy_str(p->error_msg, "bad client_order_id",
                                         sizeof(p->error_msg));
                                goto bad;
                        }
                        if (parse_json_uuid(client_oid, body, value)) {
                                copy_str(p->error_msg, "bad client_order_id",
                                         sizeof(p->error_msg));
                                goto bad;
                        }
                        got_client_oid = true;
                }

                key_idx = json_skip(num_toks, toks, key_idx + 1);
        }

        if (!got_pair) {
                copy_str(p->error_msg, "missing product_id",
                         sizeof(p->error_msg));
                goto bad;
        }
        if (!got_size) {
                copy_str(p->error_msg, "missing size", sizeof(p->error_msg));
                goto bad;
        }
        if (!got_side) {
                copy_str(p->error_msg, "missing side", sizeof(p->error_msg));
                goto bad;
        }
        if (!got_price) {
                copy_str(p->error_msg, "missing price", sizeof(p->error_msg));
                goto bad;
        }
        if (!got_client_oid) {
                copy_str(p->error_msg, "missing client_order_id",
                         sizeof(p->error_msg));
                goto bad;
        }

        memcpy(&p->ids.client_oid, client_oid, sizeof(client_oid));
        uuid_generate(p->ids.server_oid);
        p->configuration = configuration;

        struct test_order *o =
            on_order_placed(req->ctx, EXCHG_COINBASE, &ack,
                            sizeof(struct coinbase_order_status));
        receive_order(req->ctx, o, &p->ids);
        return;

bad:
        req->status = 400;
        free(configuration);
        fprintf(stderr, "%s client error: %s:\n", __func__, p->error_msg);
        fwrite(body, 1, len, stderr);
        fputc('\n', stderr);
}

static void orders_destroy(struct http_conn *req)
{
        struct placed_order *p = req->priv;
        free(p->configuration);
        free(p);
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
        req->priv = xzalloc(sizeof(struct placed_order));
        return req;
}

int coinbase_fill_order(struct exchg_net_context *ctx, struct test_order *o,
                        const decimal_t *total_fill)
{
        struct websocket_conn *ws = fake_websocket_get(
            ctx, "advanced-trade-ws-user.coinbase.com", NULL);
        if (!ws)
                return 0;

        push_user_channel_fill(ws, o);

        if (o->info.status == EXCHG_ORDER_FINISHED) {
                push_user_channel_final_update(ws, o);
        }
        return 0;
}

struct edited_order {
        bool success;
        char error_msg[128];
};

static void orders_edit_read(struct http_conn *req, struct exchg_test_event *ev,
                             struct buf *buf)
{
        struct edited_order *ack = req->priv;

        buf_xsprintf(buf, "{\"success\": %s, \"errors\": [",
                     ack->success ? "true" : "false");
        if (ack->error_msg[0]) {
                buf_xsprintf(buf, "{\"edit_failure_reason\": \"%s\"}",
                             ack->error_msg);
        }
        buf_xsprintf(buf, "]}");
}

static void orders_edit_write(struct http_conn *req, const char *body,
                              size_t len)
{
        struct edited_order *ack = req->priv;
        jsmn_parser parser;
        jsmntok_t toks[100];

        if (len < 1) {
                copy_str(ack->error_msg, "MISSING_ARGS",
                         sizeof(ack->error_msg));
                goto bad;
        }

        jsmn_init(&parser);
        int num_toks = jsmn_parse(&parser, body, len, toks, 100);
        if (num_toks <= 0) {
                copy_str(ack->error_msg, "INVALID_JSON",
                         sizeof(ack->error_msg));
                goto bad;
        }
        if (toks[0].type != JSMN_OBJECT) {
                copy_str(ack->error_msg, "INVALID_JSON_TYPE",
                         sizeof(ack->error_msg));
                goto bad;
        }

        decimal_t size, price;
        bool got_size = false, got_price = false;
        uuid_t order_id;
        bool got_order_id = false;

        int key_idx = 1;
        for (int i = 0; i < toks[0].size; i++) {
                jsmntok_t *key = &toks[key_idx];
                jsmntok_t *value = key + 1;

                if (json_streq(body, key, "order_id")) {
                        if (value->type != JSMN_STRING) {
                                copy_str(ack->error_msg, "INVALID_ORDER_ID",
                                         sizeof(ack->error_msg));
                                goto bad;
                        }
                        if (parse_json_uuid(order_id, body, value)) {
                                copy_str(ack->error_msg, "INVALID_ORDER_ID",
                                         sizeof(ack->error_msg));
                                goto bad;
                        }
                        got_order_id = true;
                } else if (json_streq(body, key, "size")) {
                        if (json_get_decimal(&size, body, value)) {
                                copy_str(ack->error_msg, "INVALID_EDITED_SIZE",
                                         sizeof(ack->error_msg));
                                goto bad;
                        }
                        if (!decimal_is_positive(&size)) {
                                copy_str(ack->error_msg, "INVALID_EDITED_SIZE",
                                         sizeof(ack->error_msg));
                                goto bad;
                        }
                        got_size = true;
                } else if (json_streq(body, key, "price")) {
                        if (json_get_decimal(&price, body, value)) {
                                copy_str(ack->error_msg, "INVALID_EDITED_PRICE",
                                         sizeof(ack->error_msg));
                                goto bad;
                        }
                        if (!decimal_is_positive(&price)) {
                                copy_str(ack->error_msg, "INVALID_EDITED_PRICE",
                                         sizeof(ack->error_msg));
                                goto bad;
                        }
                        got_price = true;
                }

                key_idx = json_skip(num_toks, toks, key_idx + 1);
        }

        if (!got_order_id) {
                copy_str(ack->error_msg, "INVALID_ORDER_ID",
                         sizeof(ack->error_msg));
                goto bad;
        }
        if (!got_price) {
                copy_str(ack->error_msg, "INVALID_EDITED_PRICE",
                         sizeof(ack->error_msg));
                goto bad;
        }
        if (!got_size) {
                copy_str(ack->error_msg, "INVALID_EDITED_SIZE",
                         sizeof(ack->error_msg));
                goto bad;
        }

        struct test_order *o, *order = NULL;
        LIST_FOREACH(o, &req->ctx->servers[EXCHG_COINBASE].order_list, list)
        {
                struct coinbase_order_status *co = test_order_private(o);
                if (uuid_compare(order_id, co->ids.server_oid) == 0) {
                        order = o;
                        break;
                }
        }
        if (order == NULL) {
                copy_str(ack->error_msg, "UNKNOWN_ORDER_ID",
                         sizeof(ack->error_msg));
                goto bad;
        }
        int cmp = decimal_cmp(&size, &order->info.filled_size);
        if (cmp < 0) {
                copy_str(ack->error_msg, "CANNOT_EDIT_TO_BELOW_FILLED_SIZE",
                         sizeof(ack->error_msg));
                goto bad;
        } else if (cmp == 0) {
                // Coinbase seems to just do nothing but say that the edit is
                // successful in this case?
                return;
        }
        ack->success =
            on_order_edited(req->ctx, EXCHG_COINBASE, order, &price, &size);
        if (ack->success) {
                edit_order(req->ctx, order, &price, &size);
        } else {
                copy_str(ack->error_msg, "TEST_ERROR_REASON",
                         sizeof(ack->error_msg));
        }
        return;

bad:
        ack->success = false;
        fprintf(stderr, "test: coinbase: %s client error: %s: %.*s\n", __func__,
                ack->error_msg, (int)len, body);
}

static void orders_edit_destroy(struct http_conn *req)
{
        free(req->priv);
        fake_http_conn_free(req);
}

static struct http_conn *orders_edit_dial(struct exchg_net_context *ctx,
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
        req->read = orders_edit_read;
        req->write = orders_edit_write;
        req->add_header = no_http_add_header;
        req->destroy = orders_edit_destroy;
        req->priv = xzalloc(sizeof(struct edited_order));
        return req;
}

struct order_cancel {
        bool has_order_id;
        uuid_t order_id;
        bool success;
        char error_msg[100];
};

static void cancel_order_read(struct http_conn *req,
                              struct exchg_test_event *ev, struct buf *buf)
{
        struct order_cancel *cancel = req->priv;

        if (!cancel->has_order_id) {
                if (!cancel->error_msg[0]) {
                        copy_str(cancel->error_msg, "unknown order",
                                 sizeof(cancel->error_msg));
                }
                cancel->success = false;
        }
        buf_xsprintf(
            buf, "{\"results\": [{\"success\": %s, \"failure_reason\": \"%s\"",
            cancel->success ? "true" : "false", cancel->error_msg);
        if (cancel->has_order_id) {
                char order_id[37];
                uuid_unparse(cancel->order_id, order_id);
                buf_xsprintf(buf, ", \"order_id\": \"%s\"", order_id);
        }
        buf_xsprintf(buf, "}]}");
}

static void cancel_order_free(struct http_conn *req)
{
        free(req->priv);
        fake_http_conn_free(req);
}

static bool cancel_order(struct exchg_net_context *ctx, struct test_order *o)
{
        enum exchg_order_status prev_status = o->info.status;
        if (!on_order_canceled(ctx, EXCHG_COINBASE, o))
                return false;

        if (prev_status != EXCHG_ORDER_FINISHED &&
            prev_status != EXCHG_ORDER_CANCELED &&
            prev_status != EXCHG_ORDER_ERROR) {
                struct websocket_conn *ws = fake_websocket_get(
                    ctx, "advanced-trade-ws-user.coinbase.com", NULL);
                if (!ws)
                        return true;

                struct coinbase_order_status *order_status =
                    test_order_private(o);
                order_status->cancel = CANCEL_USER;
                push_user_channel_final_update(ws, o);
        }
        return true;
}

static void cancel_order_write(struct http_conn *req, const char *body,
                               size_t len)
{
        struct order_cancel *cancel = req->priv;
        jsmn_parser parser;
        jsmntok_t toks[100];
        cancel->success = false;

        if (len < 1) {
                fprintf(stderr, "no body given with POST to %s%s\n", req->host,
                        req->path);
                return;
        }

        jsmn_init(&parser);
        int num_toks = jsmn_parse(&parser, body, len, toks, 100);
        if (num_toks <= 0) {
                copy_str(cancel->error_msg, "could not parse JSON",
                         sizeof(cancel->error_msg));
                goto bad;
        }
        if (toks[0].type != JSMN_OBJECT) {
                copy_str(cancel->error_msg, "non-object JSON message",
                         sizeof(cancel->error_msg));
        }

        int key_idx = 1;
        for (int i = 0; i < toks[0].size; i++) {
                jsmntok_t *key = &toks[key_idx];
                jsmntok_t *value = key + 1;

                if (json_streq(body, key, "order_ids")) {
                        if (value->type != JSMN_ARRAY) {
                                copy_str(cancel->error_msg, "bad order_ids",
                                         sizeof(cancel->error_msg));
                                break;
                        }
                        if (value->size == 0) {
                                copy_str(cancel->error_msg, "empty order_ids",
                                         sizeof(cancel->error_msg));
                                break;
                        }
                        if (value->size > 1) {
                                copy_str(cancel->error_msg,
                                         "FIXME: more than one order_ids",
                                         sizeof(cancel->error_msg));

                                break;
                        }
                        jsmntok_t *oid = value + 1;
                        if (parse_json_uuid(cancel->order_id, body, oid)) {
                                copy_str(cancel->error_msg, "bad order_id",
                                         sizeof(cancel->error_msg));
                                break;
                        }
                        cancel->has_order_id = true;
                        break;
                }
                key_idx = json_skip(num_toks, toks, key_idx + 1);
        }
        if (!cancel->has_order_id && !cancel->error_msg[0]) {
                copy_str(cancel->error_msg, "no order_ids",
                         sizeof(cancel->error_msg));
        }
        if (cancel->error_msg[0])
                goto bad;

        struct test_order *o;
        LIST_FOREACH(o, &req->ctx->servers[EXCHG_COINBASE].order_list, list)
        {
                struct coinbase_order_status *co = test_order_private(o);
                if (uuid_compare(cancel->order_id, co->ids.server_oid) == 0) {
                        if (decimal_cmp(&o->info.filled_size,
                                        &o->info.order.size) >= 0) {
                                req->status = 404;
                                snprintf(cancel->error_msg,
                                         sizeof(cancel->error_msg),
                                         "order already filled");
                        } else if (!cancel_order(req->ctx, o)) {
                                req->status = 503;
                                snprintf(cancel->error_msg,
                                         sizeof(cancel->error_msg),
                                         "Service Unavailable");
                        } else {
                                cancel->success = true;
                                copy_str(cancel->error_msg,
                                         "UNKNOWN_CANCEL_FAILURE_REASON",
                                         sizeof(cancel->error_msg));
                        }
                        return;
                }
        }
        req->status = 404;
        copy_str(cancel->error_msg, "Unrecognized order id",
                 sizeof(cancel->error_msg));
        return;

bad:
        req->status = 400;
        fprintf(stderr, "%s client error: %s:\n", __func__, cancel->error_msg);
        fwrite(body, 1, len, stderr);
        fputc('\n', stderr);
}

static struct http_conn *cancel_order_dial(struct exchg_net_context *ctx,
                                           const char *path, const char *method,
                                           void *private)
{
        if (strcmp(method, "POST")) {
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
        if (!strcmp(path, "/api/v3/brokerage/market/products"))
                return products_dial(ctx, path, method, private);
        else if (!strcmp(path, "/api/v3/brokerage/accounts"))
                return accounts_dial(ctx, path, method, private);
        else if (!strcmp(path, "/api/v3/brokerage/orders"))
                return orders_dial(ctx, path, method, private);
        else if (!strcmp(path, "/api/v3/brokerage/orders/edit"))
                return orders_edit_dial(ctx, path, method, private);
        else if (!strcmp(path, "/api/v3/brokerage/orders/batch_cancel"))
                return cancel_order_dial(ctx, path, method, private);
        else {
                exchg_log("Coinbase bad HTTP path: %s\n", path);
                return NULL;
        }
}

__attribute__((format(printf, 4, 5))) static void
do_print(char *dst, size_t dst_len, size_t *pos, const char *fmt, ...)
{
        va_list ap;
        va_start(ap, fmt);

        *pos += vsnprintf(dst + *pos, dst_len - *pos, fmt, ap);
        if (*pos >= dst_len) {
                fprintf(stderr,
                        "%s: printing too many chars to buffer w size %zu!\n",
                        __func__, dst_len);
                exit(1);
        }

        va_end(ap);
}

static void write_timestamp(char *dst, size_t dst_len, int64_t timestamp)
{
        time_t secs_since_epoch = timestamp / 1000000;
        int64_t micros = timestamp % 1000000;

        struct tm *tm = gmtime(&secs_since_epoch);
        tm->tm_mon += 1;
        tm->tm_year += 1900;

        size_t pos = 0;

        do_print(dst, dst_len, &pos, "%d", tm->tm_year);
        do_print(dst, dst_len, &pos, "-");
        do_print(dst, dst_len, &pos, "%02d", tm->tm_mon);
        do_print(dst, dst_len, &pos, "-");
        do_print(dst, dst_len, &pos, "%02d", tm->tm_mday);
        do_print(dst, dst_len, &pos, "T");
        do_print(dst, dst_len, &pos, "%02d", tm->tm_hour);
        do_print(dst, dst_len, &pos, ":");
        do_print(dst, dst_len, &pos, "%02d", tm->tm_min);
        do_print(dst, dst_len, &pos, ":");
        do_print(dst, dst_len, &pos, "%02d", tm->tm_sec);
        do_print(dst, dst_len, &pos, ".");
        do_print(dst, dst_len, &pos, "%06" PRId64, micros);
        do_print(dst, dst_len, &pos, "Z");
}

static void public_ws_read(struct websocket_conn *ws, struct buf *buf,
                           struct exchg_test_event *msg)
{
        if (msg->type != EXCHG_EVENT_BOOK_UPDATE) {
                fprintf(stderr, "%s: unexpected msg type: %d\n", __func__,
                        msg->type);
                return;
        }

        struct coinbase_public_websocket *cb = ws->priv;
        struct exchg_test_l2_updates *b = &msg->data.book;
        if (b->num_bids < 1 && b->num_asks < 1)
                return;
        const char *id = coinbase_pair_to_str(b->pair);
        if (!id)
                return;

        buf_xsprintf(buf,
                     "{\"channel\": \"l2_data\", "
                     "\"client_id\": \"\","
                     "\"timestamp\": \"2023-02-09T20:32:50.714964855Z\","
                     "\"sequence_num\": %d,"
                     "\"events\": [{ \"product_id\": \"%s\", ",
                     cb->sequence_num, id);
        cb->sequence_num += 1;

        if (!cb->channels[b->pair].first_l2_sent) {
                cb->channels[b->pair].first_l2_sent = true;
                buf_xsprintf(buf, "\"type\": \"snapshot\", "
                                  "\"updates\": [");
        } else {
                buf_xsprintf(buf, "\"type\": \"update\", "
                                  "\"updates\": [");
        }

        int64_t current_time = test_event_timestamp(msg);
        for (int i = 0; i < b->num_asks; i++) {
                char price[30], size[30], timestamp[100];
                decimal_to_str(price, &b->asks[i].price);
                decimal_to_str(size, &b->asks[i].size);
                write_timestamp(timestamp, sizeof(timestamp), current_time);
                buf_xsprintf(buf,
                             "{\"side\": \"offer\","
                             "\"event_time\": \"%s\","
                             "\"price_level\": \"%s\","
                             "\"new_quantity\": \"%s\"},",
                             timestamp, price, size);
        }
        for (int i = 0; i < b->num_bids; i++) {
                char price[30], size[30], timestamp[100];
                decimal_to_str(price, &b->bids[i].price);
                decimal_to_str(size, &b->bids[i].size);
                write_timestamp(timestamp, sizeof(timestamp), current_time);
                buf_xsprintf(buf,
                             "{\"side\": \"bid\","
                             "\"event_time\": \"%s\","
                             "\"price_level\": \"%s\","
                             "\"new_quantity\": \"%s\"},",
                             timestamp, price, size);
        }
        buf_xsprintf(buf, "]}]}");
}

static void public_ws_write(struct websocket_conn *w, const char *json,
                            size_t len)
{
        struct coinbase_public_websocket *c = w->priv;
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

        bool level2_channel = false;
        bool subscribe = false;
        bool l2_pair_sub[EXCHG_NUM_PAIRS];
        memset(l2_pair_sub, 0, sizeof(l2_pair_sub));

        int key_idx = 1;
        for (int i = 0; i < c->toks[0].size; i++) {
                jsmntok_t *key = &c->toks[key_idx];
                jsmntok_t *value = key + 1;

                if (json_streq(json, key, "type")) {
                        if (!json_streq(json, value, "subscribe")) {
                                problem = "bad \"type\" field";
                                goto bad;
                        }
                        subscribe = true;
                        key_idx += 2;
                } else if (json_streq(json, key, "channel")) {
                        if (!json_streq(json, value, "level2")) {
                                problem = "unrecognized \"channel\"";
                                goto bad;
                        }
                        level2_channel = true;
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
                                l2_pair_sub[pair] = true;
                        }
                        key_idx = json_skip(r, c->toks, key_idx + 1);
                } else {
                        key_idx = json_skip(r, c->toks, key_idx + 1);
                }
        }

        if (!subscribe) {
                problem = "no \"type\" field";
                goto bad;
        }
        if (!level2_channel) {
                problem = "no \"channel\" field";
                goto bad;
        }

        for (enum exchg_pair pair = 0; pair < EXCHG_NUM_PAIRS; pair++) {
                struct coinbase_channel *chan = &c->channels[pair];

                if (!chan->l2_subbed && l2_pair_sub[pair]) {
                        chan->l2_subbed = true;
                }
        }
        return;

bad:
        fprintf(stderr, "%s: %s:\n", __func__, problem);
        fwrite(json, 1, len, stderr);
        fputc('\n', stderr);
}

static int public_ws_matches(struct websocket_conn *w,
                             struct exchg_test_event *ev)
{
        struct coinbase_public_websocket *c = w->priv;
        if (ev->type == EXCHG_EVENT_BOOK_UPDATE) {
                return c->channels[ev->data.book.pair].l2_subbed;
        }
        if (ev->type == EXCHG_EVENT_FROM_FILE) {
                return ev->data.from_file.ws_type != EXCHG_WS_TYPE_PRIVATE;
        }
        return 0;
}

static void public_ws_destroy(struct websocket_conn *w)
{
        free(w->priv);
        ws_conn_free(w);
}

struct websocket_conn *coinbase_ws_dial(struct exchg_net_context *ctx,
                                        const char *path, void *private)
{
        struct websocket_conn *s =
            fake_websocket_alloc(EXCHG_COINBASE, ctx, private);
        s->read = public_ws_read;
        s->write = public_ws_write;
        s->matches = public_ws_matches;
        s->destroy = public_ws_destroy;
        struct coinbase_public_websocket *cb = xzalloc(sizeof(*cb));
        s->priv = cb;
        return s;
}

struct coinbase_private_websocket {
        bool user_chan_subbed;
        int sequence_num;
        jsmn_parser parser;
        jsmntok_t toks[100];
};

static void ack_read(struct buf *buf, struct exchg_test_event *msg,
                     int sequence_num, int64_t current_time)
{
        struct exchg_order_info *order_info = &msg->data.order_ack;
        struct coinbase_order_status *ack = test_event_private(msg);

        char timestamp[100];
        char client_oid[37], server_oid[37];
        char outstanding_hold_amount[30], total_value_after_fees[30],
            total_fees[30];
        decimal_t leaves;
        char price_str[30], size_str[30], filled_str[30], avg_price[30],
            leaves_str[30];
        const char *cancel_reason;
        switch (ack->cancel) {
        case CANCEL_NONE:
                cancel_reason = "";
                break;
        case CANCEL_USER:
                cancel_reason = "User requested cancel";
                break;
        case CANCEL_SERVER:
                cancel_reason = "Internal error";
                break;
        default:
                fprintf(stderr, "test: coinbase: bad cancel enum %d in %s\n",
                        ack->cancel, __func__);
                exit(1);
        }

        write_timestamp(timestamp, sizeof(timestamp), current_time);
        uuid_unparse(ack->ids.client_oid, client_oid);
        uuid_unparse(ack->ids.server_oid, server_oid);
        decimal_to_str(price_str, &order_info->order.price);
        decimal_to_str(size_str, &order_info->order.size);
        decimal_to_str(avg_price, &order_info->avg_price);
        decimal_to_str(filled_str, &order_info->filled_size);
        decimal_to_str(outstanding_hold_amount, &ack->outstanding_hold_amount);
        decimal_to_str(total_value_after_fees, &ack->total_value_after_fees);
        decimal_to_str(total_fees, &ack->total_fees);
        decimal_subtract(&leaves, &order_info->order.size,
                         &order_info->filled_size);
        decimal_to_str(leaves_str, &leaves);

        // there are more fields, but we only read these for now
        buf_xsprintf(
            buf,
            "{\"channel\": \"user\", \"client_id\": \"\", \"timestamp\": "
            "\"%s\", \"sequence_num\": %d, "
            "\"events\": [{\"type\": \"update\", \"orders\": "
            "[{\"client_order_id\": \"%s\", \"order_id\": \"%s\", "
            "\"order_side\": \"%s\", \"order_type\": \"Limit\", "
            "\"product_id\": \"%s\", \"time_in_force\": \"%s\", "
            "\"outstanding_hold_amount\": \"%s\", \"total_value_after_fees\": "
            "\"%s\", \"avg_price\": \"%s\", \"total_fees\": \"%s\", "
            "\"cumulative_quantity\": \"%s\", \"leaves_quantity\": \"%s\", "
            "\"limit_price\": \"%s\", \"cancel_reason\": \"%s\", "
            "\"reject_Reason\": \"%s\", \"status\": \"%s\"}], \"positions\": "
            "{\"perpetual_futures_positions\": [], "
            "\"expiring_futures_positions\": []}}]}",
            timestamp, sequence_num, client_oid, server_oid,
            order_info->order.side == EXCHG_SIDE_BUY ? "BUY" : "SELL",
            coinbase_pair_to_str(order_info->order.pair),
            order_info->opts.immediate_or_cancel ? "IMMEDIATE_OR_CANCEL"
                                                 : "GOOD_UNTIL_CANCELLED",
            outstanding_hold_amount, total_value_after_fees, avg_price,
            total_fees, filled_str, leaves_str, price_str, cancel_reason,
            ack->reject_reason, ack->status);
}

static void private_ws_read(struct websocket_conn *w, struct buf *buf,
                            struct exchg_test_event *msg)
{
        struct coinbase_private_websocket *cb = w->priv;

        switch (msg->type) {
        case EXCHG_EVENT_WS_PROTOCOL:
                // TODO: maybe send the first "snapshot" message
                buf_xsprintf(
                    buf,
                    "{\"channel\": \"subscriptions\", "
                    "\"client_id\": \"\","
                    "\"timestamp\": \"2023-02-09T20:32:50.714964855Z\","
                    "\"sequence_num\": %d,"
                    "\"events\": [{ \"subscriptions\": {\"user\": "
                    "[\"1d4c8d73-349a-44a6-9b6d-b3178265af01\"]}}]}",
                    cb->sequence_num);
                break;
        case EXCHG_EVENT_ORDER_ACK:
                ack_read(buf, msg, cb->sequence_num, test_event_timestamp(msg));
                break;
        default:
                fprintf(stderr,
                        "coinbase test private_ws_read can't handle event type "
                        "%d\n",
                        msg->type);
                return;
        }
        cb->sequence_num += 1;
}

static void private_ws_write(struct websocket_conn *w, const char *json,
                             size_t len)
{
        struct coinbase_private_websocket *c = w->priv;
        const char *problem = "";

        jsmn_init(&c->parser);
        int num_toks = jsmn_parse(&c->parser, json, len, c->toks, 100);
        if (num_toks < 0) {
                problem = "could not parse JSON";
                goto bad;
        }
        if (c->toks[0].type != JSMN_OBJECT) {
                problem = "non-object JSON message";
                goto bad;
        }

        bool subscribe = false;
        bool user_chan = false;

        int key_idx = 1;
        for (int i = 0; i < c->toks[0].size; i++) {
                jsmntok_t *key = &c->toks[key_idx];
                jsmntok_t *value = key + 1;

                if (json_streq(json, key, "type")) {
                        if (!json_streq(json, value, "subscribe")) {
                                problem = "bad \"type\" field";
                                goto bad;
                        }
                        subscribe = true;
                        key_idx += 2;
                } else if (json_streq(json, key, "channel")) {
                        if (!json_streq(json, value, "user")) {
                                problem = "bad \"channel\" field";
                                goto bad;
                        }
                        user_chan = true;
                        key_idx += 2;
                } else {
                        key_idx = json_skip(num_toks, c->toks, key_idx + 1);
                }
        }

        if (!subscribe || !user_chan) {
                problem = "no subscribe or user channel";
                goto bad;
        }

        c->user_chan_subbed = true;
        exchg_fake_queue_ws_event(w, EXCHG_EVENT_WS_PROTOCOL, 0);
        return;

bad:
        fprintf(stderr, "%s: %s:\n", __func__, problem);
        fwrite(json, 1, len, stderr);
        fputc('\n', stderr);
}

static int private_ws_matches(struct websocket_conn *w,
                              struct exchg_test_event *ev)
{
        struct coinbase_private_websocket *c = w->priv;
        if (!c->user_chan_subbed)
                return false;
        if (ev->type == EXCHG_EVENT_FROM_FILE) {
                return ev->data.from_file.ws_type == EXCHG_WS_TYPE_PRIVATE;
        }
        return ev->type == EXCHG_EVENT_ORDER_PLACED ||
               ev->type == EXCHG_EVENT_ORDER_CANCELED ||
               ev->type == EXCHG_EVENT_ORDER_ACK ||
               ev->type == EXCHG_EVENT_ORDER_CANCEL_ACK;
}

static void private_ws_destroy(struct websocket_conn *w)
{
        free(w->priv);
        ws_conn_free(w);
}

struct websocket_conn *coinbase_ws_user_dial(struct exchg_net_context *ctx,
                                             const char *path, void *private)
{
        struct websocket_conn *s =
            fake_websocket_alloc(EXCHG_COINBASE, ctx, private);
        s->read = private_ws_read;
        s->write = private_ws_write;
        s->matches = private_ws_matches;
        s->destroy = private_ws_destroy;
        struct coinbase_private_websocket *cb = xzalloc(sizeof(*cb));
        s->priv = cb;
        return s;
}
