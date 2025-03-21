// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "exchg/exchg.h"
#include "fake-bitstamp.h"
#include "fake-net.h"
#include "util.h"

struct bitstamp_websocket {
        int conn_id_sent;
        struct bitstamp_channel {
                bool diff_subbed;
                bool full_subbed;
                bool full_unsubbed;
        } channels[EXCHG_NUM_PAIRS];
};

static void write_orders_side(struct buf *buf,
                              struct exchg_test_l2_updates *update,
                              bool is_bids)
{
        struct exchg_test_l2_update *orders;
        int n;

        if (is_bids) {
                n = update->num_bids;
                orders = &update->bids[0];
        } else {
                n = update->num_asks;
                orders = &update->asks[0];
        }

        if (n < 1)
                return;

        buf_xsprintf(buf, "\"%s\": [", is_bids ? "bids" : "asks");
        for (int i = 0; i < n; i++) {
                char size[30], price[30];
                decimal_to_str(size, &orders[i].size);
                decimal_to_str(price, &orders[i].price);
                buf_xsprintf(buf, "[ \"%s\", \"%s\"], ", price, size);
        }
        buf_xsprintf(buf, "], ");
}

static void write_orders(struct buf *buf, struct exchg_test_l2_updates *update,
                         bool is_diff)
{
        buf_xsprintf(buf, "{ \"data\": {\"timestamp\": \"123\", "
                          "\"microtimestamp\": \"123000\", ");
        write_orders_side(buf, update, true);
        write_orders_side(buf, update, false);
        buf_xsprintf(buf,
                     "}, \"channel\": \"%sorder_book_%s\", "
                     "\"event\": \"data\" }",
                     is_diff ? "diff_" : "", exchg_pair_to_str(update->pair));
}

enum proto_type {
        NONSENSE_DIFF,
        UNSUB_SUCCEEDED,
};

struct bitstamp_proto {
        enum proto_type type;
        enum exchg_pair pair;
};

static void proto_read(struct buf *buf, struct bitstamp_proto *bp)
{
        if (bp->type == NONSENSE_DIFF) {
                decimal_t dummy_value = {.places = 0, .value = 1};
                struct exchg_test_l2_updates u = {
                    .pair = bp->pair,
                };
                exchg_test_l2_queue_order(&u, true, &dummy_value, &dummy_value);
                exchg_test_l2_queue_order(&u, false, &dummy_value,
                                          &dummy_value);
                write_orders(buf, &u, true);
                free(u.bids);
                free(u.asks);
        } else if (bp->type == UNSUB_SUCCEEDED) {
                buf_xsprintf(buf,
                             "{ \"event\": \""
                             "bts:unsubscription_succeeded\","
                             " \"channel\": \"order_book_%s\""
                             ", \"data\": { } }",
                             exchg_pair_to_str(bp->pair));
        }
}

static void bitstamp_ws_read(struct websocket_conn *ws, struct buf *buf,
                             struct exchg_test_event *msg)
{
        struct bitstamp_websocket *b = ws->priv;

        if (msg->type == EXCHG_EVENT_WS_PROTOCOL) {
                proto_read(buf,
                           (struct bitstamp_proto *)test_event_private(msg));
                return;
        }

        struct exchg_test_l2_updates *u = &msg->data.book;
        struct bitstamp_channel *c = &b->channels[u->pair];
        write_orders(buf, u,
                     c->diff_subbed && (!c->full_subbed || c->full_unsubbed));
}

static int bitstamp_ws_matches(struct websocket_conn *w,
                               struct exchg_test_event *ev)
{
        struct bitstamp_websocket *b = w->priv;
        if (ev->type == EXCHG_EVENT_BOOK_UPDATE) {
                enum exchg_pair p = ev->data.book.pair;
                return b->channels[p].diff_subbed || b->channels[p].full_subbed;
        }
        return 0;
}

static int get_channel(const char *c, enum exchg_pair *p, bool *is_full)
{
        const char *quote = c;

        while (*quote && *quote != '\"')
                quote++;
        if (!*quote) {
                fprintf(stderr, "%s: unquoted\n", __func__);
                return -1;
        }
        if (quote - c < 6 + strlen("order_book_")) {
                fprintf(stderr, "%s: too small\n", __func__);
                return -1;
        }
        if (!strncmp(c, "diff_order_book_", strlen("diff_order_book_")))
                *is_full = false;
        else if (!strncmp(c, "order_book_", strlen("order_book_")))
                *is_full = true;
        else {
                fprintf(stderr, "%s: bad channel\n", __func__);
                return -1;
        }
        char pair[7];
        memcpy(pair, quote - 6, 6);
        pair[6] = 0;
        if (exchg_str_to_pair(p, pair)) {
                fprintf(stderr, "%s: bad pair\n", __func__);
                return -1;
        }
        return 0;
}

static void bitstamp_ws_write(struct websocket_conn *w, const char *buf,
                              size_t len)
{
        struct bitstamp_websocket *b = w->priv;
        enum exchg_pair p;
        bool is_full;

        // TODO: actually parse it
        if (!strncmp("{ \"event\": \"bts:subscribe\","
                     "\"data\": { \"channel\": \"",
                     buf,
                     strlen("{ \"event\": \"bts:subscribe\","
                            "\"data\": { \"channel\": \""))) {
                if (get_channel(buf + strlen("{ \"event\": \"bts:subscribe\","
                                             "\"data\": { \"channel\": \""),
                                &p, &is_full))
                        return;
                if (is_full) {
                        b->channels[p].full_subbed = true;
                } else {
                        b->channels[p].diff_subbed = true;
                        struct bitstamp_proto *bp =
                            test_event_private(exchg_fake_queue_ws_event(
                                w, EXCHG_EVENT_WS_PROTOCOL,
                                sizeof(struct bitstamp_proto)));
                        bp->type = NONSENSE_DIFF;
                        bp->pair = p;
                }
        } else if (!strncmp("{ \"event\": \"bts:unsubscribe\","
                            "\"data\": { \"channel\": \"",
                            buf,
                            strlen("{ \"event\": \"bts:unsubscribe\","
                                   "\"data\": { \"channel\": \""))) {
                if (get_channel(buf + strlen("{ \"event\": \"bts:unsubscribe\","
                                             "\"data\": { \"channel\": \""),
                                &p, &is_full))
                        return;
                if (is_full) {
                        struct bitstamp_proto *bp =
                            test_event_private(exchg_fake_queue_ws_event(
                                w, EXCHG_EVENT_WS_PROTOCOL,
                                sizeof(struct bitstamp_proto)));
                        bp->type = UNSUB_SUCCEEDED;
                        bp->pair = p;
                        b->channels[p].full_unsubbed = true;
                } else {
                        fprintf(stderr,
                                "Bitsamp unsubbed from diff order book?\n");
                }
        }
}

static void bitstamp_ws_destroy(struct websocket_conn *w)
{
        free(w->priv);
        ws_conn_free(w);
}

struct websocket_conn *bitstamp_ws_dial(struct exchg_net_context *ctx,
                                        const char *path, void *private)
{
        struct websocket_conn *s = fake_websocket_alloc(ctx, private);
        s->read = bitstamp_ws_read;
        s->write = bitstamp_ws_write;
        s->matches = bitstamp_ws_matches;
        s->destroy = bitstamp_ws_destroy;
        struct bitstamp_websocket *b = xzalloc(sizeof(*b));
        s->priv = b;
        return s;
}

static void bitstamp_pair_info_read(struct http_conn *req,
                                    struct exchg_test_event *ev,
                                    struct buf *buf)
{
        if (!req->ctx->options.bitstamp_info_file) {
                fprintf(stderr, "test: no bitstamp_info_file set in "
                                "exchg_test_options. Please set it\n");
                exit(1);
        }
        if (buf_read_file(buf, req->ctx->options.bitstamp_info_file)) {
                fprintf(stderr,
                        "test: reading bitstamp_info_file failed. Aborting\n");
                exit(1);
        }
}

static struct http_conn *asset_pairs_dial(struct exchg_net_context *ctx,
                                          const char *path, const char *method,
                                          void *private)
{
        if (strcmp(method, "GET")) {
                fprintf(stderr, "Bitstamp bad method for %s: %s\n", path,
                        method);
                return NULL;
        }

        struct http_conn *req = fake_http_conn_alloc(
            ctx, EXCHG_BITSTAMP, EXCHG_EVENT_PAIRS_DATA, private);
        req->read = bitstamp_pair_info_read;
        req->write = no_http_write;
        req->add_header = no_http_add_header;
        req->destroy = fake_http_conn_free;
        return req;
}

static void bitstamp_balance_read(struct http_conn *req,
                                  struct exchg_test_event *ev, struct buf *buf)
{
        buf_xsprintf(buf, "{ ");
        for (enum exchg_currency c = 0; c < EXCHG_NUM_CCYS; c++) {
                char s[30];
                decimal_to_str(s,
                               &req->ctx->servers[EXCHG_BITSTAMP].balances[c]);
                buf_xsprintf(buf, "\"%s_available\": \"%s\", ",
                             exchg_ccy_to_str(c), s);
                // TODO: other fields too
        }
        buf_xsprintf(buf, " }");
}

static struct http_conn *balance_dial(struct exchg_net_context *ctx,
                                      const char *path, const char *method,
                                      void *private)
{
        if (strcmp(method, "POST")) {
                fprintf(stderr, "Bitstamp bad method for %s: %s\n", path,
                        method);
                return NULL;
        }

        struct http_conn *req = fake_http_conn_alloc(
            ctx, EXCHG_BITSTAMP, EXCHG_EVENT_BALANCES, private);
        req->read = bitstamp_balance_read;
        req->write = no_http_write;
        // TODO:
        req->add_header = no_http_add_header;
        req->destroy = fake_http_conn_free;
        return req;
}

struct http_conn *bitstamp_http_dial(struct exchg_net_context *ctx,
                                     const char *path, const char *method,
                                     void *private)
{
        if (!strcmp(path, "/api/v2/trading-pairs-info/")) {
                return asset_pairs_dial(ctx, path, method, private);
        }
        if (!strcmp(path, "/api/v2/balance/")) {
                return balance_dial(ctx, path, method, private);
        }
        fprintf(stderr, "Bitstamp bad path: %s\n", path);
        return NULL;
}
