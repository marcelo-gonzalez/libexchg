// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "auth.h"
#include "bitstamp.h"
#include "client.h"
#include "exchg/currency.h"
#include "exchg/decimal.h"
#include "json-helpers.h"
#include "time-helpers.h"

enum BTS_STATE {
        BTS_BOOK_COMPLETE = 1,
        BTS_FULL_SUBBED = (1 << 1),
        BTS_ACTIVE = (1 << 2),
};

struct bitstamp_client {
        struct bts_pair_info {
                int state;
                int64_t last_diff_update;
                int64_t first_full_update;
        } pair_info[EXCHG_NUM_PAIRS];
        struct websocket *ws;
        char *api_header;
        size_t api_header_len;
};

static int bitstamp_subscribe_event(struct websocket *w, enum exchg_pair pair,
                                    const char *event)
{
        if (websocket_printf(w,
                             "{ \"event\": \"bts:subscribe\","
                             "\"data\": { \"channel\": \"%s_%s\"} }",
                             event, exchg_pair_to_str(pair)) < 0)
                return -1;
        return 0;
}

static int bitstamp_unsubscribe_event(struct websocket *w, enum exchg_pair pair,
                                      const char *event)
{
        if (websocket_printf(w,
                             "{ \"event\": \"bts:unsubscribe\","
                             "\"data\": { \"channel\": \"%s_%s\"} }",
                             event, exchg_pair_to_str(pair)) < 0)
                return -1;
        return 0;
}

enum event_type {
        EVENT_UNKNOWN,
        EVENT_SUB,
        EVENT_UNSUB,
        EVENT_DATA,
};

enum channel_type {
        CHAN_UNKNOWN,
        CHAN_FULL,
        CHAN_DIFF,
};

struct bitstamp_msg {
        enum event_type ev_type;
        enum channel_type chan_type;
        enum exchg_pair pair;
        bool received_data;
        int64_t timestamp;
        bool need_fee_calc;
        bool need_time_fill;
};

static int fill_orders(struct exchg_client *cl, const char *json, int num_toks,
                       jsmntok_t *toks, int idx, struct bitstamp_msg *msg,
                       bool is_bids)
{
        const char *problem;
        if (toks[idx].type != JSMN_ARRAY) {
                problem = "not an array";
                goto bad;
        }

        int size = toks[idx].size;
        int i;

        for (i = 0, idx += 1; i < size; i++, idx += 3) {
                jsmntok_t *order = &toks[idx];
                jsmntok_t *price = &toks[idx + 1];
                jsmntok_t *size = &toks[idx + 2];

                if (order->type != JSMN_ARRAY) {
                        problem = "not an array";
                        goto bad;
                }
                if (order->size != 2) {
                        problem = "size != 2";
                        goto bad;
                }

                int *next;
                struct exchg_limit_order *o;

                if (is_bids) {
                        next = &cl->update.num_bids;
                        o = &cl->update.bids[*next];
                } else {
                        next = &cl->update.num_asks;
                        o = &cl->update.asks[*next];
                }

                if (*next >= cl->l2_update_size &&
                    exchg_realloc_order_bufs(cl, 2 * cl->l2_update_size))
                        return -1;

                o->update_micros = msg->timestamp;
                o->exchange_id = cl->id;
                if (json_get_decimal(&o->price, json, price) ||
                    json_get_decimal(&o->size, json, size)) {
                        problem = "bad price/size";
                        goto bad;
                }
                if (msg->pair == INVALID_PAIR)
                        msg->need_fee_calc = true;
                else {
                        struct exchg_pair_info *pi = &cl->pair_info[msg->pair];
                        if (is_bids)
                                decimal_dec_bps(&o->net_price, &o->price,
                                                pi->fee_bps,
                                                pi->price_decimals);
                        else
                                decimal_inc_bps(&o->net_price, &o->price,
                                                pi->fee_bps,
                                                pi->price_decimals);
                }
                (*next)++;
        }
        return idx;

bad:
        exchg_log("Bitstamp sent bad order book update: %s:\n", problem);
        json_fprintln(stderr, json, &toks[0]);
        return -1;
}

static int parse_data(struct exchg_client *cl, struct bitstamp_msg *msg,
                      const char *json, int num_toks, jsmntok_t *toks, int idx)
{
        jsmntok_t *data = &toks[idx];

        msg->received_data = true;

        if (msg->ev_type == EVENT_SUB || msg->ev_type == EVENT_UNSUB)
                return json_skip(num_toks, toks, idx);

        const char *problem;
        // from here on, even if event type is unknown, assume it's EVENT_DATA
        // and parse orders for an update
        if (data->type != JSMN_OBJECT) {
                problem = "not an object";
                goto bad;
        }

        int key_idx = idx + 1;

        for (int i = 0; i < data->size; i++) {
                jsmntok_t *key = &toks[key_idx];
                jsmntok_t *value = &toks[key_idx + 1];

                if (json_streq(json, key, "microtimestamp")) {
                        if (json_get_int64(&msg->timestamp, json, value)) {
                                problem = "bad \"microtimestamp\"";
                                goto bad;
                        }
                        key_idx += 2;
                } else if (json_streq(json, key, "bids")) {
                        if (msg->timestamp == -1)
                                msg->need_time_fill = true;
                        key_idx = fill_orders(cl, json, num_toks, toks,
                                              key_idx + 1, msg, true);
                        if (key_idx < 0)
                                return -1;
                } else if (json_streq(json, key, "asks")) {
                        if (msg->timestamp == -1)
                                msg->need_time_fill = true;
                        key_idx = fill_orders(cl, json, num_toks, toks,
                                              key_idx + 1, msg, false);
                        if (key_idx < 0)
                                return -1;
                } else {
                        key_idx = json_skip(num_toks, toks, key_idx + 1);
                }
        }
        if (msg->timestamp == -1) {
                problem = "no \"microtimestamp\"";
                goto bad;
        }
        return key_idx;

bad:
        exchg_log("Bitstamp sent update with bad \"data\" field: %s:\n",
                  problem);
        json_fprintln(stderr, json, &toks[0]);
        return -1;
}

static void do_update(struct exchg_client *cl, struct bitstamp_msg *msg)
{
        if (!msg->need_time_fill && !msg->need_fee_calc) {
                exchg_l2_update(cl, msg->pair);
                return;
        }

        struct exchg_pair_info *pi = &cl->pair_info[msg->pair];
        for (int i = 0; i < cl->update.num_bids; i++) {
                struct exchg_limit_order *o = &cl->update.bids[i];
                if (msg->need_fee_calc)
                        decimal_dec_bps(&o->net_price, &o->price, pi->fee_bps,
                                        pi->price_decimals);
                if (msg->need_time_fill)
                        o->update_micros = msg->timestamp;
        }
        for (int i = 0; i < cl->update.num_asks; i++) {
                struct exchg_limit_order *o = &cl->update.asks[i];
                if (msg->need_fee_calc)
                        decimal_inc_bps(&o->net_price, &o->price, pi->fee_bps,
                                        pi->price_decimals);
                if (msg->need_time_fill)
                        o->update_micros = msg->timestamp;
        }
        exchg_l2_update(cl, msg->pair);
}

static int msg_complete(struct exchg_client *cl, struct websocket *w,
                        struct bitstamp_msg *msg)
{
        struct bitstamp_client *bts = client_private(cl);
        struct bts_pair_info *pi;

        switch (msg->ev_type) {
        case EVENT_UNKNOWN:
                return 0;
        case EVENT_SUB:
        case EVENT_UNSUB:
                return 1;
        case EVENT_DATA:
                if (!msg->received_data || msg->pair == INVALID_PAIR ||
                    msg->chan_type == CHAN_UNKNOWN)
                        return 0;
                pi = &bts->pair_info[msg->pair];

                if (!(pi->state & BTS_BOOK_COMPLETE)) {
                        if (!(pi->state & BTS_FULL_SUBBED)) {
                                if (bitstamp_subscribe_event(w, msg->pair,
                                                             "order_book"))
                                        return -1;
                                pi->state |= BTS_FULL_SUBBED;
                        }

                        if (msg->chan_type == CHAN_DIFF) {
                                pi->last_diff_update = msg->timestamp;
                                if (pi->first_full_update == 0 ||
                                    msg->timestamp <= pi->first_full_update)
                                        return 1;
                                do_update(cl, msg);
                                pi->state |= BTS_BOOK_COMPLETE;
                                return 1;
                        }

                        if (pi->first_full_update != 0)
                                return 1;

                        // wait until we know there are no previous diff updates
                        // relevant to this full snapshot. Could avoid returning
                        // here by writing code to remember the old diffs until
                        // we establish a working book but this is fine for now
                        if (pi->last_diff_update > msg->timestamp)
                                return 1;

                        do_update(cl, msg);
                        pi->first_full_update = msg->timestamp;
                        if (bitstamp_unsubscribe_event(w, msg->pair,
                                                       "order_book"))
                                return -1;
                        else
                                return 1;
                }

                if (msg->chan_type == CHAN_DIFF)
                        do_update(cl, msg);
                return 1;
        default:
                exchg_log("%s: bad ev_type (%d) ?\n", __func__, msg->ev_type);
                return -1;
        }
}

static int bitstamp_recv(struct exchg_client *cl, struct websocket *w,
                         char *json, int num_toks, jsmntok_t *toks)
{
        if (num_toks < 3)
                return 0;

        if (toks[0].type != JSMN_OBJECT) {
                exchg_log("bitstamp sent a non-object JSON message\n");
                return -1;
        }

        const char *problem;
        struct bitstamp_msg msg = {
            .ev_type = EVENT_UNKNOWN,
            .chan_type = CHAN_UNKNOWN,
            .pair = INVALID_PAIR,
            .timestamp = -1,
        };

        exchg_update_init(cl);

        for (int key_idx = 1; key_idx < num_toks;) {
                jsmntok_t *key = &toks[key_idx], *value = &toks[key_idx + 1];

                if (json_streq(json, key, "data")) {
                        key_idx = parse_data(cl, &msg, json, num_toks, toks,
                                             key_idx + 1);
                        if (key_idx < 0)
                                return -1;
                } else if (json_streq(json, key, "event")) {
                        if (json_streq(json, value,
                                       "bts:subscription_succeeded")) {
                                // Nothing to do...
                                return 0;
                        } else if (json_streq(json, value,
                                              "bts:unsubscription_succeeded")) {
                                msg.ev_type = EVENT_UNSUB;
                        } else if (json_streq(json, value, "data")) {
                                msg.ev_type = EVENT_DATA;
                        } else {
                                problem = "bad event field";
                                goto bad;
                        }
                        key_idx += 2;
                } else if (json_streq(json, key, "channel")) {
                        const char *currency;
                        size_t currency_len;
                        if (value->end - value->start > strlen("order_book_") &&
                            !strncmp(&json[value->start], "order_book_",
                                     strlen("order_book_"))) {
                                msg.chan_type = CHAN_FULL;
                                currency =
                                    &json[value->start + strlen("order_book_")];
                                currency_len = value->end - value->start -
                                               strlen("order_book_");
                        } else if (value->end - value->start >
                                       strlen("diff_order_book_") &&
                                   !strncmp(&json[value->start],
                                            "diff_order_book_",
                                            strlen("diff_order_book_"))) {
                                msg.chan_type = CHAN_DIFF;
                                currency = &json[value->start +
                                                 strlen("diff_order_book_")];
                                currency_len = value->end - value->start -
                                               strlen("diff_order_book_");
                        } else {
                                problem = "bad channel field";
                                goto bad;
                        }
                        if (exchg_strn_to_pair(&msg.pair, currency,
                                               currency_len)) {
                                problem = "bad currency in channel field";
                                goto bad;
                        }
                        key_idx += 2;
                } else if (json_streq(json, key, "bts:request_reconnect")) {
                        exchg_log(
                            "Bitstamp requested reconnect. Reconnecting...\n");
                        return -1;
                } else if (json_streq(json, key, "bts:error")) {
                        json_fprintln(stderr, json, &toks[0]);
                        return -1;
                } else {
                        exchg_log("Bitstamp sent unknown event:\n");
                        json_fprintln(stderr, json, &toks[0]);
                        return 0;
                }

                int r = msg_complete(cl, w, &msg);
                if (r < 0)
                        return -1;
                if (r)
                        return 0;
        }
        exchg_log("bitstamp received incomplete message:\n");
        json_fprintln(stderr, json, &toks[0]);
        // TODO: return -1 ?
        return 0;

bad:
        exchg_log("Bitstamp sent bad message: %s:\n", problem);
        json_fprintln(stderr, json, &toks[0]);
        return -1;
}

static int book_sub(struct exchg_client *cl)
{
        struct bitstamp_client *bts = client_private(cl);
        for (enum exchg_pair pair = 0; pair < EXCHG_NUM_PAIRS; pair++) {
                struct bts_pair_info *bpi = &bts->pair_info[pair];
                struct exchg_pair_info *pi = &cl->pair_info[pair];
                bpi->state &= BTS_ACTIVE;
                if (!(bpi->state & BTS_ACTIVE))
                        continue;

                if (!pi->available) {
                        exchg_log("pair %s not available on bitstamp\n",
                                  exchg_pair_to_str(pair));
                        continue;
                }
                if (bitstamp_subscribe_event(bts->ws, pair, "diff_order_book"))
                        return -1;
        }
        return 0;
}

static bool book_sub_work(struct exchg_client *cl, void *p)
{
        struct bitstamp_client *bts = client_private(cl);

        if (!cl->pair_info_current || !websocket_established(bts->ws))
                return false;

        book_sub(cl);
        return true;
}

static int bitstamp_conn_established(struct exchg_client *cl,
                                     struct websocket *w)
{
        if (!cl->pair_info_current)
                return queue_work_exclusive(cl, book_sub_work, NULL);
        else
                return book_sub(cl);
}

static int bitstamp_on_disconnect(struct exchg_client *cl, struct websocket *w,
                                  int reconnect_seconds)
{
        struct bitstamp_client *bts = client_private(cl);
        int num_pairs_gone = 0;
        enum exchg_pair pairs_gone[EXCHG_NUM_PAIRS];

        if (reconnect_seconds < 0)
                bts->ws = NULL;

        for (enum exchg_pair pair = 0; pair < EXCHG_NUM_PAIRS; pair++) {
                struct exchg_pair_info *pi = &cl->pair_info[pair];
                struct bts_pair_info *bpi = &bts->pair_info[pair];
                if (bpi->state & BTS_ACTIVE && pi->available) {
                        pairs_gone[num_pairs_gone++] = pair;
                        exchg_book_clear(cl, pair);
                }
                bpi->last_diff_update = 0;
                bpi->first_full_update = 0;
                bpi->state &= BTS_ACTIVE;
        }
        exchg_data_disconnect(cl, w, num_pairs_gone, pairs_gone);
        return 0;
}

static const struct exchg_websocket_ops websocket_ops = {
    .on_conn_established = bitstamp_conn_established,
    .on_disconnect = bitstamp_on_disconnect,
    .recv = bitstamp_recv,
};

static int bitstamp_connect(struct exchg_client *cl,
                            const struct exchg_websocket_options *options)
{
        struct bitstamp_client *bts = client_private(cl);

        bts->ws = exchg_websocket_connect(cl, "ws.bitstamp.net", "/",
                                          &websocket_ops, options);
        if (bts->ws)
                return 0;
        return -1;
}

struct bitstamp_pair_info {
        enum exchg_pair pair;
        bool enabled;
        bool dont_care;
        int base_decimals;
        int price_decimals;
        decimal_t min_size;
        enum exchg_currency min_currency;
        bool min_order_good;
};

static int parse_info_token(struct bitstamp_pair_info *info, char *json,
                            int num_toks, jsmntok_t *toks, int key_idx,
                            char *problem)
{
        jsmntok_t *key = &toks[key_idx];
        jsmntok_t *value = &toks[key_idx + 1];

        if (info->dont_care)
                return json_skip(num_toks, toks, key_idx + 1);

        if (json_streq(json, key, "base_decimals")) {
                if (json_get_int(&info->base_decimals, json, value)) {
                        sprintf(problem, "can't parse base_decimals field");
                        return -1;
                }
                return key_idx + 2;
        } else if (json_streq(json, key, "counter_decimals")) {
                if (json_get_int(&info->price_decimals, json, value)) {
                        sprintf(problem, "can't parse counter_decimals field");
                        return -1;
                }
                return key_idx + 2;
        } else if (json_streq(json, key, "url_symbol")) {
                if (value->type != JSMN_STRING) {
                        sprintf(problem, "non string url_symbol field");
                        return -1;
                }
                if (json_get_pair(&info->pair, json, value)) {
                        info->dont_care = true;
                }
                return key_idx + 2;
        } else if (json_streq(json, key, "trading")) {
                if (json_streq(json, value, "Enabled")) {
                        info->enabled = true;
                }
                return key_idx + 2;
        } else if (json_streq(json, key, "minimum_order")) {
                size_t len = 0;
                for (const char *space = &json[value->start];
                     space < &json[value->end]; space++) {
                        if (isspace(*space)) {
                                len = space - &json[value->start];
                                break;
                        }
                }
                if (len == 0) {
                        sprintf(problem, "bad minimum_order field");
                        return -1;
                }
                if (decimal_from_str_n(&info->min_size, &json[value->start],
                                       len)) {
                        sprintf(problem, "bad minimum_order field");
                        return -1;
                }
                const char *c = &json[value->start + len];
                while (isspace(*c) && c < &json[value->end])
                        c++;
                if (c == &json[value->end]) {
                        sprintf(problem, "bad minimum_order field");
                        return -1;
                }
                if (!exchg_strn_to_ccy(&info->min_currency, c,
                                       &json[value->end] - c))
                        info->min_order_good = true;
                return key_idx + 2;
        } else
                return json_skip(num_toks, toks, key_idx + 1);
}

static int bitstamp_parse_info(struct exchg_client *cl, struct http *http,
                               int status, char *json, int num_toks,
                               jsmntok_t *toks)
{
        char problem[100];
        if (status != 200) {
                fprintf(stderr,
                        "status %d from https://www.bitstamp.net"
                        "/api/v2/trading-pairs-info/:\n",
                        status);
                if (num_toks > 0)
                        json_fprintln(stderr, json, &toks[0]);
                return -1;
        }

        if (num_toks < 2) {
                sprintf(problem, "no data received");
                goto out_bad;
        }
        if (toks[0].type != JSMN_ARRAY) {
                sprintf(problem, "didn't receive a JSON array\n");
                goto out_bad;
        }

        int key_idx = 1;
        for (int i = 0; i < toks[0].size; i++) {
                jsmntok_t *tok = &toks[key_idx];
                if (tok->type != JSMN_OBJECT) {
                        sprintf(problem, "found non-object array element");
                        goto out_bad;
                }
                struct bitstamp_pair_info info = {
                    .pair = -1,
                    .base_decimals = -1,
                    .price_decimals = -1,
                    .min_currency = -1,
                };

                key_idx++;
                for (int j = 0; j < tok->size; j++) {
                        key_idx = parse_info_token(&info, json, num_toks, toks,
                                                   key_idx, problem);
                        if (key_idx < 0)
                                goto out_bad;
                }
                if (info.dont_care)
                        continue;
                if (info.pair == -1) {
                        sprintf(problem,
                                "pair info without a url_symbol field");
                        goto out_bad;
                }
                if (info.base_decimals == -1 || info.price_decimals == -1) {

                        sprintf(problem,
                                "pair info with incomplete decimals info");
                        goto out_bad;
                }
                if (!info.min_order_good) {
                        sprintf(problem,
                                "pair info without valid minimum_order field");
                        goto out_bad;
                }
                if (!info.enabled) {
                        exchg_log(
                            "bitstamp indicates trading not enabled for %s.\n",
                            exchg_pair_to_str(info.pair));
                        continue;
                }
                struct exchg_pair_info *pi = &cl->pair_info[info.pair];
                pi->available = true;
                // TODO: get from bitstamp.net/api/v2/balance/

                pi->fee_bps = 50;
                pi->base_decimals = info.base_decimals;
                pi->price_decimals = info.price_decimals;

                enum exchg_currency base, counter;
                exchg_pair_split(&base, &counter, info.pair);
                if (info.min_currency == base)
                        pi->min_size_is_base = true;
                else if (info.min_currency == counter)
                        pi->min_size_is_base = false;
                else {
                        sprintf(problem, "bad minimum_order field");
                        goto out_bad;
                }
                pi->min_size = info.min_size;
        }

        exchg_on_pair_info(cl);
        exchg_do_work(cl);
        return 0;

out_bad:
        cl->get_info_error = -1;
        exchg_log("bad response from "
                  "https://www.bitstamp.net/api/v2/trading-pairs-info/: %s\n",
                  problem);
        return -1;
}

static struct exchg_http_ops get_info_ops = {
    .recv = bitstamp_parse_info,
    .on_established = exchg_parse_info_on_established,
    .on_closed = exchg_parse_info_on_closed,
    .on_error = exchg_parse_info_on_error,
};

static int bitstamp_l2_subscribe(struct exchg_client *cl, enum exchg_pair pair,
                                 const struct exchg_websocket_options *options)
{
        struct bitstamp_client *bts = client_private(cl);
        struct bts_pair_info *bpi = &bts->pair_info[pair];

        if (bpi->state & BTS_ACTIVE && bts->ws)
                return 0;

        bpi->state |= BTS_ACTIVE;
        if (cl->pair_info_current && websocket_established(bts->ws))
                return bitstamp_subscribe_event(bts->ws, pair,
                                                "diff_order_book");

        if (!bts->ws)
                return bitstamp_connect(cl, options);
        else
                websocket_log_options_discrepancies(bts->ws, options);
        return 0;
}

static int bitstamp_get_pair_info(struct exchg_client *cl)
{
        if (!exchg_http_get("www.bitstamp.net", "/api/v2/trading-pairs-info/",
                            &get_info_ops, cl, NULL))
                return -1;
        return 0;
}

struct http_data {
        void *p;
        char path[100];
        size_t payload_len;
        void *request_private;
};

static int balances_recv(struct exchg_client *cl, struct http *http, int status,
                         char *json, int num_toks, jsmntok_t *toks)
{
        if (num_toks < 1) {
                exchg_log("Bitstamp sent bad balance info:"
                          " no json fields received\n");
                return 0;
        }

        if (status != 200) {
                exchg_log("Bitstamp status %d getting balances:\n", status);
                json_fprintln(stderr, json, &toks[0]);
                return 0;
        }

        if (toks[0].type != JSMN_OBJECT) {
                exchg_log("Bitstamp sent non-object balance info:\n");
                json_fprintln(stderr, json, &toks[0]);
                return 0;
        }

        decimal_t balances[EXCHG_NUM_CCYS];
        memset(balances, 0, sizeof(balances));

        int key_idx = 1;
        for (int i = 0; i < toks[0].size; i++) {
                jsmntok_t *key = &toks[key_idx];
                jsmntok_t *value = &toks[key_idx + 1];
                enum exchg_currency c;

                if (key->end - key->start != strlen("_available") + 3 ||
                    memcmp("_available", &json[key->start + 3],
                           strlen("_available")) ||
                    exchg_strn_to_ccy(&c, &json[key->start], 3)) {
                        key_idx = json_skip(num_toks, toks, key_idx + 1);
                        continue;
                }

                if (json_get_decimal(&balances[c], json, value)) {
                        char s[4 + strlen("_available")];
                        memcpy(s, &json[key->start], 3 + strlen("_available"));
                        s[3 + strlen("_available")] = 0;
                        exchg_log("Bitstamp set bad balance info:"
                                  " bad \"%s\" value:\n",
                                  s);
                        json_fprintln(stderr, json, &toks[0]);
                        return 0;
                }
                key_idx += 2;
        }
        struct http_data *h = http_private(http);
        exchg_on_balances(cl, balances, h->request_private);
        return 0;
}

static int string_to_sign(char *dst, struct exchg_client *cl,
                          const char *millis, const char *nonce,
                          const char *host, const char *path,
                          const char *payload)
{
        struct bitstamp_client *bts = client_private(cl);
        const char *content_type =
            payload && *payload ? "application/x-www-form-urlencoded" : "";
        if (!payload)
                payload = "";
        return sprintf(dst, "%sPOST%s%s%s%s%sv2%s", bts->api_header, host, path,
                       content_type, nonce, millis, payload);
}

void bitstamp_get_nonce(char *dst)
{
        int len = sprintf(dst, "%" PRId64, current_micros());
        for (int i = len; i < 36; i++)
                dst[i] = dst[i % len];
        dst[36] = 0;
}

static int add_headers(struct exchg_client *cl, struct http *http)
{
        struct bitstamp_client *bts = client_private(cl);
        struct http_data *h = http_private(http);
        char millis[30], nonce[37];
        size_t millis_len;
        char to_auth[400];

        millis_len = sprintf(millis, "%" PRId64, current_millis());
        bitstamp_get_nonce(nonce);

        int len = string_to_sign(to_auth, cl, millis, nonce, "www.bitstamp.net",
                                 h->path, http_body(http));
        char hmac[HMAC_SHA256_HEX_LEN];
        size_t hmac_len;
        int err = hmac_ctx_hex(&cl->hmac_ctx, (unsigned char *)to_auth, len,
                               hmac, &hmac_len, HEX_UPPER);
        if (err)
                return -1;

        if (http_add_header(http, (unsigned char *)"X-Auth:",
                            (unsigned char *)bts->api_header,
                            bts->api_header_len))
                return 1;
        if (http_add_header(http, (unsigned char *)"X-Auth-Signature:",
                            (unsigned char *)hmac, hmac_len))
                return 1;
        if (http_add_header(http, (unsigned char *)"X-Auth-Timestamp:",
                            (unsigned char *)millis, millis_len))
                return 1;
        if (http_add_header(http, (unsigned char *)"X-Auth-Nonce:",
                            (unsigned char *)nonce, 36))
                return 1;
        if (http_add_header(http, (unsigned char *)"X-Auth-Version:",
                            (unsigned char *)"v2", 2))
                return 1;
        if (h->payload_len > 0) {
                if (http_add_header(
                        http, (unsigned char *)"Content-Type:",
                        (unsigned char *)"application/x-www-form-urlencoded",
                        strlen("application/x-www-form-urlencoded")))
                        return 1;
                char l[16];
                len = sprintf(l, "%zu", h->payload_len);
                if (http_add_header(http, (unsigned char *)"Content-Length:",
                                    (unsigned char *)l, len))
                        return 1;
        }
        return 0;
}

static struct exchg_http_ops get_balances_ops = {
    .recv = balances_recv,
    .add_headers = add_headers,
    .conn_data_size = sizeof(struct http_data),
};

static int bitstamp_get_balances(struct exchg_client *cl,
                                 const struct exchg_request_options *options)
{
        struct http *http =
            exchg_http_post("www.bitstamp.net", "/api/v2/balance/",
                            &get_balances_ops, cl, options);
        if (!http)
                return -1;
        struct http_data *h = http_private(http);
        snprintf(h->path, sizeof(h->path), "/api/v2/balance/");
        h->payload_len = 0;
        h->request_private = options ? options->user : NULL;
        return 0;
}

// UNTESTED!!!
static int place_order_recv(struct exchg_client *cl, struct http *http,
                            int status, char *json, int num_toks,
                            jsmntok_t *toks)
{
        struct http_data *h = http_private(http);
        struct order_info *oi = h->p;
        struct exchg_order_info *info = &oi->info;
        const char *problem;

        if (toks[0].type != JSMN_OBJECT) {
                problem = "non-object JSON";
                goto bad;
        }

        decimal_t size;
        bool got_size = false;
        bool is_err = false;
        int64_t id = -1;

        int key_idx = 1;
        for (int i = 0; i < toks[0].size; i++) {
                jsmntok_t *key = &toks[key_idx];
                jsmntok_t *value = &toks[key_idx + 1];

                if (json_streq(json, key, "status")) {
                        is_err = true;
                        key_idx = json_skip(num_toks, toks, key_idx + 1);
                } else if (json_streq(json, key, "reason")) {
                        if (value->type != JSMN_OBJECT) {
                                json_strncpy(info->err, json, value,
                                             EXCHG_ORDER_ERR_SIZE);
                                key_idx =
                                    json_skip(num_toks, toks, key_idx + 1);
                        } else {
                                int next_key =
                                    json_skip(num_toks, toks, key_idx + 1);
                                key_idx += 2;
                                for (int j = 0; j < value->size; j++) {
                                        key = &toks[key_idx];
                                        value = &toks[key_idx + 1];

                                        if (json_streq(json, key, "__all__")) {
                                                json_strncpy(
                                                    info->err, json, value,
                                                    EXCHG_ORDER_ERR_SIZE);
                                                break;
                                        }
                                }
                                if (!*info->err)
                                        strncpy(info->err, "<unknown>",
                                                EXCHG_ORDER_ERR_SIZE);
                                key_idx = next_key;
                        }
                } else if (json_streq(json, key, "id")) {
                        if (json_get_int64(&id, json, value)) {
                                problem = "bad \"id\"";
                                goto bad;
                        }
                        if (id != info->id) {
                                problem = "non-matching \"id\"";
                                goto bad;
                        }
                        key_idx += 2;
                } else if (json_streq(json, key, "size")) {
                        if (json_get_decimal(&size, json, value)) {
                                problem = "bad \"size\"";
                                goto bad;
                        }
                        got_size = true;
                        key_idx += 2;
                } else {
                        key_idx = json_skip(num_toks, toks, key_idx + 1);
                }
        }

        if (!is_err && !got_size) {
                problem = "missing \"size\"";
                goto bad;
        }
        if (!is_err && id == -1) {
                problem = "missing \"id\"";
                goto bad;
        }
        if (is_err && !*info->err)
                strncpy(info->err, "<unknown>", EXCHG_ORDER_ERR_SIZE);

        enum exchg_order_status new_status;
        // TODO: maybe provide a way to check
        // https://www.bitstamp.net/api/v2/order_status/
        if (!is_err)
                new_status = EXCHG_ORDER_PENDING;
        else
                new_status = EXCHG_ORDER_ERROR;
        struct order_update update = {
            .new_status = new_status,
            .filled_size = &size,
        };
        exchg_order_update(cl, oi, &update);
        return 0;

bad:
        snprintf(info->err, EXCHG_ORDER_ERR_SIZE, "Bitstamp sent bad update");
        exchg_log("%s: %s:\n", info->err, problem);
        json_fprintln(stderr, json, &toks[0]);
        struct order_update err_update = {
            .new_status = EXCHG_ORDER_ERROR,
        };
        exchg_order_update(cl, oi, &err_update);
        return 0;
}

static void place_order_on_err(struct exchg_client *cl, struct http *http,
                               const char *err)
{
        struct http_data *h = http_private(http);
        struct order_info *oi = h->p;
        struct exchg_order_info *info = &oi->info;

        if (err)
                strncpy(info->err, err, EXCHG_ORDER_ERR_SIZE);
        else
                strncpy(info->err, "<unknown>", EXCHG_ORDER_ERR_SIZE);
        struct order_update update = {
            .new_status = EXCHG_ORDER_ERROR,
        };
        exchg_order_update(cl, oi, &update);
}

const static struct exchg_http_ops place_order_ops = {
    .recv = place_order_recv,
    .add_headers = add_headers,
    .on_error = place_order_on_err,
    .conn_data_size = sizeof(struct http_data),
};

static int64_t bitstamp_place_order(struct exchg_client *cl,
                                    const struct exchg_order *order,
                                    const struct exchg_place_order_opts *opts,
                                    const struct exchg_request_options *options)
{
        char amount[30], price[30];
        char path[50];

        snprintf(path, sizeof(path), "/api/v2/%s/%s/",
                 order->side == EXCHG_SIDE_BUY ? "buy" : "sell",
                 exchg_pair_to_str(order->pair));
        struct http *http = exchg_http_post("www.bitstamp.net", path,
                                            &place_order_ops, cl, options);
        if (!http)
                return -1;
        struct http_data *h = http_private(http);
        strncpy(h->path, path, sizeof(h->path) - 1);

        decimal_to_str(amount, &order->size);
        decimal_to_str(price, &order->price);

        struct order_info *info = exchg_new_order(cl, order, opts, options, 0);
        if (!info) {
                http_close(http);
                return -ENOMEM;
        }
        h->p = info;

        h->payload_len = http_body_sprintf(
            http, "amount=%s&price=%s%s", amount, price,
            opts->immediate_or_cancel ? "&ioc_order=True" : "");
        if (h->payload_len < 0) {
                order_info_free(cl, info);
                http_close(http);
                return -ENOMEM;
        }
        info->info.status = EXCHG_ORDER_SUBMITTED;
        return info->info.id;
}

static int bitstamp_cancel_order(struct exchg_client *cl,
                                 struct order_info *info,
                                 const struct exchg_request_options *options)
{
        printf("sorry dunno how to cancel %s orders\n", exchg_name(cl));
        return -1;
}

static void bitstamp_destroy(struct exchg_client *cli)
{
        struct bitstamp_client *bts = client_private(cli);
        free(bts->api_header);
        free_exchg_client(cli);
}

static int
bitstamp_priv_ws_connect(struct exchg_client *cl,
                         const struct exchg_websocket_options *options)
{
        return 0;
}

static bool bitstamp_priv_ws_online(struct exchg_client *cl) { return true; }

static int bitstamp_new_keypair(struct exchg_client *cl,
                                const unsigned char *key, size_t len)
{
        struct bitstamp_client *bts = client_private(cl);

        if (hmac_ctx_setkey(&cl->hmac_ctx, key, len))
                return -1;

        char *p = realloc(bts->api_header,
                          cl->apikey_public_len + strlen("BITSTAMP ") + 1);
        if (!p) {
                exchg_log("%s: OOM\n", __func__);
                return -1;
        }
        bts->api_header_len = sprintf(p, "BITSTAMP %s", cl->apikey_public);
        bts->api_header = p;
        return 0;
}

struct exchg_client *alloc_bitstamp_client(struct exchg_context *ctx)
{
        if (ctx->opts.sandbox) {
                exchg_log("bitstamp doesn't have a sandbox API endpoint\n");
                return NULL;
        }

        struct exchg_client *ret = alloc_exchg_client(
            ctx, EXCHG_BITSTAMP, "SHA256", 200, sizeof(struct bitstamp_client));
        if (!ret)
                return NULL;

        ret->name = "Bitstamp";
        ret->get_balances = bitstamp_get_balances;
        ret->l2_subscribe = bitstamp_l2_subscribe;
        ret->get_pair_info = bitstamp_get_pair_info;
        ret->place_order = bitstamp_place_order;
        ret->cancel_order = bitstamp_cancel_order;
        ret->priv_ws_connect = bitstamp_priv_ws_connect;
        ret->priv_ws_online = bitstamp_priv_ws_online;
        ret->destroy = bitstamp_destroy;
        ret->new_keypair = bitstamp_new_keypair;
        return ret;
}
