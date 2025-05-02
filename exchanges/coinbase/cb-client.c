// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Marcelo Diop-Gonzalez

#include <ctype.h>
#include <glib.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <uuid.h>

#include "auth.h"
#include "b64.h"
#include "buf.h"
#include "client.h"
#include "coinbase.h"
#include "compiler.h"
#include "exchg/decimal.h"
#include "json-helpers.h"
#include "time-helpers.h"

#include "cb-auth.h"
#include "cb-client.h"

struct coinbase_conn_info {
        int next_sequence_num;
};

struct l2_update_msg {
        enum exchg_side side;
        bool got_size;
        decimal_t size;
        bool got_price;
        decimal_t price;
        int64_t update_micros;
};

// TODO: check .events[].type
/* enum l2_updates_type { */
/* 	TYPE_UNKNOWN, */
/* 	TYPE_SNAPSHOT, */
/* 	TYPE_UPDATE, */
/* }; */

struct l2_events_msg {
        enum exchg_pair pair;
        bool need_fee_calc;
        bool updates_parsed;
        jsmntok_t *first_event_time;
        int64_t first_update_micros;
};

struct message_seq {
        bool got_sequence_num;
        int sequence_num;
};

// TODO: check this before parsing the events
static int check_seq_num(struct coinbase_conn_info *conn_info,
                         struct message_seq *seq)
{
        if (!seq->got_sequence_num) {
                exchg_log("Coinbase l2 websocket gave no \"sequence_num\"\n");
                // return -1 ?
        } else {
                if (seq->sequence_num != conn_info->next_sequence_num) {
                        // TODO: decide if we should reconnect
                        exchg_log("Coinbase l2 websocket gave unexpected "
                                  "\"sequence_num\": %d expected: %d\n",
                                  seq->sequence_num,
                                  conn_info->next_sequence_num);
                        return -1;
                }
                conn_info->next_sequence_num = seq->sequence_num + 1;
        }
        return 0;
}

static void conn_info_reset(struct coinbase_conn_info *conn_info)
{
        conn_info->next_sequence_num = 0;
}

struct l2_msg {
        bool got_channel;
        struct message_seq seq;
        bool events_parsed;
};

static int push_l2_update(struct exchg_client *cl, enum exchg_pair pair,
                          struct l2_update_msg *update_msg,
                          const char **problem)
{
        if (update_msg->side == -1) {
                *problem = "no \"side\" field";
                return -1;
        }
        if (!update_msg->got_size) {
                *problem = "no \"new_quantity\" field";
                return -1;
        }
        if (!update_msg->got_price) {
                *problem = "no \"price_level\" field";
                return -1;
        }
        if (update_msg->update_micros == -1) {
                *problem = "no \"event_time\" field";
                return -1;
        }

        struct exchg_l2_update *upd = &cl->update;
        struct exchg_limit_order *order;

        if (update_msg->side == EXCHG_SIDE_BUY) {
                if (upd->num_bids >= cl->l2_update_size &&
                    exchg_realloc_order_bufs(cl, 2 * (upd->num_bids + 1))) {
                        *problem = "OOM";
                        return -1;
                }
                order = &upd->bids[upd->num_bids];
                upd->num_bids++;
        } else {
                if (upd->num_asks >= cl->l2_update_size &&
                    exchg_realloc_order_bufs(cl, 2 * (upd->num_asks + 1))) {
                        *problem = "OOM";
                        return -1;
                }
                order = &upd->asks[upd->num_asks];
                upd->num_asks++;
        }
        order->exchange_id = EXCHG_COINBASE;
        order->price = update_msg->price;
        order->size = update_msg->size;
        if (pair != INVALID_PAIR) {
                struct exchg_pair_info *pi = &cl->pair_info[pair];
                if (update_msg->side == EXCHG_SIDE_BUY) {
                        decimal_dec_bps(&order->net_price, &order->price,
                                        pi->fee_bps, pi->price_decimals);
                } else {
                        decimal_inc_bps(&order->net_price, &order->price,
                                        pi->fee_bps, pi->price_decimals);
                }
        }
        order->update_micros = update_msg->update_micros;
        return 0;
}

static int parse_time_int(char *json, int *start_pos, int end_pos,
                          const char *end_chars, int fractional_places,
                          const char **problem)
{
        int pos = *start_pos;
        for (; pos < end_pos; pos++) {
                if (!isdigit(json[pos])) {
                        bool allowed_end = false;
                        for (const char *e = end_chars; *e; e++) {
                                if (json[pos] == *e) {
                                        allowed_end = true;
                                        break;
                                }
                        }
                        if (!allowed_end) {
                                *problem = "error parsing int in time string";
                                return -1;
                        }
                        break;
                }
        }
        if (pos >= end_pos) {
                *problem = "error parsing int in time string";
                return -1;
        }

        char c = json[pos];
        json[pos] = 0;
        char *start = &json[*start_pos];
        char *end;
        long n = strtol(start, &end, 10);

        if (*end || end == start) {
                json[pos] = c;
                *problem = "error parsing int in time string";
                return -1;
        }
        json[pos] = c;

        if (fractional_places > 0) {
                int digits = end - start;
                if (digits > 9) {
                        *problem =
                            "error parsing fractional seconds in time string";
                        return -1;
                }
                if (digits > fractional_places) {
                        for (; digits > fractional_places; digits--)
                                n /= 10;
                } else if (digits < fractional_places) {
                        for (; digits < fractional_places; digits++)
                                n *= 10;
                }
        }
        *start_pos = pos + 1;
        return n;
}

static int parse_timestamp(int64_t *update_micros, char *json, jsmntok_t *value,
                           const char **problem)
{
        if (unlikely(value->type != JSMN_STRING)) {
                *problem = "bad \"event_time\"";
                return -1;
        }

        int pos = value->start;
        struct tm tm = {};

        tm.tm_year = parse_time_int(json, &pos, value->end, "-", -1, problem);
        if (tm.tm_year < 0)
                return -1;
        tm.tm_mon = parse_time_int(json, &pos, value->end, "-", -1, problem);
        if (tm.tm_mon < 0)
                return -1;
        tm.tm_mday = parse_time_int(json, &pos, value->end, "T", -1, problem);
        if (tm.tm_mday < 0)
                return -1;
        tm.tm_hour = parse_time_int(json, &pos, value->end, ":", -1, problem);
        if (tm.tm_hour < 0)
                return -1;
        tm.tm_min = parse_time_int(json, &pos, value->end, ":", -1, problem);
        if (tm.tm_min < 0)
                return -1;
        tm.tm_sec = parse_time_int(json, &pos, value->end, ".Z", -1, problem);
        if (tm.tm_sec < 0)
                return -1;
        int us = 0;
        if (json[pos - 1] == '.') {
                us = parse_time_int(json, &pos, value->end, "Z", 6, problem);
                if (us < 0)
                        return -1;
        }

        tm.tm_mon -= 1;
        tm.tm_year -= 1900;

        int64_t secs = timegm(&tm);
        *update_micros = 1000000 * secs + us;
        return 0;
}

static int parse_update(struct exchg_client *cl, struct l2_events_msg *events,
                        char *json, int num_toks, jsmntok_t *toks, int idx,
                        const char **problem)
{
        if (unlikely(toks[idx].type != JSMN_OBJECT)) {
                *problem = "non-object update data";
                return -1;
        }
        struct l2_update_msg update = {
            .side = -1,
            .update_micros = -1,
        };

        int key_idx = idx + 1;

        for (int i = 0; i < toks[idx].size; i++) {
                jsmntok_t *key = &toks[key_idx];
                jsmntok_t *value = &toks[key_idx + 1];

                if (json_streq(json, key, "side")) {
                        if (json_streq(json, value, "bid")) {
                                update.side = EXCHG_SIDE_BUY;
                        } else if (json_streq(json, value, "offer")) {
                                update.side = EXCHG_SIDE_SELL;
                        } else {
                                *problem = "bad update \"side\"";
                                return -1;
                        }
                        key_idx += 2;
                } else if (json_streq(json, key, "price_level")) {
                        if (unlikely(
                                json_get_decimal(&update.price, json, value))) {
                                *problem = "bad \"price\"";
                                return -1;
                        }
                        update.got_price = true;
                        key_idx += 2;
                } else if (json_streq(json, key, "new_quantity")) {
                        if (unlikely(
                                json_get_decimal(&update.size, json, value))) {
                                *problem = "bad \"new_quantity\"";
                                return -1;
                        }
                        update.got_size = true;
                        key_idx += 2;
                } else if (json_streq(json, key, "event_time")) {
                        if (events->first_event_time &&
                            json_tok_streq(json, value,
                                           events->first_event_time)) {
                                update.update_micros =
                                    events->first_update_micros;
                        } else {
                                if (parse_timestamp(&update.update_micros, json,
                                                    value, problem))
                                        return -1;
                                if (!events->first_event_time) {
                                        events->first_event_time = value;
                                        events->first_update_micros =
                                            update.update_micros;
                                }
                        }
                        key_idx += 2;
                } else {
                        key_idx = json_skip(num_toks, toks, key_idx + 1);
                }
        }
        if (push_l2_update(cl, events->pair, &update, problem)) {
                return -1;
        }
        return key_idx;
}

static void do_l2_update(struct exchg_client *cl, struct l2_events_msg *events)
{
        if (events->need_fee_calc) {
                struct exchg_pair_info *pi = &cl->pair_info[events->pair];
                for (int i = 0; i < cl->update.num_bids; i++) {
                        struct exchg_limit_order *order = &cl->update.bids[i];
                        decimal_dec_bps(&order->net_price, &order->price,
                                        pi->fee_bps, pi->price_decimals);
                }
                for (int i = 0; i < cl->update.num_asks; i++) {
                        struct exchg_limit_order *order = &cl->update.asks[i];
                        decimal_inc_bps(&order->net_price, &order->price,
                                        pi->fee_bps, pi->price_decimals);
                }
        }
        exchg_l2_update(cl, events->pair);
}

static int parse_updates(struct exchg_client *cl, char *json, int num_toks,
                         jsmntok_t *toks, int idx, const char **problem)
{
        struct coinbase_client *cb = client_private(cl);

        if (toks[idx].type != JSMN_OBJECT) {
                *problem = "not a JSON object";
                return -1;
        }
        exchg_update_init(cl);

        struct l2_events_msg events = {.pair = INVALID_PAIR};

        int key_idx = idx + 1;

        for (int i = 0; i < toks[idx].size; i++) {
                jsmntok_t *key = &toks[key_idx];
                jsmntok_t *value = &toks[key_idx + 1];

                if (json_streq(json, key, "product_id")) {
                        if (unlikely(value->type != JSMN_STRING)) {
                                *problem = "bad \"product_id\"";
                                return -1;
                        }
                        for (enum exchg_pair p = 0; p < EXCHG_NUM_PAIRS; p++) {
                                struct exchg_pair_info *info =
                                    &cl->pair_info[p];
                                struct coinbase_pair_info *cbinfo =
                                    &cb->pair_info[p];

                                if (!info->available)
                                        continue;
                                if (__json_streq(json, value, cbinfo->id)) {
                                        events.pair = p;
                                        break;
                                }
                        }
                        if (unlikely(events.pair == INVALID_PAIR)) {
                                *problem = "bad \"product_id\"";
                                return -1;
                        }
                        key_idx += 2;
                } else if (json_streq(json, key, "type")) {
                        // TODO
                        key_idx = json_skip(num_toks, toks, key_idx + 1);
                } else if (json_streq(json, key, "updates")) {
                        if (events.pair == INVALID_PAIR) {
                                events.need_fee_calc = true;
                        }
                        if (unlikely(value->type != JSMN_ARRAY)) {
                                *problem = "non-array \"updates\" data";
                                return -1;
                        }

                        int obj_idx = key_idx + 2;
                        for (int i = 0; i < value->size; i++) {
                                obj_idx =
                                    parse_update(cl, &events, json, num_toks,
                                                 toks, obj_idx, problem);
                                if (obj_idx < 0)
                                        return obj_idx;
                        }
                        events.updates_parsed = true;
                        key_idx = obj_idx;
                } else {
                        key_idx = json_skip(num_toks, toks, key_idx + 1);
                }
        }
        if (!events.updates_parsed) {
                *problem = "no \"updates\" field";
                return -1;
        }
        if (events.pair == INVALID_PAIR) {
                *problem = "no \"product_id\" field";
                return -1;
        }
        do_l2_update(cl, &events);
        return key_idx;
}

struct coinbase_order {
        uuid_t client_oid;
        // we could parse it as a uuid but what do we do if it's not a valid one
        // after some coinbase update? Seems better to accept whatever. So we
        // keep it in an array of static size for convencience/speed on
        // cancellation and fail if it's larger than that
        char id[50];
        bool cancel_retried;
};

int64_t *lookup_order(struct coinbase_client *cb, char *json,
                      jsmntok_t *order_id)
{
        json[order_id->end] = 0;
        int64_t *id = g_hash_table_lookup(cb->orders, &json[order_id->start]);
        json[order_id->end] = '\"';
        return id;
}

static void set_order_id(struct coinbase_client *cb, struct order_info *info,
                         char *json, jsmntok_t *order_id)
{
        struct coinbase_order *c = order_info_private(info);
        if (order_id->end - order_id->start > sizeof(c->id) - 1) {
                exchg_log("FIXME: coinbase sent order ID of length %d. Cannot "
                          "handle this\n",
                          order_id->end - order_id->start);
                return;
        }
        if (lookup_order(cb, json, order_id))
                return;

        json_strncpy(c->id, json, order_id, sizeof(c->id));

        char *coinbase_id;
        if (json_strdup(&coinbase_id, json, order_id) < 0)
                return;

        int64_t *id = malloc(sizeof(*id));
        if (!id) {
                exchg_log("%s: OOM\n", __func__);
                return;
        }
        *id = info->info.id;
        g_hash_table_insert(cb->orders, coinbase_id, id);
}

static void order_update(struct exchg_client *cl, struct order_info *oi,
                         const struct order_update *update)
{
        struct coinbase_client *cb = client_private(cl);
        struct coinbase_order *c = order_info_private(oi);

        // TODO: should do this after it's freed
        if (order_status_done(update->new_status) && c->id[0])
                g_hash_table_remove(cb->orders, c->id);
        exchg_order_update(cl, oi, update);
}

static int public_ws_recv(struct exchg_client *cl, struct websocket *w,
                          char *json, int num_toks, jsmntok_t *toks)
{
        struct coinbase_conn_info *conn_info = websocket_private(w);

        const char *problem = "";
        if (toks[0].type != JSMN_OBJECT) {
                problem = "not a JSON object";
                goto bad;
        }

        bool parse_events = true;
        struct l2_msg msg = {};
        int key_idx = 1;
        for (int j = 0; j < toks[0].size; j++) {
                jsmntok_t *key = &toks[key_idx];
                jsmntok_t *value = &toks[key_idx + 1];

                if (json_streq(json, key, "channel")) {
                        if (!json_streq(json, value, "l2_data")) {
                                // for now we dont do anything with any other
                                // message
                                if (!json_streq(json, value, "subscriptions")) {
                                        exchg_log(
                                            "Coinbase sent websocket message "
                                            "with unexpected \"channel\":\n");
                                        json_fprintln(stderr, json, &toks[0]);
                                }
                                parse_events = false;
                        }
                        msg.got_channel = true;
                        key_idx += 2;
                } else if (json_streq(json, key, "sequence_num")) {
                        if (json_get_int(&msg.seq.sequence_num, json, value)) {
                                problem = "bad \"sequence_num\"";
                                goto bad;
                        }
                        msg.seq.got_sequence_num = true;
                        key_idx += 2;
                } else if (json_streq(json, key, "events")) {
                        if (!parse_events) {
                                key_idx =
                                    json_skip(num_toks, toks, key_idx + 1);
                                continue;
                        }
                        if (unlikely(value->type != JSMN_ARRAY)) {
                                problem = "non-array \"events\" data";
                                goto bad;
                        }

                        // TODO: should make sure the channel is l2_data
                        int obj_idx = key_idx + 2;
                        for (int i = 0; i < value->size; i++) {
                                obj_idx =
                                    parse_updates(cl, json, num_toks, toks,
                                                  obj_idx, &problem);
                                if (obj_idx < 0)
                                        goto bad;
                        }
                        key_idx = obj_idx;
                        msg.events_parsed = true;
                } else {
                        key_idx = json_skip(num_toks, toks, key_idx + 1);
                }
        }
        if (check_seq_num(conn_info, &msg.seq))
                return -1;
        if (!msg.got_channel) {
                exchg_log(
                    "Coinbase sent websocket message without \"channel\":\n");
                json_fprintln(stderr, json, &toks[0]);
        } else if (parse_events && !msg.events_parsed) {
                exchg_log(
                    "Coinbase sent websocket message without \"events\":\n");
                json_fprintln(stderr, json, &toks[0]);
        }
        return 0;

bad:
        exchg_log("Coinbase gave bad update: %s:\n", problem);
        json_fprintln(stderr, json, &toks[0]);
        return -1;
}

static int public_channel_sub(struct exchg_client *cl)
{
        struct coinbase_client *cb = client_private(cl);
        bool send_message = false;
        struct buf buf;

        if (buf_alloc(&buf, 1 << 10, 0))
                return -1;

        for (enum exchg_pair pair = 0; pair < EXCHG_NUM_PAIRS; pair++) {
                struct coinbase_pair_info *cbinfo = &cb->pair_info[pair];
                struct exchg_pair_info *info = &cl->pair_info[pair];

                if (cbinfo->watching_l2 && !info->available) {
                        exchg_log("pair %s not available on Coinbase\n",
                                  exchg_pair_to_str(pair));
                        cbinfo->watching_l2 = false;
                } else if (cbinfo->watching_l2 && !cbinfo->subbed) {
                        bool comma = send_message;
                        send_message = true;
                        cbinfo->subbed = true;
                        const char *fmt;
                        if (comma)
                                fmt = ", \"%s\"";
                        else
                                fmt = "\"%s\"";
                        if (buf_sprintf(&buf, fmt, cbinfo->id) < 0) {
                                buf_free(&buf);
                                return -1;
                        }
                }
        }
        if (!send_message) {
                buf_free(&buf);
                return 0;
        }

        if (cb->authenticate_channel_sub) {
                char *jwt = coinbase_ws_jwt(cl);
                if (!jwt) {
                        buf_free(&buf);
                        return -1;
                }
                int n =
                    websocket_printf(cb->public_ws,
                                     "{ \"type\": \"subscribe\", "
                                     "\"channel\": \"level2\","
                                     "\"product_ids\": [%s], \"jwt\": \"%s\"}",
                                     buf_start(&buf), jwt);
                buf_free(&buf);
                free(jwt);
                if (n < 0)
                        return -1;
        } else {
                int n = websocket_printf(cb->public_ws,
                                         "{ \"type\": \"subscribe\", "
                                         "\"channel\": \"level2\","
                                         "\"product_ids\": [%s]}",
                                         buf_start(&buf));
                buf_free(&buf);
                if (n < 0)
                        return -1;
        }
        return 0;
}

static bool public_sub_work(struct exchg_client *cl, void *p)
{
        struct coinbase_client *cb = client_private(cl);

        if (!cl->pair_info_current || !websocket_established(cb->public_ws))
                return false;

        public_channel_sub(cl);
        return true;
}

static int public_ws_on_established(struct exchg_client *cl,
                                    struct websocket *w)
{
        if (!cl->pair_info_current)
                return queue_work_exclusive(cl, public_sub_work, NULL);
        else
                return public_channel_sub(cl);
}

static int public_ws_on_disconnect(struct exchg_client *cl,
                                   struct websocket *ws, int reconnect_seconds)
{
        struct coinbase_client *cb = client_private(cl);
        struct coinbase_conn_info *conn_info = websocket_private(ws);
        int num_pairs_gone = 0;
        enum exchg_pair pairs_gone[EXCHG_NUM_PAIRS];

        if (reconnect_seconds < 0)
                cb->public_ws = NULL;
        for (enum exchg_pair pair = 0; pair < EXCHG_NUM_PAIRS; pair++) {
                struct exchg_pair_info *info = &cl->pair_info[pair];
                struct coinbase_pair_info *cbinfo = &cb->pair_info[pair];
                if (cbinfo->watching_l2 && info->available) {
                        pairs_gone[num_pairs_gone++] = pair;
                        exchg_book_clear(cl, pair);
                }
                cbinfo->subbed = false;
        }
        cb->sub_acked = false;
        exchg_data_disconnect(cl, ws, num_pairs_gone, pairs_gone);
        conn_info_reset(conn_info);
        return 0;
}

static const struct exchg_websocket_ops public_ws_ops = {
    .on_conn_established = public_ws_on_established,
    .on_disconnect = public_ws_on_disconnect,
    .recv = public_ws_recv,
    .conn_data_size = sizeof(struct coinbase_conn_info),
};

static int coinbase_l2_subscribe(struct exchg_client *cl, enum exchg_pair pair,
                                 const struct exchg_websocket_options *options)
{
        struct coinbase_client *cb = client_private(cl);
        struct coinbase_pair_info *ci = &cb->pair_info[pair];

        if (ci->subbed)
                return 0;

        if (ws_options_authenticate(options) && !cb->pkey) {
                exchg_log("exchg_l2_subscribe called for coinbase with "
                          "authenticate=true, but no private key loaded\n");
                return -1;
        }
        if (cb->public_ws)
                websocket_log_options_discrepancies(cb->public_ws, options);

        cb->authenticate_channel_sub = ws_options_authenticate(options);

        ci->watching_l2 = true;

        if (cl->pair_info_current && websocket_established(cb->public_ws))
                return public_channel_sub(cl);

        if (!cb->public_ws) {
                cb->public_ws = exchg_websocket_connect(
                    cl, "advanced-trade-ws.coinbase.com", "/", &public_ws_ops,
                    options);
                if (!cb->public_ws)
                        return -1;
        }
        return 0;
}

struct pair_info_msg {
        enum exchg_currency base;
        enum exchg_currency counter;
        char *id;
        int base_decimals;
        int price_decimals;
        decimal_t base_increment;
        decimal_t quote_increment;
        decimal_t base_min_size;
        bool trading_disabled;
        bool online;
};

static int decimal_inc_to_places(const decimal_t *d)
{
        if (d->value != 1)
                return -EINVAL;
        return d->places;
}

static int parse_products(struct exchg_client *cl, struct http *http,
                          int status, char *json, int num_toks, jsmntok_t *toks,
                          int array_idx)
{
        struct coinbase_client *cb = client_private(cl);
        const char *problem = "";
        jsmntok_t *bad_tok = &toks[array_idx];

        if (toks[array_idx].type != JSMN_ARRAY) {
                problem = "didn't receive a JSON array\n";
                goto bad;
        }

        int obj_idx = array_idx + 1;
        bool non_obj_warned = false;
        for (int i = 0; i < toks[array_idx].size; i++) {
                if (toks[obj_idx].type != JSMN_OBJECT) {
                        if (!non_obj_warned) {
                                exchg_log("%s%s gave non-object \"products\" "
                                          "array member (idx %d):\n",
                                          http_host(http), http_path(http), i);
                                json_fprintln(stderr, json, &toks[array_idx]);
                                non_obj_warned = true;
                        }
                        obj_idx = json_skip(num_toks, toks, obj_idx);
                        continue;
                }

                struct pair_info_msg msg = {
                    .base = -1,
                    .counter = -1,
                };
                int key_idx = obj_idx + 1;

                for (int j = 0; j < toks[obj_idx].size; j++) {
                        jsmntok_t *key = &toks[key_idx];
                        jsmntok_t *value = &toks[key_idx + 1];

                        if (json_streq(json, key, "product_id")) {
                                int err = json_strdup(&msg.id, json, value);
                                if (err == -ENOMEM) {
                                        exchg_log("%s: OOM\n", __func__);
                                        return -1;
                                }
                                // maybe there is a better way to do this. The
                                // BTCAUCTION-USD pair info shows the same base
                                // and quote currencies as the BTC-USD one.
                                // So how do we distinguish them here?
                                if (strstr(msg.id, "AUCTION"))
                                        goto skip;
                                if (err < 0) {
                                        problem = "bad \"id\" field";
                                        goto bad;
                                }
                        } else if (json_streq(json, key, "base_currency_id")) {
                                if (json_get_currency(&msg.base, json, value))
                                        goto skip;
                        } else if (json_streq(json, key, "quote_currency_id")) {
                                if (json_get_currency(&msg.counter, json,
                                                      value))
                                        goto skip;
                        } else if (json_streq(json, key, "status")) {
                                if (json_streq(json, value, "online"))
                                        msg.online = true;
                        } else if (json_streq(json, key, "trading_disabled")) {
                                if (json_get_bool(&msg.trading_disabled, json,
                                                  value)) {
                                        problem =
                                            "bad \"trading_disabled\" field";
                                        free(msg.id);
                                        goto bad;
                                }
                        } else if (json_streq(json, key, "base_increment")) {
                                if (json_get_decimal(&msg.base_increment, json,
                                                     value)) {
                                        problem =
                                            "bad \"base_increment\" field";
                                        free(msg.id);
                                        goto bad;
                                }
                        } else if (json_streq(json, key, "quote_increment")) {
                                if (json_get_decimal(&msg.quote_increment, json,
                                                     value)) {
                                        problem =
                                            "bad \"quote_increment\" field";
                                        free(msg.id);
                                        goto bad;
                                }
                        } else if (json_streq(json, key, "base_min_size")) {
                                if (json_get_decimal(&msg.base_min_size, json,
                                                     value)) {
                                        problem = "bad \"base_min_size\" field";
                                        free(msg.id);
                                        goto bad;
                                }
                        }
                        key_idx = json_skip(num_toks, toks, key_idx + 1);
                }
                enum exchg_pair pair;
                if (!msg.id) {
                        problem = "no \"product_id\" field";
                        goto bad;
                }
                if (msg.base == -1) {
                        problem = "no \"base_currency_id\" field";
                        free(msg.id);
                        goto bad;
                }
                if (msg.counter == -1) {
                        problem = "no \"quote_currency_id\" field";
                        free(msg.id);
                        goto bad;
                }
                if (decimal_is_zero(&msg.base_increment)) {
                        problem = "no \"base_increment\" field";
                        free(msg.id);
                        goto bad;
                }
                if (decimal_is_zero(&msg.quote_increment)) {
                        problem = "no \"quote_increment\" field";
                        free(msg.id);
                        goto bad;
                }
                enum exchg_join_type j =
                    exchg_ccy_join(&pair, msg.base, msg.counter);
                if (j == JOIN_TYPE_ERROR) {
                        exchg_log("Coinbase offers pair %s - %s. Can't "
                                  "currently handle this pair.\n",
                                  exchg_ccy_to_str(msg.base),
                                  exchg_ccy_to_str(msg.counter));
                        goto skip;
                }
                if (j == JOIN_TYPE_FIRST_COUNTER) {
                        exchg_log("Coinbase has %s as base and %s as counter "
                                  "for %s. Can't currently handle this.\n",
                                  exchg_ccy_to_str(msg.base),
                                  exchg_ccy_to_str(msg.counter),
                                  exchg_pair_to_str(pair));
                        goto skip;
                }

                if (msg.trading_disabled) {
                        exchg_log(
                            "Coinbase indicates trading disabled in %s:\n",
                            exchg_pair_to_str(pair));
                        json_fprintln(stderr, json, &toks[obj_idx]);
                        goto skip;
                }
                if (!msg.online) {
                        exchg_log("Coinbase non-online status for %s:\n",
                                  exchg_pair_to_str(pair));
                        json_fprintln(stderr, json, &toks[obj_idx]);
                        goto skip;
                }
                struct exchg_pair_info *pi = &cl->pair_info[pair];
                struct coinbase_pair_info *cpi = &cb->pair_info[pair];

                pi->available = true;
                pi->min_size = msg.base_min_size;
                pi->base_decimals = decimal_inc_to_places(&msg.base_increment);
                if (pi->base_decimals < 0) {
                        problem = "bad \"base_increment\" field";
                        free(msg.id);
                        goto bad;
                }
                pi->price_decimals =
                    decimal_inc_to_places(&msg.quote_increment);
                if (pi->price_decimals < 0) {
                        problem = "bad \"quote_increment\" field";
                        free(msg.id);
                        goto bad;
                }
                // TODO: get from api.coinbase.com/fees
                pi->fee_bps = 50;

                cpi->id = msg.id;

                obj_idx = key_idx;
                continue;

        skip:
                free(msg.id);
                obj_idx = json_skip(num_toks, toks, obj_idx);
        }
        exchg_on_pair_info(cl);
        exchg_do_work(cl);
        return 0;

bad:
        cl->get_info_error = 1;
        exchg_log("Received bad data from %s%s %s:\n", http_host(http),
                  http_path(http), problem);
        json_fprintln(stderr, json, bad_tok);
        return -1;
}

static int parse_info(struct exchg_client *cl, struct http *http, int status,
                      char *json, int num_toks, jsmntok_t *toks)
{
        const char *problem = "no \"products\" key found";
        jsmntok_t *bad_tok = &toks[0];

        if (toks[0].type != JSMN_OBJECT) {
                problem = "didn't receive a JSON object";
                goto bad;
        }

        int key_idx = 1;

        for (int i = 0; i < toks[0].size; i++) {
                jsmntok_t *key = &toks[key_idx];

                if (json_streq(json, key, "products")) {
                        return parse_products(cl, http, status, json, num_toks,
                                              toks, key_idx + 1);
                }
                key_idx = json_skip(num_toks, toks, key_idx + 1);
        }

bad:
        cl->get_info_error = 1;
        exchg_log("Received bad data from %s%s %s:\n", http_host(http),
                  http_path(http), problem);
        json_fprintln(stderr, json, bad_tok);
        return -1;
}

static int add_user_agent(struct exchg_client *cl, struct http *http)
{
        // libwebsockets sets User-agent and coinbase complains
        if (http_add_header(http, (unsigned char *)"User-Agent:",
                            (unsigned char *)"lws", 3))
                return 1;
        return 0;
}

static struct exchg_http_ops get_info_ops = {
    .recv = parse_info,
    .add_headers = add_user_agent,
    .on_closed = exchg_parse_info_on_closed,
};

static int coinbase_get_pair_info(struct exchg_client *cl)
{
        if (!exchg_http_get("api.coinbase.com",
                            "/api/v3/brokerage/market/products", &get_info_ops,
                            cl, NULL))
                return -1;
        return 0;
}

static int private_add_headers(struct exchg_client *cl, struct http *http)
{
        if (add_user_agent(cl, http))
                return 1;

        struct http_data *data = http_private(http);
        if (data->jwt &&
            http_add_header(http, (unsigned char *)"Authorization:",
                            (unsigned char *)data->jwt, data->jwt_len))
                return 1;
        if (http_body_len(http) > 0) {
                if (http_add_header(http, (unsigned char *)"Content-Type:",
                                    (unsigned char *)"application/json",
                                    strlen("application/json")))
                        return 1;
                char l[30];
                int len = snprintf(l, sizeof(l), "%zu", http_body_len(http));
                if (unlikely(len >= sizeof(l))) {
                        exchg_log("coinbase: unexpected length %d of length "
                                  "string??\n",
                                  len);
                        return 1;
                }
                if (http_add_header(http, (unsigned char *)"Content-Length:",
                                    (unsigned char *)l, len))
                        return 1;
        }
        return 0;
}

static int parse_accounts_member(struct exchg_client *cl, char *json,
                                 int num_toks, jsmntok_t *toks, int obj_idx,
                                 decimal_t balances[EXCHG_NUM_CCYS],
                                 const char **problem)
{
        enum exchg_currency currency = -1;
        bool got_available = false;
        decimal_t available;
        bool got_active = false;
        bool active = false;
        bool good_type = false;

        if (toks[obj_idx].type != JSMN_OBJECT) {
                *problem = "\"accounts\" array member not a JSON object\n";
                json_fprintln(stdout, json, &toks[obj_idx]);
                return -1;
        }

        int key_idx = obj_idx + 1;

        // TODO: check "ready"?
        for (int i = 0; i < toks[obj_idx].size; i++) {
                jsmntok_t *key = &toks[key_idx];
                jsmntok_t *value = &toks[key_idx + 1];

                if (json_streq(json, key, "available_balance")) {
                        if (value->type != JSMN_OBJECT) {
                                *problem = "\"accounts[].available_balance\" "
                                           "not a JSON object\n";
                                return -1;
                        }

                        key_idx += 2;
                        for (int j = 0; j < value->size; j++) {
                                jsmntok_t *key = &toks[key_idx];
                                jsmntok_t *value = &toks[key_idx + 1];

                                if (json_streq(json, key, "value")) {
                                        if (json_get_decimal(&available, json,
                                                             value)) {
                                                *problem =
                                                    "error parsing "
                                                    "\"accounts[].available_"
                                                    "balance.value\"\n";
                                                return -1;
                                        }
                                        got_available = true;
                                } else if (json_streq(json, key, "currency")) {
                                        if (value->type != JSMN_STRING) {
                                                *problem =
                                                    "\"accounts[].available_"
                                                    "balance.currency\" not a "
                                                    "string\n";
                                                return -1;
                                        }
                                        if (json_get_currency(&currency, json,
                                                              value)) {
                                                return json_skip(num_toks, toks,
                                                                 obj_idx);
                                        }
                                }
                                key_idx =
                                    json_skip(num_toks, toks, key_idx + 1);
                        }
                } else if (json_streq(json, key, "active")) {
                        if (json_get_bool(&active, json, value)) {
                                *problem =
                                    "error parsing \"accounts[].active\"\n";
                                return -1;
                        }
                        got_active = true;
                        key_idx += 2;
                } else if (json_streq(json, key, "type")) {
                        if (value->type != JSMN_STRING) {
                                *problem = "\"accounts[].type\" not a string\n";
                                return -1;
                        }
                        if (!json_streq(json, value, "ACCOUNT_TYPE_CRYPTO") &&
                            !json_streq(json, value, "ACCOUNT_TYPE_FIAT")) {
                                return json_skip(num_toks, toks, obj_idx);
                        }
                        good_type = true;
                        key_idx += 2;
                } else {
                        key_idx = json_skip(num_toks, toks, key_idx + 1);
                }
        }
        if (currency == -1) {
                *problem =
                    "no \"accounts[].available_balance.currency\" field\n";
                return -1;
        }
        if (!got_available) {
                *problem = "no \"accounts[].available_balance.value\" field\n";
                return -1;
        }
        if (!good_type) {
                exchg_log(
                    "No \"accounts[].type\" field found for %s in Coinbase "
                    "/api/v3/brokerage/accounts HTTP response. Skipping\n",
                    exchg_ccy_to_str(currency));
                return key_idx;
        }
        if (!got_active) {
                exchg_log("No \"accounts[].active\" field found for %s in "
                          "Coinbase /api/v3/brokerage/accounts HTTP response. "
                          "Assuming active\n",
                          exchg_ccy_to_str(currency));
                active = true;
        }
        if (active) {
                balances[currency] = available;
        } else {
                exchg_log("\"accounts[].active\" field for %s in Coinbase "
                          "/api/v3/brokerage/accounts HTTP response shows "
                          "\"false\"\n",
                          exchg_ccy_to_str(currency));
        }
        return key_idx;
}

static int balances_recv(struct exchg_client *cl, struct http *http, int status,
                         char *json, int num_toks, jsmntok_t *toks)
{
        const char *problem = "";

        if (toks[0].type != JSMN_OBJECT) {
                problem = "didn't receive a JSON object\n";
                goto bad;
        }

        decimal_t balances[EXCHG_NUM_CCYS];
        int key_idx = 1;

        memset(balances, 0, sizeof(balances));

        for (int i = 0; i < toks[0].size; i++) {
                jsmntok_t *key = &toks[key_idx];
                jsmntok_t *value = &toks[key_idx + 1];

                // TODO: check "has_next" and "cursor"
                if (!json_streq(json, key, "accounts")) {
                        key_idx = json_skip(num_toks, toks, key_idx + 1);
                        continue;
                }

                if (value->type != JSMN_ARRAY) {
                        problem = "\"accounts\" value not a JSON array\n";
                        goto bad;
                }
                int obj_idx = key_idx + 2;

                for (int j = 0; j < value->size; j++) {
                        obj_idx =
                            parse_accounts_member(cl, json, num_toks, toks,
                                                  obj_idx, balances, &problem);
                        if (obj_idx < 0)
                                goto bad;
                }
                key_idx = obj_idx;
        }

        struct http_data *h = http_private(http);
        exchg_on_balances(cl, balances, h->private);
        return 0;

bad:
        exchg_log("Received bad data from %s%s %s:\n", http_host(http),
                  http_path(http), problem);
        json_fprintln(stderr, json, &toks[0]);
        return -1;
}

static void http_data_free(struct exchg_client *cl, struct http *http)
{
        struct http_data *data = http_private(http);
        free(data->jwt);
}

static struct exchg_http_ops get_balances_ops = {
    .recv = balances_recv,
    .add_headers = private_add_headers,
    .on_free = http_data_free,
    .conn_data_size = sizeof(struct http_data),
};

static int coinbase_get_balances(struct exchg_client *cl,
                                 const struct exchg_request_options *options)
{
        struct http *http =
            exchg_http_get("api.coinbase.com", "/api/v3/brokerage/accounts",
                           &get_balances_ops, cl, options);
        if (!http)
                return -1;
        struct http_data *data = http_private(http);
        data->private = options ? options->user : NULL;
        if (coinbase_http_auth(cl, http)) {
                http_close(http);
                return -1;
        }
        return 0;
}

struct order_ack {
        bool success;
        jsmntok_t *order_id;
        enum exchg_order_status status;
        bool got_error;
        jsmntok_t *message;
};

static int orders_recv(struct exchg_client *cl, struct http *http, int status,
                       char *json, int num_toks, jsmntok_t *toks)
{
        const char *problem = "";
        struct http_data *data = http_private(http);
        struct order_info *info = exchg_order_lookup(cl, data->id);

        if (!info) {
                exchg_log("Received unknown order update from %s%s: ",
                          http_host(http), http_path(http));
                json_fprintln(stderr, json, &toks[0]);
                return 0;
        }

        if (toks[0].type != JSMN_OBJECT) {
                problem = "non-object data";
                goto bad;
        }

        struct order_ack ack = {
            .status = EXCHG_ORDER_PENDING,
        };
        int key_idx = 1;
        for (int i = 0; i < toks[0].size; i++) {
                jsmntok_t *key = &toks[key_idx];
                jsmntok_t *value = key + 1;

                if (json_streq(json, key, "success")) {
                        if (json_get_bool(&ack.success, json, value)) {
                                problem = "bad \"success\" field";
                                goto bad;
                        }
                } else if (json_streq(json, key, "success_response")) {
                        if (value->type != JSMN_OBJECT) {
                                problem = "bad \"success_response\" field";
                                goto bad;
                        }
                        int obj_key = key_idx + 2;
                        int n = value->size;
                        for (size_t j = 0; j < n; j++) {
                                key = &toks[obj_key];
                                value = key + 1;
                                // TODO: maybe check the other stuff too
                                if (json_streq(json, key, "order_id")) {
                                        ack.order_id = value;
                                        break;
                                }
                                obj_key =
                                    json_skip(num_toks, toks, obj_key + 1);
                        }
                } else if (json_streq(json, key, "error_response")) {
                        if (value->type != JSMN_OBJECT) {
                                problem = "bad \"error_response\" field";
                                goto bad;
                        }

                        ack.got_error = true;
                        int obj_key = key_idx + 2;
                        int n = value->size;
                        for (size_t j = 0; j < n; j++) {
                                key = &toks[obj_key];
                                value = key + 1;
                                if (json_streq(json, key, "message")) {
                                        ack.message = value;
                                        break;
                                }
                                obj_key =
                                    json_skip(num_toks, toks, obj_key + 1);
                        }
                }
                key_idx = json_skip(num_toks, toks, key_idx + 1);
        }

        if (status != 200 || ack.got_error || !ack.success) {
                ack.status = EXCHG_ORDER_ERROR;
                order_err_cpy(&info->info, json, ack.message);
                exchg_log("%s%s gave error response (status %d): ",
                          http_host(http), http_path(http), status);
                json_fprintln(stderr, json, &toks[0]);
        } else {
                ack.status = EXCHG_ORDER_PENDING;
                if (!ack.order_id) {
                        exchg_log("Coinbase sent order upate with no "
                                  "\"order_id\":\n");
                        json_fprintln(stderr, json, &toks[0]);
                } else {
                        set_order_id(client_private(cl), info, json,
                                     ack.order_id);
                }
        }
        struct order_update update = {
            .new_status = ack.status,
        };
        order_update(cl, info, &update);
        return 0;

bad:
        exchg_log("Received bad update from %s%s: %s:\n", http_host(http),
                  http_path(http), problem);
        json_fprintln(stderr, json, &toks[0]);
        strncpy(info->info.err, "bad update from Coinbase",
                EXCHG_ORDER_ERR_SIZE);
        struct order_update err_update = {
            .new_status = EXCHG_ORDER_ERROR,
        };
        order_update(cl, info, &err_update);
        return 0;
}

static struct exchg_http_ops place_order_ops = {
    .recv = orders_recv,
    .add_headers = private_add_headers,
    .on_free = http_data_free,
    .conn_data_size = sizeof(struct http_data),
};

static int place_order(struct exchg_client *cl, struct http *http,
                       struct order_info *oi)
{
        struct coinbase_client *cb = client_private(cl);
        struct coinbase_order *co = order_info_private(oi);
        struct http_data *data = http_private(http);
        struct exchg_order_info *info = &oi->info;
        struct exchg_pair_info *pinfo = &cl->pair_info[info->order.pair];
        struct coinbase_pair_info *cb_info = &cb->pair_info[info->order.pair];
        char price[30], size[30], client_oid[37];

        if (!pinfo->available) {
                exchg_log("Can't submit order in %s on Coinbase. Pair not "
                          "available on the exchange.\n",
                          exchg_pair_to_str(info->order.pair));
                snprintf(info->err, EXCHG_ORDER_ERR_SIZE,
                         "%s not available on Coinbase",
                         exchg_pair_to_str(info->order.pair));
                return -1;
        }

        uuid_unparse(co->client_oid, client_oid);
        decimal_to_str(price, &info->order.price);
        decimal_to_str(size, &info->order.size);
        if (http_body_sprintf(
                http,
                "{\"client_order_id\":\"%s\",\"product_id\":\"%s\","
                "\"side\":\"%s\",",
                client_oid, cb_info->id,
                info->order.side == EXCHG_SIDE_BUY ? "BUY" : "SELL") < 0) {
                snprintf(info->err, EXCHG_ORDER_ERR_SIZE, "Out-Of-Memory");
                return -1;
        }
        if (info->opts.immediate_or_cancel &&
            http_body_sprintf(http,
                              "\"order_configuration\":{"
                              "\"sor_limit_ioc\":{\"base_size\":\"%s\","
                              "\"limit_price\":\"%s\"}}}",
                              size, price) < 0) {
                snprintf(info->err, EXCHG_ORDER_ERR_SIZE, "Out-Of-Memory");
                return -1;
        } else if (!info->opts.immediate_or_cancel &&
                   http_body_sprintf(
                       http,
                       "\"order_configuration\":{"
                       "\"limit_limit_gtc\":{\"base_size\":\"%s\","
                       "\"limit_price\":\"%s\",\"post_only\":false}}}",
                       size, price) < 0) {
                snprintf(info->err, EXCHG_ORDER_ERR_SIZE, "Out-Of-Memory");
                return -1;
        }
        data->id = info->id;
        int ret = coinbase_http_auth(cl, http);
        if (!ret) {
                info->status = EXCHG_ORDER_SUBMITTED;
        } else {
                snprintf(info->err, EXCHG_ORDER_ERR_SIZE,
                         "error computing request JWT");
        }
        return ret;
}

static bool place_order_work(struct exchg_client *cl, void *p)
{
        struct order_info *info = p;

        if (!cl->pair_info_current)
                return false;

        struct http *http =
            exchg_http_post("api.coinbase.com", "/api/v3/brokerage/orders",
                            &place_order_ops, cl, &info->options);
        if (!http) {
                strncpy(info->info.err, "HTTP POST failed",
                        EXCHG_ORDER_ERR_SIZE);
                struct order_update update = {
                    .new_status = EXCHG_ORDER_ERROR,
                };
                order_update(cl, info, &update);
                return true;
        }
        if (place_order(cl, http, info)) {
                struct order_update update = {
                    .new_status = EXCHG_ORDER_ERROR,
                };
                order_update(cl, info, &update);
                http_close(http);
        }
        return true;
}

static struct order_info *new_order(struct exchg_client *cl,
                                    const struct exchg_order *order,
                                    const struct exchg_place_order_opts *opts,
                                    const struct exchg_request_options *options)
{
        struct order_info *oi = exchg_new_order(cl, order, opts, options,
                                                sizeof(struct coinbase_order));
        if (!oi)
                return NULL;

        struct coinbase_order *c = order_info_private(oi);
        uuid_generate(c->client_oid);

        return oi;
}

static int64_t coinbase_place_order(struct exchg_client *cl,
                                    const struct exchg_order *order,
                                    const struct exchg_place_order_opts *opts,
                                    const struct exchg_request_options *options)
{
        struct order_info *info;

        if (likely(cl->pair_info_current)) {
                struct http *http = exchg_http_post(
                    "api.coinbase.com", "/api/v3/brokerage/orders",
                    &place_order_ops, cl, options);
                if (!http)
                        return -1;
                info = new_order(cl, order, opts, options);
                if (!info) {
                        http_close(http);
                        return -1;
                }
                if (place_order(cl, http, info)) {
                        order_info_free(cl, info);
                        http_close(http);
                        return -1;
                }
        } else {
                if (get_pair_info(cl))
                        return -1;
                info = new_order(cl, order, opts, options);
                if (!info)
                        return -1;
                if (queue_work(cl, place_order_work, info)) {
                        order_info_free(cl, info);
                        return -1;
                }
        }
        return info->info.id;
}

static int orders_edit_recv(struct exchg_client *cl, struct http *http,
                            int status, char *json, int num_toks,
                            jsmntok_t *toks)
{
        const char *problem = "";
        struct http_data *data = http_private(http);
        struct order_info *info = exchg_order_lookup(cl, data->id);

        if (!info) {
                exchg_log("Received unknown order update from %s%s: ",
                          http_host(http), http_path(http));
                json_fprintln(stderr, json, &toks[0]);
                return 0;
        }

        if (toks[0].type != JSMN_OBJECT) {
                problem = "non-object data";
                goto bad;
        }

        bool success = false;
        int key_idx = 1;
        for (int i = 0; i < toks[0].size; i++) {
                jsmntok_t *key = &toks[key_idx];
                jsmntok_t *value = key + 1;

                if (json_streq(json, key, "success")) {
                        if (json_get_bool(&success, json, value)) {
                                problem = "bad \"success\" field";
                                goto bad;
                        }
                }
        }

        if (!success) {
                exchg_log("Coinbase: unsuccessful order edit of order %" PRId64
                          ": ",
                          data->id);
                json_fprintln(stderr, json, &toks[0]);
        }
        return 0;

bad:
        exchg_log("Received bad update from %s%s: %s: ", http_host(http),
                  http_path(http), problem);
        json_fprintln(stderr, json, &toks[0]);
        return 0;
}

static struct exchg_http_ops edit_order_ops = {
    .recv = orders_edit_recv,
    .add_headers = private_add_headers,
    .on_free = http_data_free,
    .conn_data_size = sizeof(struct http_data),
};

int coinbase_edit_order(struct exchg_client *cl, struct order_info *info,
                        const struct exchg_price_size *ps,
                        const struct exchg_request_options *options)
{
        struct coinbase_order *cb_info = order_info_private(info);

        struct http *http =
            exchg_http_post("api.coinbase.com", "/api/v3/brokerage/orders/edit",
                            &edit_order_ops, cl, options);
        if (!http)
                return -1;
        struct http_data *data = http_private(http);
        data->id = info->info.id;

        const decimal_t *new_price, *new_size;
        if (ps->price)
                new_price = ps->price;
        else
                new_price = &info->info.order.price;
        if (ps->size)
                new_size = ps->size;
        else
                new_size = &info->info.order.size;
        char price[30], size[30];
        decimal_to_str(price, new_price);
        decimal_to_str(size, new_size);

        if (http_body_sprintf(
                http,
                "{\"order_id\":\"%s\", \"price\":\"%s\", \"size\":\"%s\"}",
                cb_info->id, price, size) < 0)
                goto bad;

        if (coinbase_http_auth(cl, http))
                goto bad;
        return 0;

bad:
        http_close(http);
        return -1;
}

static int parse_cancel_result(char *json, int num_toks, jsmntok_t *toks,
                               int obj_idx, struct coinbase_order *co,
                               bool *found_it, bool *success,
                               jsmntok_t **failure_reason, const char **problem)
{
        jsmntok_t *obj = &toks[obj_idx];
        if (obj->type != JSMN_OBJECT) {
                *problem = "non-object \"result\" array member";
                return -1;
        }
        bool this_success = false;
        jsmntok_t *this_failure_reason = NULL;

        int key_idx = obj_idx + 1;
        for (size_t i = 0; i < obj->size; i++) {
                jsmntok_t *key = &toks[key_idx];
                jsmntok_t *value = key + 1;

                if (json_streq(json, key, "order_id")) {
                        if (json_streq(json, value, co->id)) {
                                *found_it = true;
                        } else {
                                return 0;
                        }
                } else if (json_streq(json, key, "success")) {
                        if (json_get_bool(&this_success, json, value)) {
                                *problem = "bad \"success\" field";
                                return -1;
                        }
                } else if (json_streq(json, key, "failure_reason")) {
                        this_failure_reason = value;
                }
                key_idx = json_skip(num_toks, toks, key_idx + 1);
        }
        if (!*found_it)
                return 0;
        *success = this_success;
        *failure_reason = this_failure_reason;
        return 1;
}

static int cancel_order_recv(struct exchg_client *cl, struct http *http,
                             int status, char *json, int num_toks,
                             jsmntok_t *toks)
{
        struct coinbase_client *cb = client_private(cl);
        const char *problem = "";
        struct http_data *data = http_private(http);
        struct order_info *info = exchg_order_lookup(cl, data->id);

        if (!info) {
                exchg_log("Received cancellation response for order %" PRId64
                          " which is now unknown.: ",
                          data->id);
                json_fprintln(stderr, json, &toks[0]);
                return 0;
        }
        struct coinbase_order *co = order_info_private(info);

        if (toks[0].type != JSMN_OBJECT) {
                problem = "non-object data";
                goto bad;
        }

        bool found_it = false;
        bool success = false;
        jsmntok_t *failure_reason = NULL;

        int key_idx = 1;
        for (int i = 0; i < toks[0].size; i++) {
                jsmntok_t *key = &toks[key_idx];
                jsmntok_t *value = key + 1;

                if (json_streq(json, key, "results")) {
                        if (value->type != JSMN_ARRAY) {
                                problem = "bad \"results\" field";
                                goto bad;
                        }
                        int n = value->size;
                        if (n == 0) {
                                problem = "empty \"results\" field";
                                goto bad;
                        }
                        if (n > 1) {
                                exchg_log("received more than one response "
                                          "from %s%s: ",
                                          http_host(http), http_path(http));
                                json_fprintln(stderr, json, &toks[0]);
                        }
                        int obj_key = key_idx + 2;
                        for (size_t j = 0; j < n; j++) {
                                key = &toks[obj_key];
                                value = key + 1;

                                int res = parse_cancel_result(
                                    json, num_toks, toks, obj_key, co,
                                    &found_it, &success, &failure_reason,
                                    &problem);
                                if (res > 0)
                                        goto break_outer;
                                else if (res < 0)
                                        goto bad;
                                obj_key = json_skip(num_toks, toks, obj_key);
                        }
                        break;
                }
                key_idx = json_skip(num_toks, toks, key_idx + 1);
        }
break_outer:

        if (!found_it) {
                problem = "expected \"order_id\" not found";
                goto bad;
        }
        if (success) {
                exchg_log(
                    "Coinbase: success response from %s%s. %s\n",
                    http_host(http), http_path(http),
                    cb->private_ws
                        ? "Waiting for confirmation from user websocket channel"
                        : "Cancellation update not being passed to the user. "
                          "Use exchg_private_ws_connect() to receive these "
                          "updates");
        } else {
                order_err_cpy(&info->info, json, failure_reason);
                // TODO: the UNSUBMITTED is ugly, should improve API. for now we
                // pass that to not change the status
                struct order_update update = {
                    .new_status = EXCHG_ORDER_UNSUBMITTED,
                    .cancel_failed = true,
                };
                order_update(cl, info, &update);
        }
        return 0;

bad:
        exchg_log("received bad response from %s%s: %s: ", http_host(http),
                  http_path(http), problem);
        json_fprintln(stderr, json, &toks[0]);
        struct order_update update = {
            .new_status = EXCHG_ORDER_UNSUBMITTED,
            .cancel_failed = true,
        };
        order_update(cl, info, &update);
        return 0;
}

static struct exchg_http_ops cancel_order_ops = {
    .recv = cancel_order_recv,
    .add_headers = private_add_headers,
    .on_free = http_data_free,
    .conn_data_size = sizeof(struct http_data),
};

static int coinbase_cancel_order(struct exchg_client *cl,
                                 struct order_info *info,
                                 const struct exchg_request_options *options)
{
        struct coinbase_order *co = order_info_private(info);
        if (unlikely(info->info.status == EXCHG_ORDER_UNSUBMITTED)) {
                remove_work(cl, place_order_work, info);
                struct order_update update = {
                    .new_status = EXCHG_ORDER_CANCELED,
                };
                order_update(cl, info, &update);
                return 0;
        }
        if (unlikely(!co->id[0])) {
                exchg_log("Can't cancel order %" PRId64
                          " with unknown order ID\n",
                          info->info.id);
                return -1;
        }

        struct http *http = exchg_http_post(
            "api.coinbase.com", "/api/v3/brokerage/orders/batch_cancel",
            &cancel_order_ops, cl, options);
        if (!http)
                return -1;
        if (http_body_sprintf(http, "{\"order_ids\":[\"%s\"]}", co->id) < 0) {
                // TODO: figure out what to tell the user/what to do with the
                // order on errors
                http_close(http);
                return -1;
        }
        struct http_data *data = http_private(http);
        if (coinbase_http_auth(cl, http)) {
                http_close(http);
                return -1;
        }
        data->id = info->info.id;
        return 0;
}

enum channel_type {
        CHANNEL_TYPE_UNKNOWN,
        CHANNEL_TYPE_SUBSCRIPTIONS,
        CHANNEL_TYPE_USER,
};

struct user_msg {
        enum channel_type channel;
        bool got_channel;
        int64_t timestamp;
        bool got_timestamp;
        bool parsed_events;
        int events_idx;
        struct message_seq seq;
        const char *unusual;
};

struct event_msg {
        bool got_type;
        bool is_update_type;
        bool parsed_orders;
        int orders_idx;
};

struct order_msg {
        bool got_order_id;
        struct order_info *order;
        bool got_status;
        enum exchg_order_status status;
        bool got_limit_price;
        decimal_t limit_price;
        bool got_avg_price;
        decimal_t avg_price;
        bool got_cumulative_quantity;
        decimal_t cumulative_quantity;
        jsmntok_t *cancel_reason;
        jsmntok_t *reject_Reason;
};

static int parse_orders_event(struct exchg_client *cl, char *json, int num_toks,
                              jsmntok_t *toks, struct user_msg *msg,
                              struct event_msg *event_msg, const char **problem)
{
        struct coinbase_client *cb = client_private(cl);
        event_msg->parsed_orders = true;
        jsmntok_t *orders = &toks[event_msg->orders_idx];

        if (orders->type != JSMN_ARRAY) {
                msg->unusual = "non-array orders event";
                return -1;
        }

        int obj_idx = event_msg->orders_idx + 1;
        for (size_t i = 0; i < orders->size; i++) {
                jsmntok_t *order = &toks[obj_idx];

                if (order->type != JSMN_OBJECT) {
                        msg->unusual = "non-object orders member";
                        return -1;
                }
                struct order_msg order_msg = {
                    // unsubmitted so exchg_order_update() wont change it if the
                    // status string is not recognized or isn't in the message
                    // for some reason
                    .status = EXCHG_ORDER_UNSUBMITTED,
                };
                int key_idx = obj_idx + 1;
                for (size_t i = 0; i < order->size; i++) {
                        jsmntok_t *key = &toks[key_idx];
                        jsmntok_t *value = key + 1;

                        // TODO: maybe sanity check other fields, and do
                        // something with outstanding_hold_amount
                        if (json_streq(json, key, "order_id")) {
                                if (value->type != JSMN_STRING) {
                                        *problem = "non-string order ID";
                                        return -1;
                                }
                                order_msg.got_order_id = true;
                                int64_t *order_id =
                                    lookup_order(cb, json, value);
                                if (order_id)
                                        order_msg.order =
                                            exchg_order_lookup(cl, *order_id);
                                if (!order_msg.order) {
                                        // TODO: dont log this on the last one
                                        // after a cancellation
                                        exchg_log("coinbase sent order update "
                                                  "for unknown order: ");
                                        json_fprintln(stderr, json, order);
                                        key_idx =
                                            json_skip(num_toks, toks, obj_idx);
                                        break;
                                }
                                key_idx += 2;
                        } else if (json_streq(json, key, "status")) {
                                if (value->type != JSMN_STRING) {
                                        *problem = "non-string order status";
                                        return -1;
                                }
                                order_msg.got_status = true;
                                if (__json_streq(json, value, "PENDING")) {
                                        order_msg.status = EXCHG_ORDER_PENDING;
                                } else if (__json_streq(json, value, "OPEN")) {
                                        order_msg.status = EXCHG_ORDER_OPEN;
                                } else if (__json_streq(json, value,
                                                        "FILLED")) {
                                        // we'll set it to finished below if the
                                        // whole amount is filled
                                        order_msg.status = EXCHG_ORDER_OPEN;
                                } else if (__json_streq(json, value,
                                                        "CANCELLED") ||
                                           json_streq(json, value,
                                                      "CANCELED")) {
                                        order_msg.status = EXCHG_ORDER_CANCELED;
                                        // TODO: maybe tell the user about
                                        // CANCEL_QUEUED?
                                } else if (__json_streq(json, value,
                                                        "CANCEL_QUEUED")) {
                                        exchg_log("Coinbase: received "
                                                  "CANCEL_QUEUED message\n");
                                        order_msg.order = NULL;
                                        key_idx =
                                            json_skip(num_toks, toks, obj_idx);
                                        break;
                                } else {
                                        fprintf(stderr, "TODO: order status "
                                                        "not recognized: ");
                                        json_fprintln(stderr, json, value);
                                }
                                key_idx += 2;
                        } else if (json_streq(json, key, "avg_price")) {
                                if (json_get_decimal(&order_msg.avg_price, json,
                                                     value)) {
                                        *problem = "bad order avg_price";
                                        return -1;
                                }
                                order_msg.got_avg_price = true;
                                key_idx += 2;
                        } else if (json_streq(json, key, "limit_price")) {
                                if (json_get_decimal(&order_msg.limit_price,
                                                     json, value)) {
                                        *problem = "bad order limit_price";
                                        return -1;
                                }
                                order_msg.got_limit_price = true;
                                key_idx += 2;
                        } else if (json_streq(json, key,
                                              "cumulative_quantity")) {
                                if (json_get_decimal(
                                        &order_msg.cumulative_quantity, json,
                                        value)) {
                                        *problem =
                                            "bad order cumulative_quantity";
                                        return -1;
                                }
                                order_msg.got_cumulative_quantity = true;
                                key_idx += 2;
                        } else if (json_streq(json, key, "cancel_reason")) {
                                order_msg.cancel_reason = value;
                                key_idx =
                                    json_skip(num_toks, toks, key_idx + 1);
                        } else if (json_streq(json, key, "reject_Reason")) {
                                order_msg.reject_Reason = value;
                                key_idx =
                                    json_skip(num_toks, toks, key_idx + 1);
                        } else {
                                key_idx =
                                    json_skip(num_toks, toks, key_idx + 1);
                        }
                }
                obj_idx = key_idx;

                if (!order_msg.got_order_id) {
                        msg->unusual = "order message with no order_id";
                        continue;
                }
                if (!order_msg.order) {
                        continue;
                }

                decimal_t *avg_price = NULL;
                decimal_t *cumulative_quantity = NULL;

                if (order_msg.got_cumulative_quantity) {
                        cumulative_quantity = &order_msg.cumulative_quantity;
                } else {
                        msg->unusual =
                            "order message with no cumulative_quantity";
                }
                if (order_msg.got_avg_price) {
                        avg_price = &order_msg.avg_price;
                } else {
                        msg->unusual = "order message with no avg_price";
                }
                if (!order_msg.got_status) {
                        msg->unusual = "order message with no status";
                }
                if (order_msg.status == EXCHG_ORDER_CANCELED &&
                    order_msg.cancel_reason) {
                        order_err_cpy(&order_msg.order->info, json,
                                      order_msg.cancel_reason);
                } else if (order_msg.status == EXCHG_ORDER_OPEN &&
                           cumulative_quantity &&
                           decimal_cmp(cumulative_quantity,
                                       &order_msg.order->info.order.size) >=
                               0) {
                        order_msg.status = EXCHG_ORDER_FINISHED;
                } else if (order_msg.reject_Reason) {
                        order_err_cpy(&order_msg.order->info, json,
                                      order_msg.reject_Reason);
                }
                struct order_update update = {
                    .timestamp = msg->timestamp,
                    .new_status = order_msg.status,
                    .filled_size = cumulative_quantity,
                    .avg_price = avg_price,
                };
                // TODO: update on new order size too
                if (order_msg.got_limit_price)
                        update.order_price = &order_msg.limit_price;
                order_update(cl, order_msg.order, &update);
        }
        return obj_idx;
}

static int parse_user_event(struct exchg_client *cl, char *json, int num_toks,
                            jsmntok_t *toks, int obj_idx, struct user_msg *msg,
                            const char **problem)
{
        struct coinbase_client *cb = client_private(cl);
        jsmntok_t *event = &toks[obj_idx];

        if (event->type != JSMN_OBJECT) {
                msg->unusual = "non-object user event";
                return json_skip(num_toks, toks, obj_idx);
        }

        struct event_msg event_msg = {.orders_idx = -1};
        int key_idx = obj_idx + 1;
        for (int i = 0; i < event->size; i++) {
                jsmntok_t *key = &toks[key_idx];
                jsmntok_t *value = key + 1;

                if (json_streq(json, key, "type")) {
                        event_msg.got_type = true;
                        if (json_streq(json, value, "update")) {
                                event_msg.is_update_type = true;
                                if (msg->channel == CHANNEL_TYPE_USER &&
                                    event_msg.orders_idx >= 0 &&
                                    !event_msg.parsed_orders) {
                                        if (parse_orders_event(
                                                cl, json, num_toks, toks, msg,
                                                &event_msg, problem) < 0)
                                                return -1;
                                }
                                key_idx += 2;
                        } else if (json_streq(json, value, "snapshot")) {
                                // TODO: maybe parse this if the user wants it
                                key_idx += 2;
                        } else {
                                key_idx =
                                    json_skip(num_toks, toks, key_idx + 1);
                        }
                } else if (json_streq(json, key, "orders")) {
                        event_msg.orders_idx = key_idx + 1;
                        if (event_msg.is_update_type) {
                                key_idx = parse_orders_event(
                                    cl, json, num_toks, toks, msg, &event_msg,
                                    problem);
                                if (key_idx < 0)
                                        return -1;
                        } else {
                                if (msg->channel != CHANNEL_TYPE_USER) {
                                        msg->unusual =
                                            "\"orders\" in non-user channel";
                                }
                                key_idx =
                                    json_skip(num_toks, toks, key_idx + 1);
                        }
                } else if (json_streq(json, key, "subscriptions")) {
                        if (value->type != JSMN_OBJECT) {
                                msg->unusual = "non-object subscriptions event";
                                return json_skip(num_toks, toks, obj_idx);
                        }
                        if (msg->channel != CHANNEL_TYPE_SUBSCRIPTIONS) {
                                msg->unusual =
                                    "unexpected subscriptions event in events";
                                return json_skip(num_toks, toks, obj_idx);
                        }
                        int n = value->size;
                        if (n > 1)
                                msg->unusual =
                                    "more than one subscriptions event";
                        int k = key_idx + 2;
                        for (int j = 0; j < n; j++) {
                                key = &toks[k];

                                if (json_streq(json, key, "user")) {
                                        cb->user_chan_sub_acked = true;
                                        exchg_on_event(cl,
                                                       EXCHG_PRIVATE_WS_ONLINE);
                                        break;
                                } else {
                                        msg->unusual =
                                            "unknown subscriptions event";
                                }
                                k = json_skip(num_toks, toks, k + 1);
                        }
                        key_idx = json_skip(num_toks, toks, key_idx + 1);
                } else {
                        key_idx = json_skip(num_toks, toks, key_idx + 1);
                }
        }
        if (msg->channel != CHANNEL_TYPE_USER)
                return key_idx;
        if (!event_msg.got_type) {
                msg->unusual = "no \"type\" in user channel message\n";
        } else if (event_msg.is_update_type && !event_msg.parsed_orders) {
                msg->unusual = "no \"orders\" in user channel message\n";
        }
        return key_idx;
}

static int parse_user_events(struct exchg_client *cl, char *json, int num_toks,
                             jsmntok_t *toks, struct user_msg *msg,
                             const char **problem)
{
        jsmntok_t *events = &toks[msg->events_idx];
        if (events->type != JSMN_ARRAY) {
                *problem = "bad \"events\"";
                return -1;
        }
        msg->parsed_events = true;
        int obj_idx = msg->events_idx + 1;
        for (int i = 0; i < events->size; i++) {
                obj_idx = parse_user_event(cl, json, num_toks, toks, obj_idx,
                                           msg, problem);
                if (obj_idx < 0)
                        return -1;
        }
        return obj_idx;
}

static bool should_parse_events(struct user_msg *msg)
{
        return msg->events_idx >= 0 && !msg->parsed_events &&
               msg->channel != CHANNEL_TYPE_UNKNOWN && msg->got_timestamp;
}

static int private_ws_recv(struct exchg_client *cl, struct websocket *w,
                           char *json, int num_toks, jsmntok_t *toks)
{
        struct coinbase_conn_info *conn_info = websocket_private(w);

        const char *problem = "";
        if (toks[0].type != JSMN_OBJECT) {
                problem = "not a JSON object";
                goto bad;
        }

        struct user_msg msg = {
            .events_idx = -1,
        };

        int key_idx = 1;
        for (int i = 0; i < toks[0].size; i++) {
                jsmntok_t *key = &toks[key_idx];
                jsmntok_t *value = &toks[key_idx + 1];

                if (json_streq(json, key, "channel")) {
                        if (value->type != JSMN_STRING) {
                                problem = "bad \"channel\"";
                                goto bad;
                        }
                        msg.got_channel = true;
                        if (json_streq(json, value, "subscriptions")) {
                                msg.channel = CHANNEL_TYPE_SUBSCRIPTIONS;
                        } else if (json_streq(json, value, "user")) {
                                msg.channel = CHANNEL_TYPE_USER;
                        } else {
                                msg.channel = CHANNEL_TYPE_UNKNOWN;
                                msg.unusual = "unknown channel";
                        }
                        if (should_parse_events(&msg)) {
                                if (parse_user_events(cl, json, num_toks, toks,
                                                      &msg, &problem) < 0)
                                        goto bad;
                        }
                        key_idx += 2;
                } else if (json_streq(json, key, "timestamp")) {
                        if (parse_timestamp(&msg.timestamp, json, value,
                                            &problem))
                                return -1;
                        msg.got_timestamp = true;
                        if (should_parse_events(&msg)) {
                                if (parse_user_events(cl, json, num_toks, toks,
                                                      &msg, &problem) < 0)
                                        goto bad;
                        }
                        key_idx += 2;
                } else if (json_streq(json, key, "sequence_num")) {
                        if (json_get_int(&msg.seq.sequence_num, json, value)) {
                                problem = "bad \"sequence_num\"";
                                goto bad;
                        }
                        msg.seq.got_sequence_num = true;
                        key_idx += 2;
                } else if (json_streq(json, key, "events")) {
                        msg.events_idx = key_idx + 1;
                        if (should_parse_events(&msg)) {
                                key_idx = parse_user_events(
                                    cl, json, num_toks, toks, &msg, &problem);
                        } else {
                                key_idx =
                                    json_skip(num_toks, toks, key_idx + 1);
                        }
                        if (key_idx < 1)
                                goto bad;
                } else {
                        key_idx = json_skip(num_toks, toks, key_idx + 1);
                }
        }
        if (check_seq_num(conn_info, &msg.seq))
                return -1;
        if (!msg.got_channel) {
                msg.unusual = "no \"channel\"";
        } else if (msg.channel != CHANNEL_TYPE_UNKNOWN && !msg.parsed_events) {
                msg.unusual = "no \"events\"";
        }
        if (msg.unusual) {
                exchg_log("Coinbase user websocket gave unusual update: %s: ",
                          msg.unusual);
                json_fprintln(stderr, json, &toks[0]);
        }
        return 0;

bad:
        exchg_log("Coinbase gave bad update: %s:\n", problem);
        json_fprintln(stderr, json, &toks[0]);
        return -1;
}

static int user_channel_sub(struct exchg_client *cl)
{
        struct coinbase_client *cb = client_private(cl);

        if (!cb->watching_user_chan || cb->user_chan_subbed)
                return 0;

        char *jwt = coinbase_ws_jwt(cl);
        if (!jwt)
                return -1;
        int n = websocket_printf(cb->private_ws,
                                 "{ \"type\": \"subscribe\", "
                                 "\"channel\": \"user\","
                                 "\"jwt\": \"%s\"}",
                                 jwt);
        free(jwt);
        if (n < 0)
                return -1;
        cb->user_chan_subbed = true;
        return 0;
}

static bool user_sub_work(struct exchg_client *cl, void *p)
{
        struct coinbase_client *cb = client_private(cl);

        if (!cl->pair_info_current || !websocket_established(cb->private_ws))
                return false;

        user_channel_sub(cl);
        return true;
}

static int private_ws_on_established(struct exchg_client *cl,
                                     struct websocket *w)
{
        if (!cl->pair_info_current)
                return queue_work_exclusive(cl, user_sub_work, NULL);
        else
                return user_channel_sub(cl);
}

// TODO: warn user/reconnect
static int private_ws_on_disconnect(struct exchg_client *cl,
                                    struct websocket *ws, int reconnect_seconds)
{
        struct coinbase_client *cb = client_private(cl);
        struct coinbase_conn_info *conn_info = websocket_private(ws);
        if (reconnect_seconds < 0)
                cb->private_ws = NULL;
        cb->user_chan_subbed = false;
        cb->user_chan_sub_acked = false;
        conn_info_reset(conn_info);
        return 0;
}

static const struct exchg_websocket_ops private_ws_ops = {
    .on_conn_established = private_ws_on_established,
    .on_disconnect = private_ws_on_disconnect,
    .recv = private_ws_recv,
    .conn_data_size = sizeof(struct coinbase_conn_info),
};

static int
coinbase_priv_ws_connect(struct exchg_client *cl,
                         const struct exchg_websocket_options *options)
{
        struct coinbase_client *cb = client_private(cl);

        if (cb->private_ws)
                websocket_log_options_discrepancies(cb->private_ws, options);

        if (get_pair_info(cl))
                return -1;

        if (!cb->pkey) {
                exchg_log("exchg_private_ws_connect called for coinbase but no "
                          "private key loaded\n");
                return -1;
        }

        cb->watching_user_chan = true;
        if (!cb->private_ws) {
                // TODO: failover to advanced-trade-ws.coinbase.com if this is
                // down
                cb->private_ws = exchg_websocket_connect(
                    cl, "advanced-trade-ws-user.coinbase.com", "/",
                    &private_ws_ops, options);
                if (!cb->private_ws)
                        return -1;
                return 0;
        } else {
                return user_channel_sub(cl);
        }
}

static bool coinbase_priv_ws_online(struct exchg_client *cl)
{
        struct coinbase_client *cb = client_private(cl);
        return cb->watching_user_chan && cb->user_chan_sub_acked;
}

static void coinbase_destroy(struct exchg_client *cl)
{
        struct coinbase_client *cb = client_private(cl);

        coinbase_auth_free(cl);
        for (enum exchg_pair p = 0; p < EXCHG_NUM_PAIRS; p++)
                free(cb->pair_info[p].id);
        g_hash_table_unref(cb->orders);
        free_exchg_client(cl);
}

struct exchg_client *alloc_coinbase_client(struct exchg_context *ctx)
{
        struct exchg_client *ret =
            alloc_exchg_client(ctx, EXCHG_COINBASE, "SHA256", 2000,
                               sizeof(struct coinbase_client));
        if (!ret)
                return NULL;
        struct coinbase_client *cb = client_private(ret);

        cb->orders = g_hash_table_new_full(g_str_hash, g_str_equal, free, free);

        ret->name = "Coinbase";
        ret->l2_subscribe = coinbase_l2_subscribe;
        ret->get_pair_info = coinbase_get_pair_info;
        ret->get_balances = coinbase_get_balances;
        ret->place_order = coinbase_place_order;
        ret->edit_order = coinbase_edit_order;
        ret->cancel_order = coinbase_cancel_order;
        ret->priv_ws_connect = coinbase_priv_ws_connect;
        ret->priv_ws_online = coinbase_priv_ws_online;
        ret->new_keypair = coinbase_new_keypair;
        ret->new_keypair_from_file = coinbase_new_keypair_from_file;
        ret->destroy = coinbase_destroy;
        return ret;
}
