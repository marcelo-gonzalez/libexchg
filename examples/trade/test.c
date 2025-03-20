// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <exchg/exchg.h>
#include <exchg/test.h>

#include "trader.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*x))

static struct exchg_test_str_l2_updates events[] = {
    {.pair = EXCHG_PAIR_BTCUSD,
     .bids = {{"30000", "1"}, {"29500", ".1"}, {"29400", ".2"}, {"29100", "2"}},
     .asks = {{"31000", "3.3"}, {"32000", "4.3"}}},
    {.pair = EXCHG_PAIR_BTCUSD, .bids = {{"29000", "1.2"}}},
    {.pair = EXCHG_PAIR_BTCUSD,
     .bids = {{"28000", "10"}},
     .asks = {{"31000", "3.4"}}},
};

struct test_events {
        int num_generated;
        enum exchg_id exchange;
};

static void event_cb(struct exchg_net_context *net_ctx,
                     struct exchg_test_event *ev, void *p)
{
        struct test_events *t = p;
        if (ev)
                exchg_test_event_print(ev);
        if (!ev && t->num_generated < 8) {
                struct exchg_test_event event;
                decimal_t price, size;

                memset(&event, 0, sizeof(event));
                decimal_from_str(&price, "28000");
                size.places = 0;
                size.value = t->num_generated + 1;

                event.id = t->exchange;
                event.type = EXCHG_EVENT_BOOK_UPDATE;
                event.data.book.pair = EXCHG_PAIR_BTCUSD;
                exchg_test_l2_queue_order(&event.data.book, true, &price,
                                          &size);
                exchg_test_add_events(net_ctx, 1, &event);
                t->num_generated++;
        }
}

int main(void)
{
        int ret = 0;
        for (enum exchg_id id = 0; id < EXCHG_ALL_EXCHANGES; id++) {
                if (id == EXCHG_BITSTAMP)
                        continue;
                for (enum exchg_side side = 0; side < 2; side++) {
                        for (int i = 0; i < ARRAY_SIZE(events); i++) {
                                events[i].id = id;
                        }
                        struct trade_options opts = {
                            .verbose = true,
                            .side = side,
                            .pair = EXCHG_PAIR_BTCUSD,
                        };

                        decimal_from_str(&opts.size, "1.2");

                        printf("----------------------------\n");
                        struct trade_state state;
                        trade_init(&state, &opts);

                        struct exchg_options exchg_opts = {
                            .track_book = true,
                        };

                        struct test_events t = {.exchange = id};
                        struct exchg_test_options test_opts = {
                            .event_cb = event_cb,
                            .callback_user = &t,
                        };
                        struct exchg_context *ctx = exchg_test_new(
                            &trade_callbacks, &exchg_opts, &state, &test_opts);
                        struct exchg_net_context *net_ctx =
                            exchg_test_net_ctx(ctx);

                        struct exchg_client *cl = exchg_alloc_client(ctx, id);
                        if (!cl)
                                goto free_ctx;
                        switch (id) {
                        case EXCHG_GEMINI:
                                exchg_set_keypair(
                                    cl, strlen(exchg_test_gemini_public),
                                    (unsigned char *)exchg_test_gemini_public,
                                    strlen(exchg_test_gemini_private),
                                    (unsigned char *)exchg_test_gemini_private);
                                break;
                        case EXCHG_KRAKEN:
                                exchg_set_keypair(
                                    cl, strlen(exchg_test_kraken_public),
                                    (unsigned char *)exchg_test_kraken_public,
                                    strlen(exchg_test_kraken_private),
                                    (unsigned char *)exchg_test_kraken_private);
                                break;
                        case EXCHG_BITSTAMP:
                                exchg_set_keypair(
                                    cl, strlen(exchg_test_bitstamp_public),
                                    (unsigned char *)exchg_test_bitstamp_public,
                                    strlen(exchg_test_bitstamp_private),
                                    (unsigned char *)
                                        exchg_test_bitstamp_private);
                                break;
                        case EXCHG_COINBASE:
                                exchg_set_keypair(
                                    cl, strlen(exchg_test_coinbase_public),
                                    (unsigned char *)exchg_test_coinbase_public,
                                    strlen(exchg_test_coinbase_private),
                                    (unsigned char *)
                                        exchg_test_coinbase_private);
                                exchg_set_password(
                                    cl, strlen(exchg_test_coinbase_password),
                                    exchg_test_coinbase_password);
                                break;
                        default:
                                fprintf(stderr, "wtf\n");
                                return 1;
                        }

                        if (exchg_private_ws_connect(ctx, id, NULL))
                                goto free_ctx;

                        exchg_test_add_l2_events(net_ctx, ARRAY_SIZE(events),
                                                 events);

                        decimal_t *balances = exchg_test_balances(net_ctx, id);
                        decimal_from_str(&balances[EXCHG_CCY_USD], "40000");

                        ret |= trade_run(&state, cl);

                free_ctx:
                        exchg_free(ctx);
                }
        }
        return ret;
}
