// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <exchg/exchg.h>

#include "trader.h"

struct find_price_arg {
        struct trade_state *state;
        bool filled;
};

static int buy_up(const struct exchg_limit_order *o, void *user)
{
        struct find_price_arg *b = user;
        struct trade_state *state = b->state;

        if (state->verbose) {
                char s[30], p[30];

                decimal_to_str(s, &o->size);
                decimal_to_str(p, &o->price);
                printf("trading against: price: %s size: %s\n", p, s);
        }

        state->order.price = o->price;

        if (b->filled)
                return 1;

        if (decimal_cmp(&o->size, &state->left_to_send) < 0) {
                decimal_subtract_inplace(&state->left_to_send, &o->size);
                return 0;
        }
        decimal_zero(&state->left_to_send);
        b->filled = true;
        return 0;
}

static int sell_down(const struct exchg_limit_order *o, void *user)
{
        struct find_price_arg *b = user;
        struct trade_state *state = b->state;

        if (state->verbose) {
                char s[30], p[30];

                decimal_to_str(s, &o->size);
                decimal_to_str(p, &o->price);
                printf("trading against: price: %s size: %s\n", p, s);
        }

        state->order.price = o->price;

        if (b->filled)
                return 1;

        if (decimal_cmp(&o->size, &state->left_to_send) < 0) {
                decimal_subtract_inplace(&state->left_to_send, &o->size);
                return 0;
        }
        decimal_zero(&state->left_to_send);
        b->filled = true;
        return 0;
}

static void make_trades(struct exchg_client *cl, struct trade_state *state)
{
        struct exchg_context *ctx = exchg_ctx(cl);
        struct find_price_arg b = {
            .state = state,
        };

        if (state->order.side == EXCHG_SIDE_BUY)
                exchg_foreach_ask(ctx, state->order.pair, buy_up, &b);
        else
                exchg_foreach_bid(ctx, state->order.pair, sell_down, &b);
        if (!decimal_is_zero(&state->left_to_send)) {
                fprintf(stderr, "requested amount can't be filled. not enough "
                                "orders on the exchange\n");
                state->error = 1;
                exchg_shutdown(ctx);
                return;
        }

        struct exchg_place_order_opts opts = {
            .immediate_or_cancel = true,
        };
        // TODO: check intent here so we can print out the price/approx
        // expected sizes on both sides of the trade
        if (exchg_place_order(cl, &state->order, &opts, NULL) < 0) {
                exchg_shutdown(ctx);
                state->error = 1;
                return;
        }

        clock_gettime(CLOCK_MONOTONIC, &state->sent_at);
        state->sent = 1;
        char price[30];
        decimal_to_str(price, &state->order.price);
        printf("price: %s\n", price);
}

static void time_since(struct timespec *dst, const struct timespec *ts)
{
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);

        time_t carry = now.tv_nsec < ts->tv_nsec ? 1 : 0;
        dst->tv_nsec = now.tv_nsec - ts->tv_nsec;
        if (carry)
                dst->tv_nsec += 1000000000;
        dst->tv_sec = now.tv_sec - ts->tv_sec - carry;
}

static bool ready_to_trade(struct exchg_client *cl, struct trade_state *state)
{
        // TODO: or ->stop. maybe cant assume you wont be called back after
        // exchg_shutdown()
        if (state->sent || !exchg_private_ws_online(cl) ||
            !state->start_balances_recvd)
                return false;
        if (state->order.side == EXCHG_SIDE_BUY)
                return exchg_num_asks(exchg_ctx(cl), state->order.pair) > 0;
        else
                return exchg_num_bids(exchg_ctx(cl), state->order.pair) > 0;
}

static void on_l2_update(struct exchg_client *cl, enum exchg_pair pair,
                         struct exchg_l2_update *update, void *user)
{
        struct trade_state *state = user;

        if (ready_to_trade(cl, state))
                make_trades(cl, state);

        if (!state->sent || !state->verbose)
                return;

        if (!state->first_recvd) {
                state->first_recvd = true;
                return;
        }

        struct timespec diff;
        char after[50];
        if (state->acked) {
                time_since(&diff, &state->acked_at);
                if (state->end_balances_recvd &&
                    (state->updates_printed > 6 || diff.tv_sec > 1)) {
                        exchg_shutdown(exchg_ctx(cl));
                        return;
                }
                if (state->updates_printed > 6)
                        return;
                sprintf(after, "%ld.%.9ld after order acked", diff.tv_sec,
                        diff.tv_nsec);
        } else if (state->sent) {
                if (state->updates_printed > 6)
                        return;
                time_since(&diff, &state->sent_at);
                sprintf(after, "%ld.%.9ld after order sent", diff.tv_sec,
                        diff.tv_nsec);
        } else
                after[0] = 0;

        if (update->num_bids > 0)
                printf("--- bid update %s ---\n", after);
        for (int i = 0; i < update->num_bids; i++) {
                struct exchg_limit_order *o = &update->bids[i];
                char p[30], s[30];
                decimal_to_str(p, &o->price);
                decimal_to_str(s, &o->size);

                printf("price: %s size: %s\n", p, s);
        }
        if (update->num_asks > 0)
                printf("--- asks update %s ---\n", after);
        for (int i = 0; i < update->num_asks; i++) {
                struct exchg_limit_order *o = &update->asks[i];
                char p[30], s[30];
                decimal_to_str(p, &o->price);
                decimal_to_str(s, &o->size);

                printf("price: %s size: %s\n", p, s);
        }
        state->updates_printed++;
}

static void on_order_update(struct exchg_client *cl,
                            const struct exchg_order_info *info, void *user,
                            void *priv)
{
        struct trade_state *state = user;
        struct timespec elapsed;
        const char *status;

        time_since(&elapsed, &state->sent_at);
        if (state->verbose) {
                switch (info->status) {
                case EXCHG_ORDER_UNSUBMITTED:
                        status = "UNSUBMITTED";
                        break;
                case EXCHG_ORDER_SUBMITTED:
                        status = "SUBMITTED";
                        break;
                case EXCHG_ORDER_PENDING:
                        status = "PENDING";
                        break;
                case EXCHG_ORDER_OPEN:
                        status = "OPEN";
                        break;
                case EXCHG_ORDER_FINISHED:
                        status = "FINISHED";
                        break;
                case EXCHG_ORDER_CANCELED:
                        status = "CANCELED";
                        break;
                case EXCHG_ORDER_ERROR:
                        status = "ERROR";
                        break;
                default:
                        status = "<Unknown>";
                        break;
                }
                char filled[30], out_of[30];
                decimal_to_str(filled, &info->filled_size);
                decimal_to_str(out_of, &info->order.size);

                printf("=== <Order Update> === status: %s %s "
                       "filled %s/%s. latency: %ld.%.9ld ===========\n",
                       status,
                       info->status == EXCHG_ORDER_ERROR ? info->err : "",
                       filled, out_of, elapsed.tv_sec, elapsed.tv_nsec);
        }

        if (info->status == EXCHG_ORDER_ERROR) {
                if (!state->verbose)
                        printf("order error: %s\n", info->err);
                exchg_shutdown(exchg_ctx(cl));
                state->error = 1;
                return;
        }

        if (info->status == EXCHG_ORDER_CANCELED) {
                printf("order canceled: %s\n", info->err);
                exchg_shutdown(exchg_ctx(cl));
                return;
        }

        if (info->status != EXCHG_ORDER_FINISHED)
                return;

        char sz[30];

        decimal_to_str(sz, &info->filled_size);

        if (!state->verbose)
                printf("%s %s %s. latency: %ld.%.9ld\n",
                       info->order.side == EXCHG_SIDE_BUY ? "bought" : "sold",
                       sz, exchg_pair_to_str(info->order.pair), elapsed.tv_sec,
                       elapsed.tv_nsec);
        exchg_get_balances(cl, NULL);
        clock_gettime(CLOCK_MONOTONIC, &state->acked_at);
        state->acked = true;
        state->updates_printed = 0;
}

static void on_balances(struct exchg_client *cl,
                        const decimal_t balances[EXCHG_NUM_CCYS], void *user,
                        void *req_private)
{
        struct exchg_context *ctx = exchg_ctx(cl);
        struct trade_state *state = user;
        enum exchg_currency base, counter;

        exchg_pair_split(&base, &counter, state->order.pair);
        state->start_balances_recvd = true;
        if (!state->sent) {
                state->start_base = balances[base];
                state->start_counter = balances[counter];
                if (ready_to_trade(cl, state)) {
                        make_trades(cl, state);
                }
        } else {
                decimal_t base_diff, counter_diff;
                decimal_subtract(&base_diff, &balances[base],
                                 &state->start_base);
                decimal_subtract(&counter_diff, &balances[counter],
                                 &state->start_counter);
                char basestr[30], counterstr[30];
                if (decimal_is_positive(&base_diff)) {
                        basestr[0] = '+';
                        decimal_to_str(&basestr[1], &base_diff);
                } else {
                        decimal_to_str(basestr, &base_diff);
                }
                if (decimal_is_positive(&counter_diff)) {
                        counterstr[0] = '+';
                        decimal_to_str(&counterstr[1], &counter_diff);
                } else {
                        decimal_to_str(counterstr, &counter_diff);
                }

                printf("balance changes: %s: %s, %s: %s\n",
                       exchg_ccy_to_str(base), basestr,
                       exchg_ccy_to_str(counter), counterstr);
                state->end_balances_recvd = true;
                if (!state->verbose)
                        exchg_shutdown(ctx);
        }
}

static void on_event(struct exchg_client *cl, enum exchg_event_type type,
                     void *user)
{
        struct trade_state *state = user;

        if (type == EXCHG_PRIVATE_WS_ONLINE && ready_to_trade(cl, state))
                make_trades(cl, state);
}

struct exchg_callbacks trade_callbacks = {
    .on_l2_update = on_l2_update,
    .on_order_update = on_order_update,
    .on_balances_recvd = on_balances,
    .on_event = on_event,
};

int trade_run(struct trade_state *s, struct exchg_client *cl)
{
        struct exchg_context *ctx = exchg_ctx(cl);

        if (exchg_private_ws_connect(ctx, exchg_id(cl)))
                return -1;

        if (exchg_l2_subscribe(ctx, exchg_id(cl), s->order.pair))
                return -1;

        if (exchg_get_balances(cl, NULL))
                return -1;

        exchg_run(ctx);

        return s->error;
}
