// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#ifndef EXAMPLES_TRADER_H
#define EXAMPLES_TRADER_H

#include <string.h>

#include "client.h"
#include "exchg/currency.h"
#include "exchg/decimal.h"

// TODO price ceiling
struct trade_state {
        int sent;
        bool start_balances_recvd;
        bool end_balances_recvd;
        struct exchg_order order;
        decimal_t left_to_send;
        decimal_t start_base;
        decimal_t start_counter;
        struct timespec sent_at;
        int error;
        bool verbose;
        int updates_printed;
        bool acked;
        bool first_recvd;
        struct timespec acked_at;
};

struct trade_options {
        bool verbose;
        decimal_t size;
        enum exchg_side side;
        enum exchg_pair pair;
};

static inline void trade_init(struct trade_state *s, struct trade_options *opts)
{
        memset(s, 0, sizeof(*s));
        s->verbose = opts->verbose;
        s->left_to_send = opts->size;
        s->order.size = opts->size;
        s->order.side = opts->side;
        s->order.pair = opts->pair;
}

int trade_run(struct trade_state *s, struct exchg_client *cl);

extern struct exchg_callbacks trade_callbacks;

#endif
