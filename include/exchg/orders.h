// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#ifndef EXCHG_ORDERS_H
#define EXCHG_ORDERS_H

#include "exchg/decimal.h"

struct exchg_limit_order {
        int exchange_id;
        int64_t update_micros;
        decimal_t price;
        decimal_t net_price;
        decimal_t size;
};

struct exchg_l2_update {
        int exchange_id;
        int num_bids;
        struct exchg_limit_order *bids;
        int num_asks;
        struct exchg_limit_order *asks;
};

#endif
