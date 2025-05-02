// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Marcelo Diop-Gonzalez

#ifndef COINBASE_CLIENT_H
#define COINBASE_CLIENT_H

#include <openssl/evp.h>

#include "client.h"

struct http_data {
        size_t jwt_len;
        char *jwt;
        union {
                // Used for balances private data
                void *private;
                // Used for order placement
                int64_t id;
        };
};

struct coinbase_client {
        bool watching_user_chan;
        bool user_chan_subbed;
        bool user_chan_sub_acked;
        bool sub_acked;
        bool authenticate_channel_sub;
        struct coinbase_pair_info {
                char *id;
                bool subbed;
                bool watching_l2;
        } pair_info[EXCHG_NUM_PAIRS];
        struct websocket *public_ws;
        struct websocket *private_ws;
        GHashTable *orders;
        EVP_PKEY *pkey;
};

#endif
