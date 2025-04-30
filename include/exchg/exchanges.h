// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#ifndef EXCHG_EXCHANGES_H
#define EXCHG_EXCHANGES_H

#ifdef __cplusplus
extern "C" {
#endif

enum exchg_id {
        // Bitstamp order placement not fully implemented/tested
        EXCHG_BITSTAMP = 0,
        EXCHG_GEMINI,
        EXCHG_KRAKEN,
        EXCHG_COINBASE,
        EXCHG_ALL_EXCHANGES,
};

const char *exchg_id_to_name(enum exchg_id id);

#ifdef __cplusplus
}
#endif

#endif
