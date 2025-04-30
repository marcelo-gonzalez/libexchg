// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#ifndef EXCHG_EXCHG_CCY_H
#define EXCHG_EXCHG_CCY_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

enum exchg_currency {
        EXCHG_CCY_USD,
        EXCHG_CCY_BTC,
        EXCHG_CCY_ETH,
        EXCHG_CCY_ZEC,
        EXCHG_CCY_XRP,
        EXCHG_CCY_LTC,
        EXCHG_CCY_BCH,
        EXCHG_CCY_DAI,
        EXCHG_CCY_NEAR,
        EXCHG_NUM_CCYS,
};

enum exchg_pair {
        INVALID_PAIR = -1,
        EXCHG_PAIR_BTCUSD = 0,
        EXCHG_PAIR_ETHUSD,
        EXCHG_PAIR_ETHBTC,
        EXCHG_PAIR_ZECUSD,
        EXCHG_PAIR_ZECBTC,
        EXCHG_PAIR_ZECETH,
        EXCHG_PAIR_ZECBCH,
        EXCHG_PAIR_ZECLTC,
        EXCHG_PAIR_BCHUSD,
        EXCHG_PAIR_BCHBTC,
        EXCHG_PAIR_BCHETH,
        EXCHG_PAIR_LTCUSD,
        EXCHG_PAIR_LTCBTC,
        EXCHG_PAIR_LTCETH,
        EXCHG_PAIR_LTCBCH,
        // TODO: other dai pairs
        EXCHG_PAIR_DAIUSD,
        EXCHG_PAIR_NEARUSD,
        EXCHG_NUM_PAIRS,
};

const char *exchg_pair_to_str(enum exchg_pair pair);

// These return nonzero on error
int exchg_str_to_pair(enum exchg_pair *pair, const char *str);
int exchg_strn_to_pair(enum exchg_pair *pair, const char *str, int len);
int exchg_pair_base(enum exchg_currency *base, enum exchg_pair pair);
int exchg_pair_counter(enum exchg_currency *counter, enum exchg_pair pair);
int exchg_pair_split(enum exchg_currency *base, enum exchg_currency *counter,
                     enum exchg_pair pair);
int exchg_str_to_ccy(enum exchg_currency *dst, const char *str);
int exchg_strn_to_ccy(enum exchg_currency *dst, const char *str, size_t len);

enum exchg_join_type {
        JOIN_TYPE_FIRST_BASE,
        JOIN_TYPE_FIRST_COUNTER,
        JOIN_TYPE_ERROR,
};

enum exchg_join_type exchg_ccy_join(enum exchg_pair *dst, enum exchg_currency a,
                                    enum exchg_currency b);

const char *exchg_ccy_to_str(enum exchg_currency currency);
const char *exchg_ccy_to_upper(enum exchg_currency currency);

#ifdef __cplusplus
}
#endif

#endif
