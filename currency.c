// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "exchg/currency.h"

const char *exchg_ccy_to_str(enum exchg_currency currency) {
	switch (currency) {
	case EXCHG_CCY_USD:
		return "usd";
	case EXCHG_CCY_BTC:
		return "btc";
	case EXCHG_CCY_ETH:
		return "eth";
	case EXCHG_CCY_ZEC:
		return "zec";
	case EXCHG_CCY_XRP:
		return "xrp";
	case EXCHG_CCY_LTC:
		return "ltc";
	case EXCHG_CCY_BCH:
		return "bch";
	case EXCHG_CCY_DAI:
		return "dai";
	case EXCHG_CCY_NEAR:
		return "near";
	default:
		return "<bad currency>";
	}
}

const char *exchg_ccy_to_upper(enum exchg_currency currency) {
	switch (currency) {
	case EXCHG_CCY_USD:
		return "USD";
	case EXCHG_CCY_BTC:
		return "BTC";
	case EXCHG_CCY_ETH:
		return "ETH";
	case EXCHG_CCY_ZEC:
		return "ZEC";
	case EXCHG_CCY_XRP:
		return "XRP";
	case EXCHG_CCY_LTC:
		return "LTC";
	case EXCHG_CCY_BCH:
		return "BCH";
	case EXCHG_CCY_DAI:
		return "DAI";
	case EXCHG_CCY_NEAR:
		return "NEAR";
	default:
		return "<bad currency>";
	}
}

const char *exchg_pair_to_str(enum exchg_pair pair) {
	switch (pair) {
	case EXCHG_PAIR_BTCUSD:
		return "btcusd";
	case EXCHG_PAIR_ETHUSD:
		return "ethusd";
	case EXCHG_PAIR_ETHBTC:
		return "ethbtc";
	case EXCHG_PAIR_ZECUSD:
		return "zecusd";
	case EXCHG_PAIR_ZECBTC:
		return "zecbtc";
	case EXCHG_PAIR_ZECETH:
		return "zeceth";
	case EXCHG_PAIR_ZECBCH:
		return "zecbch";
	case EXCHG_PAIR_ZECLTC:
		return "zecltc";
	case EXCHG_PAIR_BCHUSD:
		return "bchusd";
	case EXCHG_PAIR_BCHBTC:
		return "bchbtc";
	case EXCHG_PAIR_BCHETH:
		return "bcheth";
	case EXCHG_PAIR_LTCUSD:
		return "ltcusd";
	case EXCHG_PAIR_LTCBTC:
		return "ltcbtc";
	case EXCHG_PAIR_LTCETH:
		return "ltceth";
	case EXCHG_PAIR_LTCBCH:
		return "ltcbch";
	case EXCHG_PAIR_DAIUSD:
		return "daiusd";
	case EXCHG_PAIR_NEARUSD:
		return "nearusd";
	default:
		return "<invalid pair>";
	}
}

enum exchg_join_type exchg_ccy_join(enum exchg_pair *dst,
				    enum exchg_currency a,
				    enum exchg_currency b) {
	switch (a) {
	case EXCHG_CCY_USD:
		switch (b) {
		case EXCHG_CCY_USD:
			return JOIN_TYPE_ERROR;
		case EXCHG_CCY_BTC:
			*dst = EXCHG_PAIR_BTCUSD;
			return JOIN_TYPE_FIRST_COUNTER;
		case EXCHG_CCY_ETH:
			*dst = EXCHG_PAIR_ETHUSD;
			return JOIN_TYPE_FIRST_COUNTER;
		case EXCHG_CCY_ZEC:
			*dst = EXCHG_PAIR_ZECUSD;
			return JOIN_TYPE_FIRST_COUNTER;
		case EXCHG_CCY_XRP:
			return JOIN_TYPE_ERROR;
		case EXCHG_CCY_LTC:
			*dst = EXCHG_PAIR_LTCUSD;
			return JOIN_TYPE_FIRST_COUNTER;
		case EXCHG_CCY_BCH:
			*dst = EXCHG_PAIR_BCHUSD;
			return JOIN_TYPE_FIRST_COUNTER;
		case EXCHG_CCY_DAI:
			*dst = EXCHG_PAIR_DAIUSD;
			return JOIN_TYPE_FIRST_COUNTER;
		case EXCHG_CCY_NEAR:
			*dst = EXCHG_PAIR_NEARUSD;
			return JOIN_TYPE_FIRST_COUNTER;
		default:
			fprintf(stderr, "%s: bad currency %d\n", __func__, b);
			return JOIN_TYPE_ERROR;
		}
	case EXCHG_CCY_BTC:
		switch (b) {
		case EXCHG_CCY_USD:
			*dst = EXCHG_PAIR_BTCUSD;
			return JOIN_TYPE_FIRST_BASE;
		case EXCHG_CCY_BTC:
			return JOIN_TYPE_ERROR;
		case EXCHG_CCY_ETH:
			*dst = EXCHG_PAIR_ETHBTC;
			return JOIN_TYPE_FIRST_COUNTER;
		case EXCHG_CCY_ZEC:
			*dst = EXCHG_PAIR_ZECBTC;
			return JOIN_TYPE_FIRST_COUNTER;
		case EXCHG_CCY_XRP:
			return JOIN_TYPE_ERROR;
		case EXCHG_CCY_LTC:
			*dst = EXCHG_PAIR_LTCBTC;
			return JOIN_TYPE_FIRST_COUNTER;
		case EXCHG_CCY_BCH:
			*dst = EXCHG_PAIR_BCHBTC;
			return JOIN_TYPE_FIRST_COUNTER;
		case EXCHG_CCY_DAI:
			return JOIN_TYPE_ERROR;
		case EXCHG_CCY_NEAR:
			return JOIN_TYPE_ERROR;
		default:
			fprintf(stderr, "%s: bad currency %d\n", __func__, b);
			return JOIN_TYPE_ERROR;
		}
		break;
	case EXCHG_CCY_ETH:
		switch (b) {
		case EXCHG_CCY_USD:
			*dst = EXCHG_PAIR_ETHUSD;
			return JOIN_TYPE_FIRST_BASE;
		case EXCHG_CCY_BTC:
			*dst = EXCHG_PAIR_ETHBTC;
			return JOIN_TYPE_FIRST_BASE;
		case EXCHG_CCY_ETH:
			return JOIN_TYPE_ERROR;
		case EXCHG_CCY_ZEC:
			*dst = EXCHG_PAIR_ZECETH;
			return JOIN_TYPE_FIRST_COUNTER;
		case EXCHG_CCY_XRP:
			return JOIN_TYPE_ERROR;
		case EXCHG_CCY_LTC:
			*dst = EXCHG_PAIR_LTCETH;
			return JOIN_TYPE_FIRST_COUNTER;
		case EXCHG_CCY_BCH:
			*dst = EXCHG_PAIR_BCHETH;
			return JOIN_TYPE_FIRST_COUNTER;
		case EXCHG_CCY_DAI:
			return JOIN_TYPE_ERROR;
		case EXCHG_CCY_NEAR:
			return JOIN_TYPE_ERROR;
		default:
			fprintf(stderr, "%s: bad currency %d\n", __func__, b);
			return JOIN_TYPE_ERROR;
		}
		break;
	case EXCHG_CCY_ZEC:
		switch (b) {
		case EXCHG_CCY_USD:
			*dst = EXCHG_PAIR_ZECUSD;
			return JOIN_TYPE_FIRST_BASE;
		case EXCHG_CCY_BTC:
			*dst = EXCHG_PAIR_ZECBTC;
			return JOIN_TYPE_FIRST_BASE;
		case EXCHG_CCY_ETH:
			*dst = EXCHG_PAIR_ZECETH;
			return JOIN_TYPE_FIRST_BASE;
		case EXCHG_CCY_ZEC:
			return JOIN_TYPE_ERROR;
		case EXCHG_CCY_XRP:
			return JOIN_TYPE_ERROR;
		case EXCHG_CCY_LTC:
			*dst = EXCHG_PAIR_ZECLTC;
			return JOIN_TYPE_FIRST_BASE;
		case EXCHG_CCY_BCH:
			*dst = EXCHG_PAIR_ZECBCH;
			return JOIN_TYPE_FIRST_BASE;
		case EXCHG_CCY_DAI:
			return JOIN_TYPE_ERROR;
		case EXCHG_CCY_NEAR:
			return JOIN_TYPE_ERROR;
		default:
			fprintf(stderr, "%s: bad currency %d\n", __func__, b);
			return JOIN_TYPE_ERROR;
		}
		break;
	case EXCHG_CCY_XRP:
		return JOIN_TYPE_ERROR;
	case EXCHG_CCY_LTC:
		switch (b) {
		case EXCHG_CCY_USD:
			*dst = EXCHG_PAIR_LTCUSD;
			return JOIN_TYPE_FIRST_BASE;
		case EXCHG_CCY_BTC:
			*dst = EXCHG_PAIR_LTCBTC;
			return JOIN_TYPE_FIRST_BASE;
		case EXCHG_CCY_ETH:
			*dst = EXCHG_PAIR_LTCETH;
			return JOIN_TYPE_FIRST_BASE;
		case EXCHG_CCY_ZEC:
			*dst = EXCHG_PAIR_ZECLTC;
			return JOIN_TYPE_FIRST_COUNTER;
		case EXCHG_CCY_XRP:
		case EXCHG_CCY_LTC:
			return JOIN_TYPE_ERROR;
		case EXCHG_CCY_DAI:
			return JOIN_TYPE_ERROR;
		case EXCHG_CCY_BCH:
			*dst = EXCHG_PAIR_LTCBCH;
			return JOIN_TYPE_FIRST_BASE;
		case EXCHG_CCY_NEAR:
			return JOIN_TYPE_ERROR;
		default:
			fprintf(stderr, "%s: bad currency %d\n", __func__, b);
			return JOIN_TYPE_ERROR;
		}
		break;
	case EXCHG_CCY_BCH:
		switch (b) {
		case EXCHG_CCY_USD:
			*dst = EXCHG_PAIR_BCHUSD;
			return JOIN_TYPE_FIRST_BASE;
		case EXCHG_CCY_BTC:
			*dst = EXCHG_PAIR_BCHBTC;
			return JOIN_TYPE_FIRST_BASE;
		case EXCHG_CCY_ETH:
			*dst = EXCHG_PAIR_BCHETH;
			return JOIN_TYPE_FIRST_BASE;
		case EXCHG_CCY_ZEC:
			*dst = EXCHG_PAIR_ZECBCH;
			return JOIN_TYPE_FIRST_COUNTER;
		case EXCHG_CCY_XRP:
			return JOIN_TYPE_ERROR;
		case EXCHG_CCY_LTC:
			*dst = EXCHG_PAIR_LTCBCH;
			return JOIN_TYPE_FIRST_COUNTER;
		case EXCHG_CCY_BCH:
			return JOIN_TYPE_ERROR;
		case EXCHG_CCY_DAI:
			return JOIN_TYPE_ERROR;
		case EXCHG_CCY_NEAR:
			return JOIN_TYPE_ERROR;
		default:
			fprintf(stderr, "%s: bad currency %d\n", __func__, b);
			return JOIN_TYPE_ERROR;
		}
		break;
	case EXCHG_CCY_DAI:
		switch (b) {
		case EXCHG_CCY_USD:
			*dst = EXCHG_PAIR_DAIUSD;
			return JOIN_TYPE_FIRST_BASE;
		case EXCHG_CCY_BTC:
		case EXCHG_CCY_ETH:
		case EXCHG_CCY_ZEC:
		case EXCHG_CCY_XRP:
		case EXCHG_CCY_LTC:
		case EXCHG_CCY_BCH:
		case EXCHG_CCY_NEAR:
		case EXCHG_CCY_DAI:
			return JOIN_TYPE_ERROR;
		default:
			fprintf(stderr, "%s: bad currency %d\n", __func__, b);
			return JOIN_TYPE_ERROR;
		}
	case EXCHG_CCY_NEAR:
		switch (b) {
		case EXCHG_CCY_USD:
			*dst = EXCHG_PAIR_NEARUSD;
			return JOIN_TYPE_FIRST_BASE;
		case EXCHG_CCY_BTC:
		case EXCHG_CCY_ETH:
		case EXCHG_CCY_ZEC:
		case EXCHG_CCY_XRP:
		case EXCHG_CCY_LTC:
		case EXCHG_CCY_BCH:
		case EXCHG_CCY_NEAR:
		case EXCHG_CCY_DAI:
			return JOIN_TYPE_ERROR;
		default:
			fprintf(stderr, "%s: bad currency %d\n", __func__, b);
			return JOIN_TYPE_ERROR;
		}
	default:
		return JOIN_TYPE_ERROR;
	}
}

int exchg_pair_base(enum exchg_currency *base, enum exchg_pair pair) {
	static const enum exchg_currency bases[] = {
		EXCHG_CCY_BTC,
		EXCHG_CCY_ETH,
		EXCHG_CCY_ETH,
		EXCHG_CCY_ZEC,
		EXCHG_CCY_ZEC,
		EXCHG_CCY_ZEC,
		EXCHG_CCY_ZEC,
		EXCHG_CCY_ZEC,
		EXCHG_CCY_BCH,
		EXCHG_CCY_BCH,
		EXCHG_CCY_BCH,
		EXCHG_CCY_LTC,
		EXCHG_CCY_LTC,
		EXCHG_CCY_LTC,
		EXCHG_CCY_LTC,
		EXCHG_CCY_DAI,
		EXCHG_CCY_NEAR,
	};

	if (pair < 0 || pair >= EXCHG_NUM_PAIRS)
		return -1;
	*base = bases[pair];
	return 0;
}

int exchg_pair_counter(enum exchg_currency *counter, enum exchg_pair pair) {
	static const enum exchg_currency counters[] = {
		EXCHG_CCY_USD,
		EXCHG_CCY_USD,
		EXCHG_CCY_BTC,
		EXCHG_CCY_USD,
		EXCHG_CCY_BTC,
		EXCHG_CCY_ETH,
		EXCHG_CCY_BCH,
		EXCHG_CCY_LTC,
		EXCHG_CCY_USD,
		EXCHG_CCY_BTC,
		EXCHG_CCY_ETH,
		EXCHG_CCY_USD,
		EXCHG_CCY_BTC,
		EXCHG_CCY_ETH,
		EXCHG_CCY_BCH,
		EXCHG_CCY_USD,
		EXCHG_CCY_USD,
	};

	if (pair < 0 || pair >= EXCHG_NUM_PAIRS)
		return -1;
	*counter = counters[pair];
	return 0;
}

int exchg_pair_split(enum exchg_currency *base, enum exchg_currency *counter,
		     enum exchg_pair pair) {
	return exchg_pair_base(base, pair) |
		exchg_pair_counter(counter, pair);
}

static int str_to_currency(enum exchg_currency *currency,
			   const char *str, size_t len) {
	if (!strncmp(str, "usd", len))
		*currency = EXCHG_CCY_USD;
	else if (!strncmp(str, "btc", len))
		*currency = EXCHG_CCY_BTC;
	else if (!strncmp(str, "eth", len))
		*currency = EXCHG_CCY_ETH;
	else if (!strncmp(str, "zec", len))
		*currency = EXCHG_CCY_ZEC;
	else if (!strncmp(str, "xrp", len))
		*currency = EXCHG_CCY_XRP;
	else if (!strncmp(str, "ltc", len))
		*currency = EXCHG_CCY_LTC;
	else if (!strncmp(str, "bch", len))
		*currency = EXCHG_CCY_BCH;
	else if (!strncmp(str, "dai", len))
		*currency = EXCHG_CCY_DAI;
	else if (!strncmp(str, "near", len))
		*currency = EXCHG_CCY_NEAR;
	else
		return EINVAL;
	return 0;
}

static int str_to_pair(enum exchg_pair *pair, const char *str) {
	if (!strcmp(str, "btcusd"))
		*pair = EXCHG_PAIR_BTCUSD;
	else if (!strcmp(str, "ethusd"))
		*pair = EXCHG_PAIR_ETHUSD;
	else if (!strcmp(str, "ethbtc"))
		*pair = EXCHG_PAIR_ETHBTC;
	else if (!strcmp(str, "zecusd"))
		*pair = EXCHG_PAIR_ZECUSD;
	else if (!strcmp(str, "zecbtc"))
		*pair = EXCHG_PAIR_ZECBTC;
	else if (!strcmp(str, "zeceth"))
		*pair = EXCHG_PAIR_ZECETH;
	else if (!strcmp(str, "zecbch"))
		*pair = EXCHG_PAIR_ZECBCH;
	else if (!strcmp(str, "zecltc"))
		*pair = EXCHG_PAIR_ZECLTC;
	else if (!strcmp(str, "bchusd"))
		*pair = EXCHG_PAIR_BCHUSD;
	else if (!strcmp(str, "bchbtc"))
		*pair = EXCHG_PAIR_BCHBTC;
	else if (!strcmp(str, "bcheth"))
		*pair = EXCHG_PAIR_BCHETH;
	else if (!strcmp(str, "ltcusd"))
		*pair = EXCHG_PAIR_LTCUSD;
	else if (!strcmp(str, "ltcbtc"))
		*pair = EXCHG_PAIR_LTCBTC;
	else if (!strcmp(str, "ltceth"))
		*pair = EXCHG_PAIR_LTCETH;
	else if (!strcmp(str, "ltcbch"))
		*pair = EXCHG_PAIR_LTCBCH;
	else if (!strcmp(str, "daiusd"))
		*pair = EXCHG_PAIR_DAIUSD;
	else if (!strcmp(str, "nearusd"))
		*pair = EXCHG_PAIR_NEARUSD;
	else
		return EINVAL;
	return 0;
}

static void str_to_lower(char *dst, size_t len, const char *str) {
	for (int i = 0; i < len; i++)
		dst[i] = tolower(str[i]);
	dst[len] = 0;
}

int exchg_str_to_pair(enum exchg_pair *pair,
		      const char *str) {
	size_t len = strlen(str);
	if (len < 6 || len > 7)
		return -1;

	char lower[8];
	str_to_lower(lower, len, str);
	return str_to_pair(pair, str);
}

int exchg_strn_to_pair(enum exchg_pair *pair,
		       const char *str, int len) {
	if (len < 6 || len > 7)
		return -1;

	char lower[8];
	str_to_lower(lower, len, str);
	return str_to_pair(pair, lower);
}

int exchg_str_to_ccy(enum exchg_currency *dst,
		     const char *str) {
	size_t len = strlen(str);
	if (len < 3 || len > 4)
		return -1;

	char lower[5];
	str_to_lower(lower, len, str);
	return str_to_currency(dst, lower, len);
}

int exchg_strn_to_ccy(enum exchg_currency *dst,
		      const char *str, size_t len) {
	if (len < 3 || len > 4)
		return -1;

	char lower[5];
	str_to_lower(lower, len, str);
	return str_to_currency(dst, lower, len);
}
