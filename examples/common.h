// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#ifndef EXAMPLES_COMMON_H
#define EXAMPLES_COMMON_H

#include <stdbool.h>

#include "exchg/exchg.h"

int set_keys(struct exchg_client *cl, const char *public_path,
	     const char *private_path);
int set_pass(struct exchg_client *cl, const char *path);

int option_parse_exchanges(bool want_exchange[EXCHG_ALL_EXCHANGES], char *arg);
int exchange_from_str(enum exchg_id *ret, const char *str);

#endif
