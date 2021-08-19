// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#ifndef KRAKEN_H
#define KRAKEN_H

#include <stdbool.h>

#include "exchg/exchg.h"

struct exchg_client *alloc_kraken_client(struct exchg_context *ctx);

#endif
