// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#ifndef COINBASE_H
#define COINBASE_H

#include "exchg/exchg.h"

struct exchg_client *alloc_coinbase_client(struct exchg_context *ctx);

#endif
