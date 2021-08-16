// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#ifndef BITSTAMP_H
#define BITSTAMP_H

#include "exchg/exchg.h"

struct exchg_client *alloc_bitstamp_client(struct exchg_context *ctx);

#endif
