// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#ifndef COINBASE_TEST_H
#define COINBASE_TEST_H

#include "net-backend.h"

struct http_conn *coinbase_http_dial(struct exchg_net_context *ctx,
				    const char *path,
				    const char *method, void *private);

struct websocket_conn *coinbase_ws_dial(struct exchg_net_context *ctx,
				   const char *path, void *private);

#endif
