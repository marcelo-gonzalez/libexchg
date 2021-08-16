#ifndef COINBASE_TEST_H
#define COINBASE_TEST_H

#include "net-backend.h"

struct http_req *coinbase_http_dial(struct exchg_net_context *ctx,
				    const char *path,
				    const char *method, void *private);

struct websocket *coinbase_ws_dial(struct exchg_net_context *ctx,
				   const char *path, void *private);

#endif
