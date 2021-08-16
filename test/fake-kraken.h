#ifndef KRAKEN_TEST_H
#define KRAKEN_TEST_H

#include "net-backend.h"

struct http_req *kraken_http_dial(struct exchg_net_context *ctx,
				  const char *path,
				  const char *method, void *private);

struct websocket *kraken_ws_dial(struct exchg_net_context *ctx,
				 const char *path, void *private);
struct websocket *kraken_ws_auth_dial(struct exchg_net_context *ctx,
				      const char *path, void *private);

#endif
