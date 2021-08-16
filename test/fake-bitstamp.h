#ifndef BITSTAMP_TEST_H
#define BITSTAMP_TEST_H

#include "net-backend.h"

struct http_req *bitstamp_http_dial(struct exchg_net_context *ctx,
				  const char *path,
				  const char *method, void *private);

struct websocket *bitstamp_ws_dial(struct exchg_net_context *ctx,
				 const char *path, void *private);

#endif
