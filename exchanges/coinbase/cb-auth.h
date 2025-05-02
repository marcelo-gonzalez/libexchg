// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Marcelo Diop-Gonzalez

#ifndef COINBASE_AUTH_H
#define COINBASE_AUTH_H

#include "client.h"

int coinbase_new_keypair(struct exchg_client *cl, const unsigned char *key,
                         size_t len);
int coinbase_new_keypair_from_file(struct exchg_client *cl, const char *path);
int coinbase_http_auth(struct exchg_client *cl, struct http *http);
char *coinbase_ws_jwt(struct exchg_client *cl);

void coinbase_auth_free(struct exchg_client *cl);

#endif
