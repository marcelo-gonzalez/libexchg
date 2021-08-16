#ifndef KRAKEN_H
#define KRAKEN_H

#include <stdbool.h>

#include "exchg/exchg.h"

struct exchg_client *alloc_kraken_client(struct exchg_context *ctx);

#endif
