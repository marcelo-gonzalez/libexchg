// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#ifndef ORDER_BOOK_H
#define ORDER_BOOK_H

#include <glib.h>
#include <stdint.h>

#include "exchg/decimal.h"
#include "exchg/exchanges.h"
#include "exchg/orders.h"

struct order_book;

struct order_book *order_book_new(int max_depth[EXCHG_ALL_EXCHANGES],
                                  bool sort_by_nominal_price);
void order_book_free(struct order_book *ob);
void order_book_clear(struct order_book *ob, enum exchg_id);
void order_book_add_update(struct order_book *ob,
                           const struct exchg_l2_update *update);
void order_book_update_finish(struct order_book *ob,
                              const struct exchg_l2_update *update);
int order_book_num_bids(struct order_book *ob);
int order_book_num_offers(struct order_book *ob);
void order_book_foreach_bid(struct order_book *ob,
                            int (*f)(const struct exchg_limit_order *o,
                                     void *user),
                            void *user);
void order_book_foreach_offer(struct order_book *ob,
                              int (*f)(const struct exchg_limit_order *o,
                                       void *user),
                              void *user);
bool order_book_best_bid(struct exchg_limit_order *dst, struct order_book *ob,
                         enum exchg_id);
bool order_book_best_ask(struct exchg_limit_order *dst, struct order_book *ob,
                         enum exchg_id);

#endif
