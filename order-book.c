// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#include <glib.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>

#include "exchg/decimal.h"
#include "exchg/exchanges.h"
#include "order-book.h"

struct order_book {
        GTree *bids;
        GTree *asks;
        int (*bids_cmp)(const void *a, const void *b, void *p);
        int (*asks_cmp)(const void *a, const void *b, void *p);
        struct per_exchg_book {
                int max_depth;
                bool check_update_time;
                GTree *bids;
                GTree *asks;
                GTreeNode *last_bid;
                GTreeNode *last_ask;
                int last_bid_rank;
                int last_ask_rank;
        } per_exchg[EXCHG_ALL_EXCHANGES];
};

static int int_compare(int a, int b)
{
        if (a < b)
                return -1;
        if (a > b)
                return 1;
        return 0;
}

static int bids_compare(const void *a, const void *b, void *p)
{
        const struct exchg_limit_order *o_a = a;
        const struct exchg_limit_order *o_b = b;

        int c = decimal_cmp(&o_a->price, &o_b->price);
        if (c)
                return -c;
        return int_compare(o_a->exchange_id, o_b->exchange_id);
}

static int bids_compare_net(const void *a, const void *b, void *p)
{
        const struct exchg_limit_order *o_a = a;
        const struct exchg_limit_order *o_b = b;

        int c = decimal_cmp(&o_a->net_price, &o_b->net_price);
        if (c)
                return -c;
        return bids_compare(a, b, p);
}

static int asks_compare(const void *a, const void *b, void *p)
{
        const struct exchg_limit_order *o_a = a;
        const struct exchg_limit_order *o_b = b;

        int c = decimal_cmp(&o_a->price, &o_b->price);
        if (c)
                return c;
        return int_compare(o_a->exchange_id, o_b->exchange_id);
}

static int asks_compare_net(const void *a, const void *b, void *p)
{
        const struct exchg_limit_order *o_a = a;
        const struct exchg_limit_order *o_b = b;

        int c = decimal_cmp(&o_a->net_price, &o_b->net_price);
        if (c)
                return c;
        return asks_compare(a, b, p);
}

static void orders_clear(GTree *tree, enum exchg_id id)
{
        GTreeNode *node = g_tree_node_first(tree);
        while (node) {
                struct exchg_limit_order *o = g_tree_node_key(node);
                GTreeNode *next = g_tree_node_next(node);

                if (o->exchange_id == id)
                        g_tree_remove(tree, o);
                node = next;
        }
}

void order_book_clear(struct order_book *ob, enum exchg_id id)
{
        orders_clear(ob->bids, id);
        orders_clear(ob->asks, id);

        struct per_exchg_book *b = &ob->per_exchg[id];

        g_tree_unref(b->bids);
        g_tree_unref(b->asks);
        b->bids = g_tree_new_full(ob->bids_cmp, NULL, NULL, NULL);
        b->asks = g_tree_new_full(ob->asks_cmp, NULL, NULL, NULL);
        b->last_bid = NULL;
        b->last_ask = NULL;
        b->last_bid_rank = 0;
        b->last_ask_rank = 0;
}

static void per_exchg_remove(struct order_book *ob,
                             const struct exchg_limit_order *order, bool is_bid)
{
        struct per_exchg_book *b = &ob->per_exchg[order->exchange_id];

        GTree *tree;
        GTreeNode **last;
        int *rank;
        int (*cmp)(const void *a, const void *b, void *p);

        if (is_bid) {
                cmp = ob->bids_cmp;
                tree = b->bids;
                last = &b->last_bid;
                rank = &b->last_bid_rank;
        } else {
                cmp = ob->asks_cmp;
                tree = b->asks;
                last = &b->last_ask;
                rank = &b->last_ask_rank;
        }

        if (b->max_depth < 1 || !*last) {
                g_tree_remove(tree, order);
                return;
        }

        int c = cmp(g_tree_node_key(*last), order, NULL);

        if (c > 0)
                (*rank)--;

        if (c != 0) {
                g_tree_remove(tree, order);
                return;
        }

        GTreeNode *prev = g_tree_node_previous(*last);
        if (prev) {
                (*rank)--;
                *last = prev;
        } else {
                *last = g_tree_node_next(*last);
        }
        g_tree_remove(tree, order);
}

static void per_exchg_insert(struct order_book *ob,
                             struct exchg_limit_order *order, bool is_bid)
{
        GTree *tree;
        GTreeNode *last;
        int *rank;
        int (*cmp)(const void *a, const void *b, void *p);
        struct per_exchg_book *b = &ob->per_exchg[order->exchange_id];

        if (is_bid) {
                cmp = ob->bids_cmp;
                tree = b->bids;
                last = b->last_bid;
                rank = &b->last_bid_rank;
        } else {
                cmp = ob->asks_cmp;
                tree = b->asks;
                last = b->last_ask;
                rank = &b->last_ask_rank;
        }

        g_tree_insert(tree, order, NULL);

        if (b->max_depth < 1)
                return;

        if (!last)
                return;

        if (cmp(g_tree_node_key(last), order, NULL) > 0)
                (*rank)++;
}

static void insert_order(struct order_book *ob,
                         const struct exchg_limit_order *order, bool is_bid)
{
        GTree *tree;

        if (is_bid) {
                tree = ob->bids;
        } else {
                tree = ob->asks;
        }

        struct exchg_limit_order *o;
        bool found = g_tree_lookup_extended(tree, order, (void **)&o, NULL);
        bool check_update_time =
            ob->per_exchg[order->exchange_id].check_update_time;

        // prob not gonna happen, but for some reason sometimes kraken sends
        // multiple updates of the same level in the same message. seems like
        // they're always in ascending time order but just check it to be safe
        if (check_update_time && found &&
            o->update_micros > order->update_micros) {
                return;
        }

        if (decimal_is_zero(&order->size)) {
                per_exchg_remove(ob, order, is_bid);
                g_tree_remove(tree, order);
        } else {
                if (found) {
                        o->size = order->size;
                } else {
                        o = malloc(sizeof(*o));
                        if (!o) {
                                fprintf(stderr, "%s: OOM\n", __func__);
                                return;
                        }
                        memcpy(o, order, sizeof(*o));
                        g_tree_insert(tree, o, NULL);
                        per_exchg_insert(ob, o, is_bid);
                }
        }
}

void order_book_add_update(struct order_book *ob,
                           const struct exchg_l2_update *update)
{
        for (int i = 0; i < update->num_bids; i++) {
                insert_order(ob, &update->bids[i], true);
        }
        for (int i = 0; i < update->num_asks; i++) {
                insert_order(ob, &update->asks[i], false);
        }
}

static void per_exchg_side_update(GTree *full_tree, GTree *exchg_tree,
                                  GTreeNode **last, int *rank, int max_depth)
{
        int n = g_tree_nnodes(exchg_tree);

        if (n < 1) {
                *rank = 0;
                *last = NULL;
                return;
        }
        if (!*last) {
                *last = g_tree_node_last(exchg_tree);
                *rank = n;
        }

        while (*rank < max_depth && *rank < n) {
                (*rank)++;
                *last = g_tree_node_next(*last);
        }

        GTreeNode *node = *last;

        for (int r = *rank + 1; r <= n; r++) {
                GTreeNode *n = g_tree_node_next(node);
                void *k = g_tree_node_key(n);

                g_tree_remove(exchg_tree, k);
                g_tree_remove(full_tree, k);

                node = n;
        }

        for (; *rank > max_depth; (*rank)--) {
                GTreeNode *prev = g_tree_node_previous(*last);
                void *k = g_tree_node_key(*last);

                g_tree_remove(exchg_tree, k);
                g_tree_remove(full_tree, k);

                *last = prev;
        }
}

void order_book_update_finish(struct order_book *ob,
                              const struct exchg_l2_update *update)
{
        struct per_exchg_book *b = &ob->per_exchg[update->exchange_id];

        if (b->max_depth < 1)
                return;

        if (update->num_bids > 0)
                per_exchg_side_update(ob->bids, b->bids, &b->last_bid,
                                      &b->last_bid_rank, b->max_depth);
        if (update->num_asks > 0)
                per_exchg_side_update(ob->asks, b->asks, &b->last_ask,
                                      &b->last_ask_rank, b->max_depth);
}

struct apply_func_arg {
        int (*f)(const struct exchg_limit_order *o, void *user);
        void *user;
};

static int apply_func(void *key, void *val, void *p)
{
        const struct exchg_limit_order *o = key;
        struct apply_func_arg *arg = p;

        return arg->f(o, arg->user);
}

void order_book_foreach_bid(struct order_book *ob,
                            int (*f)(const struct exchg_limit_order *o,
                                     void *user),
                            void *user)
{
        struct apply_func_arg arg = {
            .f = f,
            .user = user,
        };
        g_tree_foreach(ob->bids, apply_func, &arg);
}

void order_book_foreach_offer(struct order_book *ob,
                              int (*f)(const struct exchg_limit_order *o,
                                       void *user),
                              void *user)
{
        struct apply_func_arg arg = {
            .f = f,
            .user = user,
        };
        g_tree_foreach(ob->asks, apply_func, &arg);
}

static bool best_order(struct exchg_limit_order *dst, GTree *tree)
{
        GTreeNode *n = g_tree_node_first(tree);
        if (n) {
                *dst = *(struct exchg_limit_order *)g_tree_node_key(n);
                return true;
        } else {
                return false;
        }
}

bool order_book_best_bid(struct exchg_limit_order *dst, struct order_book *ob,
                         enum exchg_id id)
{
        if (id == EXCHG_ALL_EXCHANGES)
                return best_order(dst, ob->bids);
        if (0 <= id && id < EXCHG_ALL_EXCHANGES)
                return best_order(dst, ob->per_exchg[id].bids);
        return false;
}

bool order_book_best_ask(struct exchg_limit_order *dst, struct order_book *ob,
                         enum exchg_id id)
{
        if (id == EXCHG_ALL_EXCHANGES)
                return best_order(dst, ob->asks);
        if (0 <= id && id < EXCHG_ALL_EXCHANGES)
                return best_order(dst, ob->per_exchg[id].asks);
        return false;
}

int order_book_num_bids(struct order_book *ob)
{
        return g_tree_nnodes(ob->bids);
}

int order_book_num_offers(struct order_book *ob)
{
        return g_tree_nnodes(ob->asks);
}

struct order_book *
order_book_new(struct order_book_config configs[EXCHG_ALL_EXCHANGES],
               bool sort_by_nominal_price)
{
        struct order_book *ob = malloc(sizeof(*ob));
        if (!ob) {
                fprintf(stderr, "%s: OOM\n", __func__);
                return NULL;
        }
        memset(ob, 0, sizeof(*ob));
        if (sort_by_nominal_price) {
                ob->bids_cmp = bids_compare;
                ob->asks_cmp = asks_compare;
        } else {
                ob->bids_cmp = bids_compare_net;
                ob->asks_cmp = asks_compare_net;
        }
        ob->bids = g_tree_new_full(ob->bids_cmp, NULL, free, NULL);
        ob->asks = g_tree_new_full(ob->asks_cmp, NULL, free, NULL);
        for (int i = 0; i < EXCHG_ALL_EXCHANGES; i++) {
                struct order_book_config *config = &configs[i];
                ob->per_exchg[i].max_depth = config->max_depth;
                ob->per_exchg[i].check_update_time = config->check_update_time;
                ob->per_exchg[i].bids =
                    g_tree_new_full(ob->bids_cmp, NULL, NULL, NULL);
                ob->per_exchg[i].asks =
                    g_tree_new_full(ob->asks_cmp, NULL, NULL, NULL);
        }
        return ob;
}

void order_book_free(struct order_book *ob)
{
        if (!ob)
                return;

        g_tree_unref(ob->bids);
        g_tree_unref(ob->asks);
        for (int i = 0; i < EXCHG_ALL_EXCHANGES; i++) {
                g_tree_unref(ob->per_exchg[i].bids);
                g_tree_unref(ob->per_exchg[i].asks);
        }
        free(ob);
}
