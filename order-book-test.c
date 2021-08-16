// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#include <stdio.h>

#include "test/util.h"
#include "order-book.h"

#define ARRAY_SIZE(x) sizeof(x) / sizeof(*x)

struct insert_test {
	int max_depth[EXCHG_ALL_EXCHANGES];
	struct update_data {
		int exchange_id;
		struct order_data {
			int is_bid;
			const char *price;
			const char *size;
		} data[20];
	} data[20];
} insert_tests[] = {
	{
		.max_depth = {3},
		.data = {
			{
				.exchange_id = 0,
				{
					{.is_bid = 1, .price = "12.1", .size = "1"},
					{.is_bid = 1, .price = "13.1", .size = "2"},
					{.is_bid = 1, .price = "14.1", .size = ".2"},
				},
			},
			{
				.exchange_id = 0,
				{
					{.is_bid = 1, .price = "10.1", .size = ".5"},
				},
			},
			{
				.exchange_id = 0,
				{
					{.is_bid = 1, .price = "13.5", .size = ".2"},
					{.is_bid = 1, .price = "15.1", .size = ".5"},
					{.is_bid = 1, .price = "13.5", .size = "9"},
				},
			},
			{
				.exchange_id = 0,
				{
					{.is_bid = 1, .price = "15.1", .size = "0"},
				},
			},
			{
				.exchange_id = 0,
				{
					{.is_bid = 1, .price = "13.5", .size = "0"},
					{.is_bid = 1, .price = "14.1", .size = "0"},
				},
			},
			{
				.exchange_id = 0,
				{
					{.is_bid = 1, .price = "10.1", .size = ".5"},
					{.is_bid = 1, .price = "13.5", .size = ".2"},
					{.is_bid = 1, .price = "15.1", .size = ".5"},
				},
			},
			{
				.exchange_id = 0,
				{
					{.is_bid = 1, .price = "10.1", .size = "0"},
					{.is_bid = 1, .price = "16.1", .size = ".6"},
					{.is_bid = 1, .price = "20.1", .size = "4"},
					{.is_bid = 1, .price = "26.1", .size = ".6"},
					{.is_bid = 1, .price = "30.1", .size = "4"},
					{.is_bid = 1, .price = "46.1", .size = ".6"},
				},
			},
		},
	},
};

static void print_order(const struct exchg_limit_order *o) {
	char px[30], npx[30], sz[30];

	decimal_to_str(px, &o->price);
	decimal_to_str(npx, &o->net_price);
	decimal_to_str(sz, &o->size);
	printf("%d: %s %s %s\n", o->exchange_id, px, npx, sz);
}

int print_orders(const struct exchg_limit_order *o, void *u) {
	print_order(o);
	return 0;
}

static void print_update(struct exchg_l2_update *update) {
	printf("--- update ---\n");
	if (update->num_bids > 0) {
		printf("bids:\n");
		for (int i = 0; i < update->num_bids; i++) {
			print_order(&update->bids[i]);
		}
	}
	if (update->num_asks > 0) {
		printf("asks:\n");
		for (int i = 0; i < update->num_asks; i++) {
			print_order(&update->asks[i]);
		}
	}
	printf("-------\n");

}

void fill_order(struct exchg_limit_order *order, struct order_data *data, int exchange_id) {
	order->exchange_id = exchange_id;
	decimal_from_str(&order->price, data->price);
	decimal_from_str(&order->size, data->size);
	if (data->is_bid) {
		decimal_dec_bps(&order->net_price,
				&order->price, 50, 8);
	} else {
		decimal_inc_bps(&order->net_price,
				&order->price, 50, 8);
	}
}

void fill_update(struct exchg_l2_update *u, struct update_data *data) {
	memset(u, 0, sizeof(*u));
	u->exchange_id = data->exchange_id;
	for (int i = 0; i < sizeof(data->data) / sizeof(*data->data); i++) {
		struct order_data *o = &data->data[i];
		if (!o->price)
			break;
		if (o->is_bid)
			u->num_bids++;
		else
			u->num_asks++;
	}
	if (u->num_bids > 0) {
		u->bids = xzalloc(u->num_bids * sizeof(*u->bids));
	}
	if (u->num_asks > 0) {
		u->asks = xzalloc(u->num_asks * sizeof(*u->asks));
	}
	int b = 0, a = 0;
	for (int i = 0; i < sizeof(data->data) / sizeof(*data->data); i++) {
		struct order_data *o = &data->data[i];
		struct exchg_limit_order *l;
		if (!o->price)
			break;

		if (o->is_bid) {
			l = &u->bids[b];
			b++;
		} else {
			l = &u->bids[a];
			a++;
		}
		fill_order(l, o, data->exchange_id);
	}
}

void test_insert(void) {
	struct exchg_l2_update u;
        // TODO: automate pass/fail
	for (int i = 0; i < ARRAY_SIZE(insert_tests); i++) {
		struct insert_test *t = &insert_tests[i];

		struct order_book *book = order_book_new(t->max_depth, false);
		for (struct update_data *ud = &t->data[0]; ; ud++) {
			fill_update(&u, ud);
			if (!u.num_bids && !u.num_asks)
				break;
			print_update(&u);
			order_book_add_update(book, &u);
			order_book_update_finish(book, &u);
			free(u.bids);
			free(u.asks);
			printf("<><>< tree <><><>\n");
			order_book_foreach_bid(book, print_orders, (void *)1);
			order_book_foreach_offer(book, print_orders, NULL);
			printf("<><><><><><><><><\n");
		}

		printf("CLEAR\n");
		order_book_clear(book, 0);
		fill_update(&u, &t->data[0]);
		print_update(&u);
		order_book_add_update(book, &u);
		order_book_update_finish(book, &u);
		free(u.bids);
		free(u.asks);
		printf("<><>< tree <><><>\n");
		order_book_foreach_bid(book, print_orders, (void *)1);
		order_book_foreach_offer(book, print_orders, NULL);
		printf("<><><><><><><><><\n");
		printf("-----------------------------\n");

		order_book_free(book);
	}
}

int main(void) {
	test_insert();
}
