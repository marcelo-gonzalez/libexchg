// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#include <curses.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <exchg/exchg.h>

#include "examples/common.h"

static int interrupted;

static void sigint_handler(int sig) {
	interrupted = 1;
}

struct book_data {
	int num_levels;
	int cap;
	struct screen_level {
		decimal_t price;
		decimal_t bid_size;
		decimal_t ask_size;
	} *levels;
};

struct terminal_book {
	enum exchg_pair pair;
	bool inited;
	int cols;
	int rows;
	int right_line;
	int left_line;
	int price_width;
	int base_decimals;
	int price_decimals;
	decimal_t price_inc;
	decimal_t low;
	decimal_t hi;
	struct book_data data;
	struct book_data old_data;
};

static void sub_increment(decimal_t *dst, const decimal_t *d, int places, int n) {
	decimal_t x = {
		.places = places,
		.value = n,
	};
	decimal_subtract(dst, d, &x);
}

static void add_increment(decimal_t *dst, const decimal_t *d, int places, int n) {
	decimal_t x = {
		.places = places,
		.value = n,
	};
	decimal_add(dst, d, &x);
}

static int decimal_width(const decimal_t *d, int places) {
	if (decimal_is_zero(d))
		return places+2;

	decimal_t x = *d;
	while (x.places > 0) {
		x.places--;
		x.value /= 10;
	}

	int ret = places + 1;
	if (x.value < 0) {
		ret++;
		x.value *= -1;
	}
	while (x.value > 0) {
		ret++;
		x.value /= 10;
	}
	return ret;
}

static int price_row(struct terminal_book *t, const decimal_t *price) {
	decimal_t diff, n;
	decimal_subtract(&diff, &t->hi, price);
	decimal_divide(&n, &diff, &t->price_inc, 0);
	if (n.value < 0 || n.value >= t->data.num_levels)
		return -1;
	return n.value;
}

static int fill_bids(const struct exchg_limit_order *o, void *p) {
	struct terminal_book *t = p;

	if (decimal_cmp(&o->price, &t->hi) > 0)
		return 0;
	if (decimal_cmp(&o->price, &t->low) < 0)
		return 1;

	int row = price_row(t, &o->price);
	if (row < 0)
		return 0;
	struct screen_level *l = &t->data.levels[row];
	decimal_add(&l->bid_size, &l->bid_size, &o->size);
	return 0;
}

static int fill_asks(const struct exchg_limit_order *o, void *p) {
	struct terminal_book *t = p;

	if (decimal_cmp(&o->price, &t->hi) > 0)
		return 1;
	if (decimal_cmp(&o->price, &t->low) < 0)
		return 0;

	int row = price_row(t, &o->price);
	if (row < 0)
		return 0;
	struct screen_level *l = &t->data.levels[row];
	decimal_add(&l->ask_size, &l->ask_size, &o->size);
	return 0;
}

static void book_write_price(struct terminal_book *t, const decimal_t *price) {
	char price_str[30];
	decimal_t px;
	int row = price_row(t, price);

	if (row < 0)
		return;

	decimal_trim(&px, price, t->price_decimals);
	decimal_to_str(price_str, &px);
	mvaddstr(2*row+1, t->left_line + 1, price_str);
}

static void clear_segment(int row, int from, int to) {
	chtype blank = getbkgd(stdscr);
	for (int i = from; i < to; i++) {
		mvaddch(row, i, blank);
	}
}

static void book_write_bid(struct terminal_book *t, int idx) {
	struct screen_level *l = &t->data.levels[idx];

	clear_segment(2*idx+1, 0, t->left_line);

	if (decimal_is_zero(&l->bid_size)) {
		return;
	}

	char size_str[30];
	decimal_trim(&l->bid_size, &l->bid_size, t->base_decimals);
	int len = decimal_to_str(size_str, &l->bid_size);
	mvaddstr(2*idx+1, t->left_line - len - 1, size_str);
}

static void book_write_ask(struct terminal_book *t, int idx) {
	struct screen_level *l = &t->data.levels[idx];

	clear_segment(2*idx+1, t->right_line+1, t->cols);

	if (decimal_is_zero(&l->ask_size)) {
		return;
	}

	char size_str[30];
	decimal_trim(&l->ask_size, &l->ask_size, t->base_decimals);
	decimal_to_str(size_str, &l->ask_size);
	mvaddstr(2*idx+1, t->right_line + 1, size_str);
}

static void levels_init(struct book_data *b) {
	b->cap = 50;
	b->levels = malloc(b->cap * sizeof(struct screen_level));
	if (!b->levels) {
		fprintf(stderr, "OOM\n");
		exit(1);
	}
	memset(b->levels, 0,
	       sizeof(struct screen_level) * b->cap);
}

static void realloc_levels(struct book_data *b, int levels) {
	b->num_levels = levels;
	if (levels <= b->cap)
		return;
	struct screen_level *l = realloc(b->levels, levels * sizeof(*l));
	if (!l) {
		fprintf(stderr, "%s: OOM\n", __func__);
		exit(1);
	}
	b->levels = l;
	b->cap = levels;
}

static void draw_book(struct terminal_book *t, struct exchg_context *ctx,
		      decimal_t *center) {
	int cols, rows;
	getmaxyx(stdscr, rows, cols);

	realloc_levels(&t->data, rows / 2);

	sub_increment(&t->low, center, t->price_decimals, t->data.num_levels / 2 - 1);
	add_increment(&t->hi, center, t->price_decimals,
		      t->data.num_levels - (t->data.num_levels / 2));

	decimal_trim(&t->hi, &t->hi, t->price_decimals);
	int price_width = decimal_width(&t->hi, t->price_decimals);

	if (cols != t->cols || rows != t->rows ||
	    t->price_width < price_width) {
		clear();
		t->old_data.num_levels = 0;

		t->cols = cols;
		t->rows = rows;
		t->price_width = price_width;
		t->left_line = cols / 2 - (price_width+2) / 2;
		t->right_line = t->left_line + t->price_width + 2;

		mvvline(0, t->left_line, 0, rows);
		mvvline(0, t->right_line, 0, rows);
		for (int i = 0; i < t->data.num_levels; i++) {
			mvhline(2*i, 0, 0, cols);
		}
	}

	if (cols < t->price_width + 21+21+4) {
		refresh();
		return;
	}

	memset(t->data.levels, 0, sizeof(struct screen_level) * t->data.num_levels);
	exchg_foreach_bid(ctx, t->pair, fill_bids, t);
	exchg_foreach_ask(ctx, t->pair, fill_asks, t);

	decimal_t price = t->hi;
	for (int i = 0; i < t->data.num_levels; i++) {
		struct screen_level *level = &t->data.levels[i];
		struct screen_level *old = NULL;
		if (i < t->old_data.num_levels)
			old = &t->old_data.levels[i];

		level->price = price;

		if (!old || decimal_cmp(&old->price, &level->price))
			book_write_price(t, &price);

		if ((!old && !decimal_is_zero(&level->bid_size)) ||
		    (old && decimal_cmp(&old->bid_size, &level->bid_size)))
			book_write_bid(t, i);
		if ((!old && !decimal_is_zero(&level->ask_size)) ||
		    (old && decimal_cmp(&old->ask_size, &level->ask_size)))
			book_write_ask(t, i);

		decimal_subtract(&price, &price, &t->price_inc);
	}

	refresh();
	realloc_levels(&t->old_data, t->data.num_levels);
	memcpy(t->old_data.levels, t->data.levels,
	       t->data.num_levels * sizeof(struct screen_level));
}

static void on_l2_update(struct exchg_client *cl, enum exchg_pair pair,
			 struct exchg_l2_update *update,
			 void *user) {
	struct terminal_book *book = user;
	struct exchg_context *ctx = exchg_ctx(cl);
	struct exchg_limit_order bid;

	if (!book->inited)
		return;

	if (!exchg_best_bid(&bid, ctx, EXCHG_ALL_EXCHANGES, pair))
		return;

	draw_book(book, ctx, &bid.price);
}

static void book_init(struct terminal_book *book, struct exchg_context *ctx) {
	if (book->inited)
		return;

	bool available = false;
	for (enum exchg_id i = 0; i < EXCHG_ALL_EXCHANGES; i++) {
		struct exchg_client *cl = exchg_client(ctx, i);
		if (!cl)
			continue;
		if (!exchg_pair_info_current(cl))
			return;
		const struct exchg_pair_info *info = exchg_pair_info(cl, book->pair);
		if (!info->available)
			continue;

		available = true;
		if (book->base_decimals < info->base_decimals)
			book->base_decimals = info->base_decimals;
		if (book->price_decimals < info->price_decimals)
			book->price_decimals = info->price_decimals;
		book->price_inc.value = 1;
		book->price_inc.places = book->price_decimals;
	}
	book->inited = true;
	if (!available) {
		exchg_log("%s not available on any of the given exchanges\n",
			  exchg_pair_to_str(book->pair));
		exchg_shutdown(ctx);
	} else {
		exchg_log("inited\n");
	}
}

static void on_pair_info(struct exchg_client *cl, void *user) {
	struct terminal_book *book = user;

	book_init(book, exchg_ctx(cl));
}

static struct exchg_callbacks callbacks = {
	.on_l2_update = on_l2_update,
	.on_pair_info = on_pair_info,
};

static void usage(const char *prog) {
	fprintf(stderr, "%s [-E exchange1,exchange2,...] pair\n", prog);
	exit(1);
}

int main(int argc, char **argv) {
	int opt;
	bool want_exchange[EXCHG_ALL_EXCHANGES];

	memset(want_exchange, 0xff, sizeof(want_exchange));

	while ((opt = getopt(argc, argv, "E:")) != -1) {
		switch (opt) {
		case 'E':
			if (option_parse_exchanges(want_exchange, optarg))
				exit(1);
			break;
		case '?':
			usage(argv[0]);
		}
	}

	if (argc - optind != 1)
		usage(argv[0]);

	struct terminal_book book;
	memset(&book, 0, sizeof(book));
	if (exchg_str_to_pair(&book.pair, argv[optind])) {
		fprintf(stderr, "bad pair: %s\n", argv[optind]);
		return 1;
	}
	levels_init(&book.data);
	levels_init(&book.old_data);

	initscr();
	refresh();

	struct sigaction sa = { .sa_handler = sigint_handler };
	if (sigaction(SIGINT, &sa, NULL) == -1) {
		perror("sigaction");
		return 1;
	}

	struct exchg_options opts = {
		.track_book = true,
		.sort_by_nominal_price = true,
	};

	struct exchg_context *ctx = exchg_new(&callbacks, &opts, &book);
	if (!ctx)
		return 1;

	for (enum exchg_id id = 0; id < EXCHG_ALL_EXCHANGES; id++) {
		if (want_exchange[id] && !exchg_alloc_client(ctx, id))
			goto out_shutdown;
	}
	if (exchg_l2_subscribe(ctx, EXCHG_ALL_EXCHANGES, book.pair))
		goto out_shutdown;

	book_init(&book, ctx);

	while (exchg_service(ctx) && !interrupted) { }

out_shutdown:
	exchg_blocking_shutdown(ctx);
	exchg_free(ctx);
	free(book.data.levels);
	free(book.old_data.levels);
	endwin();
}
