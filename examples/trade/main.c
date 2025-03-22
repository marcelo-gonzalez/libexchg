// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "examples/common.h"

#include "exchg/currency.h"
#include "exchg/exchg.h"

#include "trader.h"

static void usage(const char *comm)
{
        fprintf(stderr,
                "%s --public-key-file [file] --private-key-file [file] "
                "(--password-file [file]) "
                "[exchange] [buy|sell] [amount] [pair]\n",
                comm);
        exit(1);
}

static int check_intent(const char *exchange, enum exchg_pair pair,
                        enum exchg_side side, const char *amount, bool sandbox)
{
        enum exchg_currency base, price;

        exchg_pair_split(&base, &price, pair);

        if (sandbox)
                printf("<only trading on sandbox exchange>\n");
        else
                printf("WILL TRADE WITH REAL MONEY!!\n");
        printf("please make sure you want to do the following:\n\n");
        char to_do[100];
        if (side == EXCHG_SIDE_BUY)
                snprintf(to_do, sizeof(to_do), "buy %s %s paying in %s on %s",
                         amount, exchg_ccy_to_str(base),
                         exchg_ccy_to_str(price), exchange);
        else
                snprintf(to_do, sizeof(to_do), "sell %s %s to receive %s on %s",
                         amount, exchg_ccy_to_str(base),
                         exchg_ccy_to_str(price), exchange);
        puts(to_do);
        printf("\nto confirm, retype the above:\n");

        char *line;
        size_t size = 0;
        ssize_t len;
        while ((len = getline(&line, &size, stdin)) != -1) {
                // get rid of newline
                if (len > 0)
                        line[len - 1] = '\0';

                if (!strcmp(to_do, line)) {
                        free(line);
                        putchar('\n');
                        return 1;
                }
                printf("Try again. Please type this: \"%s\"\n", to_do);
        }
        free(line);
        return 0;
}

static const int opt_pub_key = 200;
static const int opt_priv_key = 201;
static const int opt_pass = 202;

static struct option long_opts[] = {
    {"public-key-file", required_argument, 0, opt_pub_key},
    {"private-key-file", required_argument, 0, opt_priv_key},
    {"password-file", required_argument, 0, opt_pass},
    {0, 0, 0, 0},
};

int main(int argc, char **argv)
{
        bool sandbox = false;
        int opt;
        struct trade_options opts = {
            .verbose = false,
        };
        const char *pub_key_file = NULL;
        const char *priv_key_file = NULL;
        const char *password_file = NULL;

        while ((opt = getopt_long(argc, argv, "sv", long_opts, NULL)) != -1) {
                switch (opt) {
                case 's':
                        sandbox = true;
                        break;
                case 'v':
                        opts.verbose = true;
                        break;
                case opt_pub_key:
                        pub_key_file = optarg;
                        break;
                case opt_priv_key:
                        priv_key_file = optarg;
                        break;
                case opt_pass:
                        password_file = optarg;
                        break;
                case '?':
                        return 1;
                }
        }

        if (argc - optind != 4 || !pub_key_file || !priv_key_file)
                usage(argv[0]);

        if (!strcmp(argv[optind + 1], "buy"))
                opts.side = EXCHG_SIDE_BUY;
        else if (!strcmp(argv[optind + 1], "sell"))
                opts.side = EXCHG_SIDE_SELL;
        else
                usage(argv[0]);

        if (decimal_from_str(&opts.size, argv[optind + 2])) {
                fprintf(stderr, "bad amount: %s\n", argv[optind + 2]);
                return 1;
        }

        if (exchg_str_to_pair(&opts.pair, argv[optind + 3])) {
                fprintf(stderr, "bad pair: %s\n", argv[optind + 3]);
                return 1;
        }

        struct trade_state state;
        trade_init(&state, &opts);

        struct exchg_client *cl;
        struct exchg_options exchg_opts = {
            .track_book = true,
            .sandbox = sandbox,
        };
        struct exchg_context *ctx =
            exchg_new(&trade_callbacks, &exchg_opts, &state);
        if (!ctx)
                return 1;

        int ret = 1;
        enum exchg_id id;
        if (exchange_from_str(&id, argv[optind]) < 0) {
                fprintf(stderr, "unrecognized exchange: %s\n", argv[optind]);
                goto free_ctx;
        }
        cl = exchg_alloc_client(ctx, id);
        if (!cl)
                goto free_ctx;
        if (set_keys(cl, pub_key_file, priv_key_file))
                goto free_ctx;
        if (id == EXCHG_COINBASE) {
                if (!password_file) {
                        fprintf(
                            stderr,
                            "Must give --password-file to trade on Coinbase\n");
                        goto free_ctx;
                }
                if (set_pass(cl, password_file))
                        goto free_ctx;
        }

        if (!check_intent(argv[optind], state.order.pair, state.order.side,
                          argv[optind + 2], sandbox))
                return 1;

        ret = trade_run(&state, cl);

free_ctx:
        exchg_free(ctx);
        return ret;
}
