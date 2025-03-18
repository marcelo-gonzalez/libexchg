// SPDX-License-Identifier: MIT
// Copyright (C) 2024 Marcelo Diop-Gonzalez

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <exchg/exchg.h>
#include <exchg/test.h>

#include "examples/common.h"

static int interrupted;

static void sigint_handler(int sig) { interrupted = 1; }

static void on_l2_update(struct exchg_client *cl, enum exchg_pair pair,
                         struct exchg_l2_update *update, void *user)
{
        printf("update %d bids %d asks\n", update->num_bids, update->num_asks);
}

static struct exchg_callbacks callbacks = {
    .on_l2_update = on_l2_update,
};

static void usage(const char *prog)
{
        fprintf(stderr, "%s [-E exchange1,exchange2,...] <pair>\n", prog);
        exit(1);
}

int main(int argc, char **argv)
{
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
                        return 1;
                }
        }

        if (argc - optind != 1)
                usage(argv[0]);

        enum exchg_pair pair;
        if (exchg_str_to_pair(&pair, argv[optind])) {
                fprintf(stderr, "bad pair: %s\n", argv[optind]);
        }

        struct sigaction sa = {.sa_handler = sigint_handler};
        if (sigaction(SIGINT, &sa, NULL) == -1) {
                perror("sigaction");
                return 1;
        }

        struct exchg_options opts = {
            .track_book = true,
        };
        struct exchg_context *ctx = exchg_new(&callbacks, &opts, NULL);
        if (!ctx)
                return 1;

        for (enum exchg_id id = 0; id < EXCHG_ALL_EXCHANGES; id++) {
                if (want_exchange[id] && !exchg_alloc_client(ctx, id))
                        goto out_shutdown;
        }

        printf("Printing numbers of %s bids and asks received\n",
               exchg_pair_to_str(pair));

        if (exchg_l2_subscribe(ctx, EXCHG_ALL_EXCHANGES, pair, NULL))
                goto out_shutdown;

        while (exchg_service(ctx) && !interrupted) {
        }

out_shutdown:
        exchg_blocking_shutdown(ctx);
        exchg_free(ctx);
}
