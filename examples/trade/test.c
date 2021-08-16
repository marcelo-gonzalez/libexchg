#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <exchg/exchg.h>
#include <exchg/test.h>

#include "trader.h"

static struct fake_book_update_str events[] = {
	{.pair = EXCHG_PAIR_BTCUSD,
	 .bids = {{"30000", "1"}, {"29500", ".1"}, {"29400", ".2"}, {"29100", "2"}},
	 .asks = {{"31000", "3.3"}}},
	{.pair = EXCHG_PAIR_BTCUSD,
	 .bids = {{"29000", "1.2"}}},
	{.pair = EXCHG_PAIR_BTCUSD,
	 .bids = {{"28000", "10"}},
	 .asks = {{"31000", "3.4"}}},
};

static void event_cb(struct exchg_net_context *net_ctx,
		     struct exchg_test_event *ev, void *p) {
	if (ev)
		exchg_test_event_print(ev);
}

int main(void) {
	int ret = 0;
	for (enum exchg_id id = 0; id < EXCHG_ALL_EXCHANGES; id++) {
		for (enum exchg_side side = 0; side < 2; side++) {
			for (int i = 0; i < sizeof(events) / sizeof(*events); i++) {
				events[i].id = id;
			}
			struct trade_options opts = {
				.verbose = false,
				.side = side,
				.pair = EXCHG_PAIR_BTCUSD,
			};

			decimal_from_str(&opts.size, "1.2");

			printf("----------------------------\n");
			struct trade_state state;
			trade_init(&state, &opts);

			struct exchg_options exchg_opts = {
				.track_book = true,
			};

			struct exchg_context *ctx = exchg_test_new(&trade_callbacks,
								   &exchg_opts, &state);
			struct exchg_net_context *net_ctx = exchg_test_net_ctx(ctx);
			exchg_test_set_callback(net_ctx, event_cb, NULL);

			struct exchg_client *cl = exchg_alloc_client(ctx, id);
			if (!cl)
				goto free_ctx;
			switch (id) {
			case EXCHG_GEMINI:
				exchg_set_keypair(cl, strlen(exchg_test_gemini_public),
						  (unsigned char *)exchg_test_gemini_public,
						  strlen(exchg_test_gemini_private),
						  (unsigned char *)exchg_test_gemini_private);
				break;
			case EXCHG_KRAKEN:
				exchg_set_keypair(cl, strlen(exchg_test_kraken_public),
						  (unsigned char *)exchg_test_kraken_public,
						  strlen(exchg_test_kraken_private),
						  (unsigned char *)exchg_test_kraken_private);
				if (exchg_kraken_private_ws_connect(cl))
					goto free_ctx;
				break;
			case EXCHG_BITSTAMP:
				exchg_set_keypair(cl, strlen(exchg_test_bitstamp_public),
						  (unsigned char *)exchg_test_bitstamp_public,
						  strlen(exchg_test_bitstamp_private),
						  (unsigned char *)exchg_test_bitstamp_private);
				break;
			case EXCHG_COINBASE:
				exchg_set_keypair(cl, strlen(exchg_test_coinbase_public),
						  (unsigned char *)exchg_test_coinbase_public,
						  strlen(exchg_test_coinbase_private),
						  (unsigned char *)exchg_test_coinbase_private);
				break;
			default:
				fprintf(stderr, "wtf\n");
				return 1;
			}

			exchg_test_add_book_events(net_ctx, 3, events);

			decimal_t *balances = exchg_test_balances(net_ctx, cl->id);
			decimal_from_str(&balances[EXCHG_CCY_USD], "40000");

			ret |= trade_run(&state, cl);

		free_ctx:
			exchg_free(ctx);
		}
	}
	return ret;
}
