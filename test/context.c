#include "client.h"

struct exchg_net_context *exchg_test_net_ctx(struct exchg_context *ctx)
{
        return ctx->net_context;
}

struct exchg_context *exchg_test_new(struct exchg_callbacks *c,
                                     const struct exchg_options *opts,
                                     void *user)
{
        return exchg_new(c, opts, user);
}
