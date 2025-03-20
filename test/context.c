#include "exchg/test.h"

#include "client.h"

struct exchg_net_context *exchg_test_net_ctx(struct exchg_context *ctx)
{
        return ctx->net_context;
}

struct exchg_context *exchg_test_new(struct exchg_callbacks *c,
                                     const struct exchg_options *opts,
                                     void *user,
                                     const struct exchg_test_options *test_opts)
{
        return __exchg_new(c, opts, user, (void *)test_opts);
}
