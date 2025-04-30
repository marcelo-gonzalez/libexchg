// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#ifndef TIME_HELPERS_H
#define TIME_HELPERS_H

#include <stdint.h>
#include <time.h>

static inline int64_t current_seconds(void)
{
        struct timespec now;
        clock_gettime(CLOCK_REALTIME, &now);
        return now.tv_sec;
}

static inline int64_t current_millis(void)
{
        struct timespec now;
        clock_gettime(CLOCK_REALTIME, &now);
        return 1000 * now.tv_sec + now.tv_nsec / 1000000;
}

static inline int64_t current_micros(void)
{
        struct timespec now;
        clock_gettime(CLOCK_REALTIME, &now);
        return 1000000 * now.tv_sec + now.tv_nsec / 1000;
}

#endif
