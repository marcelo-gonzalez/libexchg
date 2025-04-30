// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#include <jsmn/jsmn.h>

int json_skip(int num_tokens, jsmntok_t *tokens, int idx)
{
        int left = idx, right = num_tokens;
        int endpos = tokens[idx].end;

        while (left < idx + 3) {
                left++;
                if (left >= num_tokens || tokens[left].start >= endpos)
                        return left;
        }

        while (left < right) {
                int mid = (left + right) / 2;
                jsmntok_t *tok = &tokens[mid];

                if (tok->start < endpos)
                        left = mid + 1;
                else
                        right = mid;
        }
        return left;
}
