// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include <exchg/exchg.h>

static int read_file(const char *path, unsigned char **out) {
	FILE *file = fopen(path, "r");
	if (!file) {
		fprintf(stderr, "opening %s: %m\n", path);
		return -1;
	}
	int n;
	int pos = 0;
	int size = 100;
	unsigned char *buf = malloc(size);
	if (!buf) {
		fprintf(stderr, "%s: OOM\n", __func__);
		fclose(file);
		return -1;
	}
	while ((n = fread(buf+pos, 1, 100, file)) > 0) {
		pos += n;
		if (pos >= size) {
			size *= 2;
			unsigned char *b = realloc(buf, size);
			if (!b) {
				fprintf(stderr, "%s: OOM\n", __func__);
				free(buf);
				fclose(file);
				return -1;
			}
			buf = b;
		}
	}
	*out = buf;
	fclose(file);
	return pos;
}

int set_keys(struct exchg_client *cl, const char *public_path,
	     const char *private_path) {
	unsigned char *public, *private;
	int public_len = read_file(public_path, &public);
	if (public_len < 0)
		return public_len;
	int private_len = read_file(private_path, &private);
	if (private_len < 0) {
		free(public);
		return private_len;
	}
	exchg_set_keypair(cl, public_len, public, private_len, private);
	free(public);
	free(private);
	return 0;
}

enum exchg_id exchange_from_str(const char *str) {
	if (!strcmp(str, "bitstamp"))
		return EXCHG_BITSTAMP;
	else if (!strcmp(str, "gemini"))
		return EXCHG_GEMINI;
	else if (!strcmp(str, "kraken"))
		return EXCHG_KRAKEN;
	else if (!strcmp(str, "coinbase"))
		return EXCHG_COINBASE;
	else
		return -1;
}

int option_parse_exchanges(bool want_exchange[EXCHG_ALL_EXCHANGES], char *arg) {
	char *str;
	int i;

	memset(want_exchange, 0, sizeof(bool) * EXCHG_ALL_EXCHANGES);
	for (i = 0, str = arg; ; str = NULL, i++) {
		char *exchange = strtok(str, ",");
		if (!exchange)
			break;
		enum exchg_id id = exchange_from_str(exchange);
		if (id < 0) {
			fprintf(stderr, "unrecognized exchange: %s\n", exchange);
			return -1;
		} else {
			want_exchange[id] = true;
		}
	}
	for (enum exchg_id id = 0; id < EXCHG_ALL_EXCHANGES; id++)
		if (want_exchange[id])
			return 0;
	fprintf(stderr, "No valid exchanges given: %s\n", arg);
	return -1;
}
