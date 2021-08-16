#include <jsmn/jsmn.h>
#include <string.h>
#include <stdio.h>

#include "json-helpers.h"

static int ret;


struct getint_test {
	const char *json;
	int tok;
	int want;
} getint_tests[] = {
	{"{\"asdf\": 3}", 2, 3},
	{"{\"asdf\": 3}", 1, -1},
	{"{\"asdf\": 345,\"b\":\"c\"}", 1, -1},
	{"{\"asdf\": 345,\"b\":\"c\"}", 2, 345},
	{},
};

void test_getint(void) {
	jsmn_parser parser;
	int numtoks = 100;
	jsmntok_t toks[numtoks];
	for (struct getint_test *t = &getint_tests[0]; t->json; t++) {
		jsmn_init(&parser);
		int res = jsmn_parse(&parser, t->json, strlen(t->json),
				     toks, numtoks);
		if (res < 0) {
			fprintf(stderr, "%s: jsmn_parse: %d\n", __func__, res);
			ret = 1;
			continue;
		}
		if (res < t->tok + 1) {
			fprintf(stderr, "%s: not enough tokens\n", __func__);
			ret = 1;
			continue;
		}
		int got;
		res = json_get_int(&got, t->json, &toks[t->tok]);
		if (t->want < 0) {
			if (!res) {
				fprintf(stderr, "%s: json_get_int(\"%s\", %d) succeeded\n",
					__func__, t->json, t->tok);
				ret = 1;
			}
			continue;
		}
		if (res) {
			fprintf(stderr, "%s: json_get_int(\"%s\", %d) failed\n",
				__func__, t->json, t->tok);
			ret = 1;
			continue;
		}
		if (got != t->want) {
			fprintf(stderr, "%s: json_get_int(\"%s\", %d) = %d\n",
				__func__, t->json, t->tok, got);
			ret = 1;
			continue;
		}
	}
}

struct streq_test {
	const char *json;
	const char *str;
	int tok;
	int wanteq;
} streq_tests[] = {
	{"{\"asdf\": 3}", "asdf", 1, 1},
	{"{\"asdf\": 3}", "asdff", 1, 0},
	{"{\"asdf\": 3}", "asd", 1, 0},
	{"{\"asdf\": 3}", "asdf", 0, 0},
	{},
};

void test_streq(void) {
	jsmn_parser parser;
	int numtoks = 100;
	jsmntok_t toks[numtoks];
	for (struct streq_test *t = &streq_tests[0]; t->json; t++) {
		jsmn_init(&parser);
		int res = jsmn_parse(&parser, t->json, strlen(t->json),
				     toks, numtoks);
		if (res < 0) {
			fprintf(stderr, "%s: jsmn_parse: %d\n", __func__, res);
			ret = 1;
			continue;
		}
		if (res < t->tok + 1) {
			fprintf(stderr, "%s: not enough tokens\n", __func__);
			ret = 1;
			continue;
		}
		if (!!json_streq(t->json, &toks[t->tok], t->str) != !!t->wanteq) {
			fprintf(stderr, "%s: json_streq(\"%s\", \"%s\")\n",
				__func__, t->json, t->str);
			ret = 1;
			return;
		}
	}
}

struct skip_test {
	const char *json;
	int idx;
	int want;
} skip_tests[] = {
	{"{\"asdf\": 3}", 0, 3 },
	{"{\"asdf\": 3}", 1, 2 },
	{"[1,2,[3,4],{\"a\": 3, \"b\":[1,3,\"c\"]}]",1,2},
	{"[1,2,[3,4],{\"a\": 3, \"b\":[1,3,\"c\"]}]",0,14},
	{"[1,2,[3,4],{\"a\": 3, \"b\":[1,3,\"c\"]}]",2,3},
	{"[1,2,[3,4],{\"a\": 3, \"b\":[1,3,\"c\"]}]",3,6},
	{"[1,2,[3,4],{\"a\": 3, \"b\":[1,3,\"c\"]}]",13,14},
	{"[1,2,[3,4],{\"a\": 3, \"b\":[1,3,\"c\"]}]",7,8},
	{"{\"a\": {\"b\": 3}, \"c\": 4}", 2, 5},
	{}
};

void test_skip(void) {
	jsmn_parser parser;
	int numtoks = 100;
	jsmntok_t toks[numtoks];

	for (struct skip_test *t = &skip_tests[0]; t->json; t++) {
		jsmn_init(&parser);

		int res = jsmn_parse(&parser, t->json, strlen(t->json),
				     toks, numtoks);
		if (res < 0) {
			fprintf(stderr, "%s: jsmn_parse: %d\n", __func__, res);
			ret = 1;
			continue;
		}

		/* printf("%d\n", strlen(t->json)); */
		/* for (int i = 0; i < res; i++) { */
		/* 	jsmntok_t *tok = &toks[i]; */
		/* 	printf("%c %d %d, %d\n", t->json[tok->start], tok->start, */
		/* 	       tok->end, tok->size); */
		/* } */
		/* printf("---\n\n"); */
		int next = json_skip(res, toks, t->idx);
		if (next != t->want) {
			fprintf(stderr, "%s: skip(\"%s\", %d) = %d, want %d\n",
				__func__, t->json, t->idx, next, t->want);
			ret = 1;
			continue;
		}
	}
}

int main(void) {
	test_streq();
	test_getint();
	test_skip();
	return ret;
}
