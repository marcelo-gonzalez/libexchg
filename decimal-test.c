// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#include <inttypes.h>
#include <string.h>
#include <stdio.h>

#include "exchg/decimal.h"

#define ARRAY_SIZE(x) sizeof(x) / sizeof(*x)

static int ret;

const static struct {
	char *a;
	char *b;
	char *want_add;
	char *want_sub;
	char *want_mul;
} arithmetic_tests[] = {
	{ "123", "34", "157", "89", "4182" },
	{ "3", "0.4", "3.4", "2.6", "1.2" },
	{ "-35", "0.4", "-34.6", "-35.4", "-14" },
	{ "3", "4", "7", "-1", "12" },
	{ "3.12", ".0013", "3.1213", "3.1187", "0.004056" },
	{ "3.00", "4.00", "7.00", "-1.00", "12" },
	{ "3.00", "4.10", "7.10", "-1.10", "12.3" },
	{"50000000000.00000", "1.0026", "50000000001.00260",
	 "49999999998.99740", "50130000000.0000"},
};

void test_arithmetic(void) {
	for (int i = 0; i < ARRAY_SIZE(arithmetic_tests); i++) {
		decimal_t x, y;
		decimal_t add, sub, mul;
		decimal_from_str(&x, arithmetic_tests[i].a);
		decimal_from_str(&y, arithmetic_tests[i].b);

		decimal_add(&add, &x, &y);
		decimal_subtract(&sub, &x, &y);
		decimal_multiply(&mul, &x, &y);
		char a[30];
		char s[30];
		char m[30];
		decimal_to_str(a, &add);
		decimal_to_str(s, &sub);
		decimal_to_str(m, &mul);
		if (strcmp(a, arithmetic_tests[i].want_add)) {
			fprintf(stderr, "%s + %s = %s, want %s\n",
				arithmetic_tests[i].a,
				arithmetic_tests[i].b,
				a, arithmetic_tests[i].want_add);
			ret = 1;
		}
		if (strcmp(s, arithmetic_tests[i].want_sub)) {
			fprintf(stderr, "%s - %s = %s, want %s\n",
				arithmetic_tests[i].a,
				arithmetic_tests[i].b,
				s, arithmetic_tests[i].want_sub);
			ret = 1;
		}
		if (strcmp(m, arithmetic_tests[i].want_mul)) {
			fprintf(stderr, "%s * %s = %s, want %s\n",
				arithmetic_tests[i].a,
				arithmetic_tests[i].b,
				m, arithmetic_tests[i].want_mul);
			ret = 1;
		}
	}
}

const static struct {
	decimal_t number;
	const char *want;
} to_str_tests[] = {
	{ { 0, 1234 }, "1234" },
	{ { 1, 123 }, "12.3" },
	{ { 1, -123 }, "-12.3" },
	{ { 3, -56133 }, "-56.133" },
	{ { 6, 123456789000 }, "123456.789000" },
	{ { 8, 1 }, "0.00000001" },
	{ { 4, 123 }, "0.0123" },
	{ { 4, 1234 }, "0.1234" },
	{ { 4, -4 }, "-0.0004" },
};

void test_to_str(void) {
	for (int i = 0; i < ARRAY_SIZE(to_str_tests); i++) {
		char str[30];
		int n = decimal_to_str(str, &to_str_tests[i].number);
		if (strcmp(str, to_str_tests[i].want)) {
			fprintf(stderr, "to_str(%d, %" PRId64 ") gave %s, want %s\n",
				to_str_tests[i].number.places,
				to_str_tests[i].number.value, str,
				to_str_tests[i].want);
			ret = 1;
		}
		if (n != strlen(to_str_tests[i].want)) {
			fprintf(stderr, "to_str(%d, %" PRId64 ") = %d, want %lu = strlen(\"%s\")\n",
				to_str_tests[i].number.places,
				to_str_tests[i].number.value, n,
				strlen(to_str_tests[i].want),
				to_str_tests[i].want);
			ret = 1;
		}
	}
}

static struct {
	decimal_t a;
	decimal_t b;
	int want_cmp;
} cmp_tests[] = {
	{ { 0 , 123 }, { 0 , 123}, 0 },
	{ { 1 , 123 }, { 0 , 123}, -1 },
	{ { 0 , 123 }, { 1 , 123}, 1 },
	{ { 0 , 1234 }, { 0 , 123}, 1 },
	{ { 0 , 123 }, { 0 , 1234}, -1 },
	{ { 1 , 1230 }, { 0 , 123}, 0 },
	{ { 3 , 123000 }, { 0 , 123}, 0 },
	{ { 3 , 123456 }, { 2 , 12346}, -1 },
	{ { 0 , 123 }, { 1 , 12}, 1 },
	{ { 0 , -123 }, { 0 , 123}, -1 },
	{ { 5 , -123 }, { 0 , 123}, -1 },
	{ { 0 , -123 }, { 5 , 123}, -1 },
};

void test_decimal_cmp(void) {
	for (int i = 0; i < ARRAY_SIZE(cmp_tests); i++) {
		decimal_t *a = &cmp_tests[i].a;
		decimal_t *b = &cmp_tests[i].b;
		int cmp = decimal_cmp(a, b);
		if (cmp != cmp_tests[i].want_cmp) {
			fprintf(stderr, "decimal_cmp({%d, %" PRId64 "}, {%d, %" PRId64 "}) "
				"wanted %d, got %d\n", a->places, a->value,
				b->places, b->value, cmp_tests[i].want_cmp, cmp);
			ret = 1;
		}
	}
}

static struct to_fractional_test {
	const char *value;
	int64_t want_0_places;
	int64_t want_3_places;
	int64_t want_6_places;
} to_fractional_tests[] = {
	{ "123", 123, 123000, 123000000 },
	{ "123.1", 123, 123100, 123100000 },
	{ "123.456", 123, 123456, 123456000 },
	{ "123.4567", 123, 123456, 123456700 },
	{ "123.456789", 123, 123456, 123456789 },
	{ "123.4567898", 123, 123456, 123456789 },
};

void test_decimal_to_fractional(void) {
	for (int i = 0; i < ARRAY_SIZE(to_fractional_tests); i++) {
		struct to_fractional_test *test = &to_fractional_tests[i];
		decimal_t d;
		int err = decimal_from_str(&d, test->value);
		if (err) {
			ret = 1;
			return;
		}
		int64_t got_0 = decimal_to_fractional(&d, 0);
		int64_t got_3 = decimal_to_fractional(&d, 3);
		int64_t got_6 = decimal_to_fractional(&d, 6);
		if (got_0 != test->want_0_places ||
		    got_3 != test->want_3_places ||
		    got_6 != test->want_6_places) {
			fprintf(stderr, "error: decimal_to_fractional(%s): 0 -> %ld, "
				"3 -> %ld, 6 -> %ld\n", test->value, got_0,
				got_3, got_6);
			ret = 1;
		}
	}
}

static struct bps_test {
	const char *value;
	int places;
	int bps;
	const char *want_up;
	const char *want_down;
} bps_tests[] = {
	{"123", 0, 5000, "185", "61"},
	{"124", 0, 5000, "186", "62"},
	{"123.4567", 4, 500, "129.6296", "117.2838"},
	{"123.4567893", 8, 1500, "141.97530770", "104.93827090"},
	{"123.4567893", 4, 1500, "141.9754", "104.9382"},
	{"123.4567893", 8, 35, "123.88888807", "123.02469053"},
	{"123.4567893", 4, 35, "123.8889", "123.0246"},
	{"123.4567893", -1, 35, "123.88888806255", "123.02469053745"},
	{"922337203.68547758", 8, 35, "925565383.89836915", "919109023.47257783"},
	{"50000000000.00000", 8, 26, "50130000000", "49870000000"},
};

void test_bps(void) {
	for (int i = 0; i < ARRAY_SIZE(bps_tests); i++) {
		struct bps_test *t = &bps_tests[i];
		decimal_t d, up, down, want_up, want_down;

		decimal_from_str(&d, t->value);
		decimal_from_str(&want_up, t->want_up);
		decimal_from_str(&want_down, t->want_down);

		decimal_inc_bps(&up, &d, t->bps, t->places);
		decimal_dec_bps(&down, &d, t->bps, t->places);

		if (decimal_cmp(&up, &want_up)) {
			char s[30];
			decimal_to_str(s, &up);
			fprintf(stderr, "decimal_inc_bps(%s, %d, %d) = %s, want %s\n",
				t->value, t->bps, t->places, s, t->want_up);
			ret = 1;
		}
		if (decimal_cmp(&down, &want_down)) {
			char s[30];
			decimal_to_str(s, &down);
			fprintf(stderr, "decimal_dec_bps(%s, %d, %d) = %s, want %s\n",
				t->value, t->bps, t->places, s, t->want_down);
			ret = 1;
		}
	}
}

static struct {
	const char *input;
	size_t len;
	int want_err;
	decimal_t expected;
} from_str_tests[] = {
	{ "123", strlen("123"), 0, { 0, 123 } },
	{ "123", 1, 0, { 0, 1 } },
	{ "123.4", strlen("123.4"), 0, { 1, 1234 } },
	{ "123.4, 13", strlen("123.4"), 0, { 1, 1234 } },
	{ "123.4567", strlen("123.4567"), 0, { 4, 1234567 } },
	{ "-12345.67", strlen("-12345.67"), 0, { 2, -1234567 } },
	{ "-0.67", strlen("-0.67"), 0, { 2, -67 } },
	{ "-12345.s67", strlen("-12345.s67"), 1 },
	{ "-12345..67", strlen("-12345..67"), 1 },
	{ "12345.67.3", strlen("12345.67.3"), 1 },
	{ "12345.67.3", strlen("12345.67.3")-2, 0, {2, 1234567} },
};

void test_decimal_from_str_n(void) {
	for (int i = 0; i < ARRAY_SIZE(from_str_tests); i++) {
		decimal_t d;
		int err = decimal_from_str_n(&d, from_str_tests[i].input,
					     from_str_tests[i].len);
		if (!!err != !!from_str_tests[i].want_err) {
			fprintf(stderr, "%s: test %d, got err %d, want err %d\n",
				__func__, i, !!err, !!from_str_tests[i].want_err);
			ret = 1;
		}
		if (err)
			continue;

		int cmp = decimal_cmp(&d, &from_str_tests[i].expected);
		if (cmp != 0) {
			fprintf(stderr,"decimal_from_str_n(\"%s\", %zu) comparison with"
				" expected not zero. Got { %d, %" PRId64 " }. Comparison %d\n",
				from_str_tests[i].input, from_str_tests[i].len,
				d.places, d.value, cmp);
			ret = 1;
		}
	}
}

static struct div_test {
	const char *a;
	const char *b;
	int places;
	const char *want;
} div_tests[] = {
	{"12", "5", 0, "2"},
	{"12", "5", 1, "2.4"},
	{"1234.12", "20000.36", 8, ".06170488"},
	{"1234.12", "20000.36", 4, ".0617"},
	{"92233720368547758.07", "17", 4, "5425512962855750.47"},
	{"101.3764213046", "101.30000", 8, "1.00075440"},
	{"0.1994813484", "99.80000", 8, "0.00199881"}
};

void test_div(void) {
	for (int i = 0; i < ARRAY_SIZE(div_tests); i++) {
		struct div_test *t = &div_tests[i];
		decimal_t a, b, want, got;
		decimal_from_str(&a, t->a);
		decimal_from_str(&b, t->b);
		decimal_from_str(&want, t->want);

		decimal_divide(&got, &a, &b, t->places);
		if (decimal_cmp(&got, &want)) {
			char s[30];
			decimal_to_str(s, &got);
			fprintf(stderr, "decimal_divide(%s, %s, %d) = %s, want %s.\n",
				t->a, t->b, t->places, s, t->want);
			ret = 1;
		}
	}
}

static struct trunc_test {
	const char *x;
	int places;
	const char *want;
} trunc_tests[] = {
	{"12", 0, "12"},
	{"12", 2, "12"},
	{"1234.12", 8, "1234.12"},
	{"1234.12", 1, "1234.1"},
	{"1234.12", 0, "1234"},
	{"922337203685.4775807", 3, "922337203685.477"},
};

void test_trunc(void) {
	for (int i = 0; i < ARRAY_SIZE(trunc_tests); i++) {
		struct trunc_test *t = &trunc_tests[i];
		decimal_t x, got, want;

		decimal_from_str(&x, t->x);
		decimal_from_str(&want, t->want);

		decimal_trunc(&got, &x, t->places);
		if (decimal_cmp(&got, &want)) {
			char s[30];
			decimal_to_str(s, &got);
			fprintf(stderr, "trunc(%s, %d) = %s, want %s\n",
				t->x, t->places, s, t->want);
			ret = 1;
		}
	}
}

static struct trunc_test trim_tests[] = {
	{"12.0", 1, "12.0"},
	{"12.0", 0, "12"},
	{"12.5600", 2, "12.56"},
	{"12.5610", 2, "12.561"},
	{"12.5000", 2, "12.50"},
	{"12.50001", 2, "12.50001"},
	{".5000", 2, "0.50"},
};

void test_trim(void) {
	for (int i = 0; i < ARRAY_SIZE(trim_tests); i++) {
		struct trunc_test *t = &trim_tests[i];
		decimal_t x, trim, want;
		char got[30];

		decimal_from_str(&x, t->x);
		decimal_from_str(&want, t->want);

		decimal_trim(&trim, &x, t->places);
		decimal_to_str(got, &trim);
		if (strcmp(got, t->want)) {
			fprintf(stderr, "trim(%s, %d) = %s, want %s\n",
				t->x, t->places, got, t->want);
			ret = 1;
		}
	}
}

int main(void) {
	test_decimal_from_str_n();
	test_decimal_cmp();
	test_to_str();
	test_arithmetic();
	test_decimal_to_fractional();
	test_bps();
	test_div();
	test_trunc();
	test_trim();
	return ret;
}
