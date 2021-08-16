#ifndef TEST_UTIL_H
#define TEST_UTIL_H

#include <stdlib.h>
#include <string.h>

static inline unsigned char *xdupwithnull(const unsigned char *buf, size_t len) {
	unsigned char *dup = malloc(len+1);
	if (!dup) {
		fprintf(stderr, "%s: OOM\n", __func__);
		exit(1);
	}
	memcpy(dup, buf, len);
	dup[len] = 0;
	return dup;
}

static inline void *xzalloc(size_t s) {
	void *p = malloc(s);
	if (!p) {
		fprintf(stderr, "OOM\n");
		exit(1);
	}
	memset(p, 0, s);
	return p;
}


#endif
