#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "buf.h"

int buf_alloc(struct buf *buf, size_t size, size_t padding) {
	size += padding;
	buf->buf = malloc(size);
	if (!buf->buf) {
		fprintf(stderr, "%s: OOM\n", __func__);
		return -1;
	}
	buf->size = size;
	buf->padding = padding;
	buf->len = 0;
	return 0;
}

int buf_vsprintf(struct buf *buf, const char *fmt, va_list ap) {
	int len;
	va_list a;
	bool copied = false;

	va_copy(a, ap);

	while ((len = vsnprintf(&buf->buf[buf->padding + buf->len],
				buf->size - buf->len - buf->padding, fmt, ap)) >=
	       buf->size - buf->len - buf->padding) {
		int sz = 2*(buf->padding + buf->len + len + 1);
		char *b = realloc(buf->buf, sz);
		if (!b) {
			fprintf(stderr, "%s: OOM\n", __func__);
			return -1;
		}
		buf->buf = b;
		buf->size = sz;

		if (copied)
			va_end(ap);
		va_copy(ap, a);
		copied = true;
	}
	va_end(a);
	buf->len += len;
	return len;
}

int buf_xsprintf(struct buf *buf, const char *fmt, ...) {
	va_list ap;

	va_start(ap, fmt);
	int ret = buf_vsprintf(buf, fmt, ap);
	if (ret < 0)
		exit(1);
	va_end(ap);

	return ret;
}

void buf_xcpy(struct buf *buf, void *src, size_t len) {
	if (buf->size < buf->padding + buf->len + len) {
		int sz = buf->padding + buf->len + len;
		char *b = realloc(buf->buf, sz);
		if (!b) {
			fprintf(stderr, "%s: OOM\n", __func__);
			exit(1);
		}
		buf->buf = b;
		buf->size = sz;
	}
	memcpy(&buf->buf[buf->padding + buf->len], src, len);
	buf->len += len;
}
