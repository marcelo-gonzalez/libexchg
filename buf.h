#ifndef BUF_H
#define BUF_H

#include <stdarg.h>
#include <stddef.h>
#include <sys/types.h>

struct buf {
	char *buf;
	size_t len;
	size_t size;
	size_t padding;
};

int buf_alloc(struct buf *buf, size_t size, size_t padding);

static inline char *buf_start(struct buf *buf) {
	if (!buf->buf)
		return NULL;
	return &buf->buf[buf->padding];
}

int buf_vsprintf(struct buf *buf, const char *fmt, va_list ap);

// for use int test code
int buf_xsprintf(struct buf *buf, const char *fmt, ...)
	__attribute__((format (printf, 2, 3)));
void buf_xcpy(struct buf *buf, void *src, size_t len);

#endif
