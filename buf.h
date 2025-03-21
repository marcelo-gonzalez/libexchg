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
void buf_free(struct buf *buf);

static inline char *buf_pos(struct buf *buf, size_t pos)
{
        if (!buf->buf)
                return NULL;
        return &buf->buf[buf->padding + pos];
}

static inline char *buf_start(struct buf *buf) { return buf_pos(buf, 0); }

static inline char *buf_end(struct buf *buf) { return buf_pos(buf, buf->len); }

int buf_vsprintf(struct buf *buf, const char *fmt, va_list ap);

// for use int test code
int buf_xsprintf(struct buf *buf, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
void buf_xcpy(struct buf *buf, void *src, size_t len);
void buf_xensure_append_size(struct buf *buf, size_t len);

#endif
