#ifndef NET_BACKEND_H
#define NET_BACKEND_H

#include <stdarg.h>
#include <stdbool.h>

struct exchg_net_context;

struct http_req;

struct http_callbacks {
	void (*on_error)(void *p, const char *err);
	void (*on_established)(void *p, int status);
	int (*add_headers)(void *p, struct http_req *);
	int (*recv)(void *p, char *in, size_t len);
	void (*on_closed)(void *p);
};

struct websocket_callbacks {
	void (*on_error)(void *p);
	void (*on_established)(void *p);
	int (*recv)(void *p, char *in, size_t len);
	void (*on_closed)(void *p);
};

struct net_callbacks {
	struct http_callbacks http;
	struct websocket_callbacks ws;
};

extern struct exchg_net_context *net_new(struct net_callbacks *c);
extern int net_service(struct exchg_net_context *);
extern void net_destroy(struct exchg_net_context *);

int http_add_header(struct http_req *req, const unsigned char *name,
		    const unsigned char *val, size_t len);

int http_vsprintf(struct http_req *req, const char *fmt, va_list ap);
char *http_body(struct http_req *req);

struct http_req *http_dial(struct exchg_net_context *,
			   const char *host, const char *path,
			   const char *method, void *private);
int http_status(struct http_req *);

void http_close(struct http_req *req);

struct websocket;

#define CONN_WRITE_BUF_LEN (1 << 10)
// MUST NOT exceed CONN_WRITE_BUF_LEN
extern int ws_vprintf(struct websocket *, const char *fmt, va_list ap);

void ws_close(struct websocket *ws);

struct websocket *ws_dial(struct exchg_net_context *, const char *host,
			  const char *path, void *private);

#endif
