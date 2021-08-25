// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Marcelo Diop-Gonzalez

#include <libwebsockets.h>
#include <stdbool.h>

#include "net-backend.h"

struct websocket {
	struct lws *wsi;
	const char *host;
	char *path;
	void *user;
};

struct buf {
	char *buf;
	size_t len;
	size_t size;
};

static int buf_alloc(struct buf *buf, size_t size) {
	size += LWS_PRE;
	buf->buf = malloc(size);
	if (!buf->buf) {
		fprintf(stderr, "%s: OOM\n", __func__);
		return -1;
	}
	buf->size = size;
	buf->len = 0;
	return 0;
}

static char *buf_start(struct buf *buf) {
	if (!buf->buf)
		return NULL;
	return buf->buf + LWS_PRE;
}

static int buf_vsprintf(struct buf *buf, const char *fmt, va_list ap) {
	int len;
	va_list a;

	va_copy(a, ap);
	while ((len = vsnprintf(&buf->buf[buf->len + LWS_PRE],
				buf->size - buf->len - LWS_PRE, fmt, ap)) >=
	       buf->size - buf->len - LWS_PRE) {
		int sz = LWS_PRE + buf->len + len + 1;
		char *b = realloc(buf->buf, sz);
		if (!b) {
			fprintf(stderr, "%s: OOM\n", __func__);
			return -1;
		}
		buf->buf = b;
		buf->size = sz;
		va_copy(ap, a);
		va_copy(a, ap);
	}
	buf->len += len;
	return len;
}

int ws_vprintf(struct websocket *ws, const char *fmt, va_list ap) {
	va_list a;
	char buf[1024 + LWS_PRE];
	va_copy(a, ap);

	int len = vsnprintf(buf + LWS_PRE, 1024, fmt, ap);
	if (len < 1024) {
		if (lws_write(ws->wsi, (unsigned char *)buf+LWS_PRE,
			      len, LWS_WRITE_TEXT) < len) {
			// TODO: exchg_log() should be accessible here without including exchg.h
			fprintf(stderr, "lws_write() error writing %d bytes:\n%s\n", len, buf);
			return -1;
		} else {
			return len;
		}
	} else {
		struct buf b;

		if (buf_alloc(&b, len+1))
			return -1;
		len = buf_vsprintf(&b, fmt, a);
		if (len < 0) {
			free(b.buf);
			return len;
		}
		if (lws_write(ws->wsi, (unsigned char *)buf_start(&b),
			      len, LWS_WRITE_TEXT) < len) {
			fprintf(stderr, "lws_write() error writing %d bytes:\n%s\n",
				len, buf_start(&b));
			free(b.buf);
			return -1;
		}
		free(b.buf);
		return len;
	}
}

void ws_close(struct websocket *ws) {
	lws_set_timeout(ws->wsi, PENDING_TIMEOUT_USER_OK,
			LWS_TO_KILL_ASYNC);
}

static int websocket_callback(struct lws *wsi, enum lws_callback_reasons reason,
			      void *user, void *in, size_t len) {
	const struct net_callbacks *c = lws_context_user(lws_get_context(wsi));
	const struct websocket_callbacks *ops = &c->ws;
	struct websocket *ws = user;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("Websocket Connection Error: %s%s: %s\n",
			 ws->host, ws->path, in ? (char *)in : "(null)");
		ops->on_error(ws->user);
		free(ws->path);
		free(ws);
		break;
	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		ops->on_established(ws->user);
		break;
	case LWS_CALLBACK_CLIENT_RECEIVE:
		return ops->recv(ws->user, in, len);
	case LWS_CALLBACK_WS_PEER_INITIATED_CLOSE:
		// TODO
		break;
	case LWS_CALLBACK_CLIENT_CLOSED:
		ops->on_closed(ws->user);
		free(ws->path);
		free(ws);
		return 0;
	default:
		break;
	}
	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static int prepare_http_client_read(struct lws *wsi) {
	char buffer[1024 + LWS_PRE];
	char *p = buffer + LWS_PRE;
	int len = sizeof(buffer) - LWS_PRE;
	return lws_http_client_read(wsi, &p, &len);
}

struct http_req {
	struct lws *wsi;
	const char *host;
	const char *path;
	int status;
	unsigned char **headers_start;
	unsigned char *headers_end;
	struct buf body;
	void *user;
};

int http_vsprintf(struct http_req *req, const char *fmt, va_list ap) {
	if (!req->body.buf && buf_alloc(&req->body, 200))
		return -1;

	return buf_vsprintf(&req->body, fmt, ap);
}

int http_status(struct http_req *req) {
	return req->status;
}

char *http_body(struct http_req *req) {
	return buf_start(&req->body);
}

int http_add_header(struct http_req *req, const unsigned char *name,
		    const unsigned char *val, size_t len) {
	if (lws_add_http_header_by_name(req->wsi, name, val, len,
					req->headers_start, req->headers_end)) {
		fprintf(stderr, "lws_add_http_header_by_name() error\n");
		return -1;
	}
	return 0;
}

void http_close(struct http_req *req) {
	lws_set_timeout(req->wsi, PENDING_TIMEOUT_USER_OK,
			LWS_TO_KILL_ASYNC);
}

static int http_callback(struct lws *wsi, enum lws_callback_reasons reason,
			 void *user, void *in, size_t len) {
	const struct net_callbacks *c = lws_context_user(lws_get_context(wsi));
	const struct http_callbacks *http = &c->http;
	struct http_req *req = user;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("HTTP CONNECTION ERROR: %s%s: %s\n",
			 req->host, req->path, in ? (char *)in : "(null)");
		http->on_error(req->user, (char *)in);
		free(req->body.buf);
		free(req);
		break;
	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		req->status = lws_http_client_http_response(wsi);
		http->on_established(req->user, req->status);
		break;
	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
		if (req->body.len > 0) {
			lws_client_http_body_pending(wsi, 1);
			lws_callback_on_writable(wsi);
		}
		req->headers_start = (unsigned char **)in;
		req->headers_end = *req->headers_start + len;
		return http->add_headers(req->user, req);
	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE:
		if (req->body.len < 1) {
			lws_client_http_body_pending(wsi, 0);
			return 0;
		}
		if (lws_write(req->wsi, (unsigned char *)buf_start(&req->body),
			      req->body.len, LWS_WRITE_TEXT) < req->body.len) {
			lwsl_err("%s%s: write error\n", req->host, req->path);
			return -1;
		}
		lws_client_http_body_pending(wsi, 0);
		return 0;
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		return prepare_http_client_read(wsi);
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		return http->recv(req->user, in, len);
		// TODO: not always called. to trigger, remove ssl global init
		// in context_create_info, or set hostname to garbage
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		http->on_closed(req->user);
		free(req->body.buf);
		free(req);
		break;
	default:
		break;
	}
	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

struct lws_protocols protocols[] = {
	{
		"ws",
		websocket_callback,
	},
	{
		"http",
		http_callback,
	},
	{},
};

struct exchg_net_context {
	struct lws_context *ctx;
};

struct http_req *http_dial(struct exchg_net_context *ctx,
			   const char *host, const char *path,
			   const char *method, void *private) {
	struct http_req *req = malloc(sizeof(*req));
	if (!req) {
		fprintf(stderr, "OOM: %s\n", __func__);
		return NULL;
	}
	memset(req, 0, sizeof(*req));

	struct lws_client_connect_info info = {
		.context = ctx->ctx,
		.port = 443,
		.address = host,
		.path = path,
		.method = method,
		.host = host,
		.origin = host,
		.ssl_connection = LCCSCF_USE_SSL,
		.protocol = "http",
		.userdata = req,
		.pwsi = &req->wsi,
	};
	req->host = host;
	req->path = path;
	req->user = private;

	if (!lws_client_connect_via_info(&info)) {
		fprintf(stderr, "lws_client_connect_via_info() error connecting to %s%s\n", host, path);
		free(req);
		return NULL;
	}
	return req;
}

struct websocket *ws_dial(struct exchg_net_context *ctx, const char *host,
			  const char *path, void *private) {
	struct websocket *ws = malloc(sizeof(*ws));
	if (!ws) {
		fprintf(stderr, "OOM: %s\n", __func__);
		return NULL;
	}
	memset(ws, 0, sizeof(*ws));
	struct lws_client_connect_info info = {
		.context = ctx->ctx,
		.port = 443,
		.address = host,
		.path = path,
		.host = host,
		.origin = host,
		.ssl_connection = LCCSCF_USE_SSL,
		.protocol = "ws",
		.userdata = ws,
		.pwsi = &ws->wsi,
	};
	if (!lws_client_connect_via_info(&info)) {
		free(ws);
		fprintf(stderr, "websocket connection to %s%s failed\n", host, path);
		return NULL;
	}
	ws->user = private;
	ws->host = host;
	ws->path = strdup(path);
	if (!ws->path) {
		fprintf(stderr, "OOM: %s\n", __func__);
		free(ws);
		return NULL;
	}
	return ws;
}

int net_service(struct exchg_net_context *ctx) {
	return lws_service(ctx->ctx, 0);
}

void net_destroy(struct exchg_net_context *ctx) {
	lws_context_destroy(ctx->ctx);
	free(ctx);
}

struct exchg_net_context *net_new(struct net_callbacks *c) {
	struct exchg_net_context *ret = malloc(sizeof(*ret));
	if (!ret) {
		fprintf(stderr, "OOM: %s\n", __func__);
		return NULL;
	}
	struct lws_context_creation_info info = {
		.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT,
		.port = CONTEXT_PORT_NO_LISTEN,
		.protocols = protocols,
		.user = c,
	};
	ret->ctx = lws_create_context(&info);
	if (!ret->ctx) {
		free(ret);
		fprintf(stderr, "lws_create_context failed\n");
		return NULL;
	}
	return ret;
}
