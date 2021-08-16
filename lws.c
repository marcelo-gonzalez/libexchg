#include <libwebsockets.h>
#include <stdbool.h>

#include "net-backend.h"

struct websocket {
	struct lws *wsi;
	const char *host;
	char *path;
	void *user;
};

int ws_vprintf(struct websocket *ws, const char *fmt, va_list ap) {
	char buf[CONN_WRITE_BUF_LEN + LWS_PRE];
	int len = vsprintf(buf + LWS_PRE, fmt, ap);

	if (lws_write(ws->wsi, (unsigned char *)buf + LWS_PRE,
		      len, LWS_WRITE_TEXT) < len) {
		fprintf(stderr, "lws_write error\n");
		return -1;
	}
	return 0;
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
	char *body;
	size_t body_len;
	size_t body_size;
	void *user;
};

int http_status(struct http_req *req) {
	return req->status;
}

int http_vsprintf(struct http_req *req, const char *fmt, va_list ap) {
	if (!req->body) {
		req->body = malloc(200 + LWS_PRE);
		if (!req->body) {
			fprintf(stderr, "%s: OOM\n", __func__);
			return -1;
		}
		req->body_size = 200 + LWS_PRE;
	}
	int len;
	va_list a;

	va_copy(a, ap);
	while ((len = vsnprintf(&req->body[req->body_len + LWS_PRE],
				req->body_size - req->body_len - LWS_PRE, fmt, ap)) >=
	       req->body_size - req->body_len - LWS_PRE) {
		int sz = LWS_PRE + req->body_len + len + 1;
		char *b = realloc(req->body, sz);
		if (!b) {
			fprintf(stderr, "%s: OOM\n", __func__);
			return -1;
		}
		req->body = b;
		req->body_size = sz;
		va_copy(ap, a);
		va_copy(a, ap);
	}
	req->body_len += len;
	return len;
}

char *http_body(struct http_req *req) {
	if (!req->body)
		return NULL;
	return req->body + LWS_PRE;
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
		break;
	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		req->status = lws_http_client_http_response(wsi);
		http->on_established(req->user, req->status);
		break;
	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
		if (req->body_len > 0) {
			lws_client_http_body_pending(wsi, 1);
			lws_callback_on_writable(wsi);
		}
		req->headers_start = (unsigned char **)in;
		req->headers_end = *req->headers_start + len;
		return http->add_headers(req->user, req);
	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE:
		if (req->body_len < 1) {
			lws_client_http_body_pending(wsi, 0);
			return 0;
		}
		if (lws_write(req->wsi, (unsigned char *)req->body + LWS_PRE,
			      req->body_len, LWS_WRITE_TEXT) < req->body_len) {
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
		free(req->body);
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
