/*
 * ssl.c - platform TLS I/O abstraction + io_t wrapper
 *
 * macOS: Network.framework
 * Linux/others: OpenSSL
 *
 * The file exposes io_t wrappers so upper layers call io_* uniformly.
 */

#include "ssl.h"
#include "socket.h" /* so_resolv / so_connect / so_recvln / write_wrapper if needed */
#include "utils.h"  /* zmalloc */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#ifdef __APPLE__
/* macOS CFStream (CFNetwork) TLS implementation - C API, no Blocks, no Security.framework */
#include <CoreFoundation/CoreFoundation.h>
#include <CFNetwork/CFNetwork.h>

struct ssl_conn {
	CFReadStreamRef  rstream;
	CFWriteStreamRef wstream;
};

/* create TLS streams and perform handshake (blocking, short timeout) */
ssl_conn_t *ssl_connect_host(const char *host, int port) {
	if (!host) return NULL;

	CFStringRef cfHost = CFStringCreateWithCString(NULL, host, kCFStringEncodingUTF8);
	if (!cfHost) return NULL;

	CFReadStreamRef r = NULL;
	CFWriteStreamRef w = NULL;
	CFStreamCreatePairWithSocketToHost(NULL, cfHost, (UInt32)port, &r, &w);
	if (!r || !w) {
		if (r) CFRelease(r);
		if (w) CFRelease(w);
		CFRelease(cfHost);
		return NULL;
	}

	/* SSL settings: validate peer using host name */
	CFMutableDictionaryRef sslSettings = CFDictionaryCreateMutable(NULL, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (sslSettings) {
		CFDictionaryAddValue(sslSettings, kCFStreamSSLPeerName, cfHost);
		/* leave other SSL options to defaults (system trust) */
		CFReadStreamSetProperty(r, kCFStreamPropertySSLSettings, sslSettings);
		CFWriteStreamSetProperty(w, kCFStreamPropertySSLSettings, sslSettings);
		CFRelease(sslSettings);
	}

	/* open streams */
	if (!CFReadStreamOpen(r) || !CFWriteStreamOpen(w)) {
		CFReadStreamClose(r); CFWriteStreamClose(w);
		CFRelease(r); CFRelease(w); CFRelease(cfHost);
		return NULL;
	}

	/* wait briefly for stream to become open */
	int ready = 0;
	for (int i = 0; i < 200; ++i) { /* ~2s total */
		CFStreamStatus rs = CFReadStreamGetStatus(r);
		CFStreamStatus ws = CFWriteStreamGetStatus(w);
		if (rs == kCFStreamStatusOpen && ws == kCFStreamStatusOpen) { ready = 1; break; }
		if (rs == kCFStreamStatusError || ws == kCFStreamStatusError) break;
		usleep(10000);
	}
	CFRelease(cfHost);
	if (!ready) {
		CFReadStreamClose(r); CFWriteStreamClose(w);
		CFRelease(r); CFRelease(w);
		return NULL;
	}

	ssl_conn_t *c = zmalloc(sizeof(*c));
	if (!c) { CFReadStreamClose(r); CFWriteStreamClose(w); CFRelease(r); CFRelease(w); return NULL; }
	c->rstream = r;
	c->wstream = w;
	return c;
}

ssize_t ssl_write_all(ssl_conn_t *c, const void *buf, size_t len) {
	if (!c || !c->wstream || !buf || len == 0) return -1;
	size_t written = 0;
	while (written < len) {
		CFIndex w = CFWriteStreamWrite(c->wstream, (const UInt8 *)buf + written, (CFIndex)(len - written));
		if (w < 0) return -1;
		if (w == 0) {
			/* check stream status for error/closed */
			CFStreamStatus st = CFWriteStreamGetStatus(c->wstream);
			if (st == kCFStreamStatusAtEnd || st == kCFStreamStatusError) return -1;
			/* small wait and retry */
			usleep(10000);
			continue;
		}
		written += (size_t)w;
	}
	return (ssize_t)written;
}

ssize_t ssl_read(ssl_conn_t *c, void *buf, size_t len) {
	if (!c || !c->rstream || !buf || len == 0) return -1;
	CFIndex r = CFReadStreamRead(c->rstream, (UInt8 *)buf, (CFIndex)len);
	if (r < 0) return -1;
	if (r == 0) {
		CFStreamStatus st = CFReadStreamGetStatus(c->rstream);
		if (st == kCFStreamStatusAtEnd || st == kCFStreamStatusClosed) return 0;
		/* Would block / no data available */
		return 0;
	}
	return (ssize_t)r;
}

void ssl_close_conn(ssl_conn_t *c) {
	if (!c) return;
	if (c->rstream) { CFReadStreamClose(c->rstream); CFRelease(c->rstream); }
	if (c->wstream) { CFWriteStreamClose(c->wstream); CFRelease(c->wstream); }
	free(c);
}
#else /* OpenSSL path for Linux/others */

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <sys/socket.h>

struct ssl_conn {
	SSL_CTX *ctx;
	SSL *ssl;
	int sd;
};

ssl_conn_t *ssl_connect_host(const char *host, int port) {
	struct addrinfo *addresses = NULL;
	if (!so_resolv(&addresses, host, port)) return NULL;
	int sd = so_connect(addresses);
	freeaddrinfo(addresses);
	if (sd < 0) return NULL;

	SSL_library_init();
	SSL_load_error_strings();
	const SSL_METHOD *method = TLS_client_method();
	SSL_CTX *ctx = SSL_CTX_new(method);
	if (!ctx) { close(sd); return NULL; }
	SSL *ssl = SSL_new(ctx);
	if (!ssl) { SSL_CTX_free(ctx); close(sd); return NULL; }

	SSL_set_fd(ssl, sd);
	if (SSL_connect(ssl) <= 0) { SSL_free(ssl); SSL_CTX_free(ctx); close(sd); return NULL; }

	ssl_conn_t *c = zmalloc(sizeof(*c));
	c->ctx = ctx; c->ssl = ssl; c->sd = sd;
	return c;
}

ssize_t ssl_write_all(ssl_conn_t *c, const void *buf, size_t len) {
	if (!c || !c->ssl) return -1;
	size_t written = 0;
	while (written < len) {
		int w = SSL_write(c->ssl, (const char *)buf + written, (int)(len - written));
		if (w <= 0) return -1;
		written += w;
	}
	return (ssize_t)written;
}

ssize_t ssl_read(ssl_conn_t *c, void *buf, size_t len) {
	if (!c || !c->ssl) return -1;
	int r = SSL_read(c->ssl, buf, (int)len);
	if (r <= 0) {
		int err = SSL_get_error(c->ssl, r);
		if (err == SSL_ERROR_ZERO_RETURN) return 0;
		return -1;
	}
	return (ssize_t)r;
}

void ssl_close_conn(ssl_conn_t *c) {
	if (!c) return;
	if (c->ssl) {
		SSL_shutdown(c->ssl);
		SSL_free(c->ssl);
	}
	if (c->ctx) SSL_CTX_free(c->ctx);
	if (c->sd >= 0) close(c->sd);
	free(c);
}

#endif /* platform branches */

int ssl_recvln(ssl_conn_t *c, char **buf, int *bsize) {
	if (!c || !buf || !bsize) return -1;
	int pos = 0;
	char ch;
	int r;
	if (!*buf || *bsize <= 0) return -1;
	while (1) {
		r = (int)ssl_read(c, &ch, 1);
		if (r < 0) return -1;
		if (r == 0) return 0;
		if (pos + 2 > *bsize) {
			int nb = (*bsize) * 2;
			char *n = realloc(*buf, nb);
			if (!n) return -1;
			*buf = n;
			*bsize = nb;
		}
		(*buf)[pos++] = ch;
		if (ch == '\n') break;
	}
	(*buf)[pos] = '\0';
	return pos;
}

/* ---------- io_t wrappers ---------- */

io_t *io_from_fd(int fd) {
	io_t *io = zmalloc(sizeof(*io));
	if (!io) return NULL;
	io->type = IO_TYPE_FD;
	io->fd = fd;
	io->ssl = NULL;
	return io;
}

io_t *io_from_ssl(ssl_conn_t *c) {
	if (!c) return NULL;
	io_t *io = zmalloc(sizeof(*io));
	if (!io) return NULL;
	io->type = IO_TYPE_SSL;
	io->ssl = c;
	io->fd = -1;
	return io;
}

void io_close(io_t *io) {
	if (!io) return;
	if (io->type == IO_TYPE_SSL && io->ssl) {
		ssl_close_conn(io->ssl);
	}
	/* do not close plain fd here unless explicitly owned */
	if (io->type == IO_TYPE_FD && io->fd >= 0) {
		close(io->fd);
	}
	free(io);
}

ssize_t io_write_all(io_t *io, const void *buf, size_t len) {
	if (!io) return -1;
	if (io->type == IO_TYPE_FD) {
		/* use existing write wrapper for plain sockets */
		return (ssize_t)write_wrapper(io->fd, buf, len);
	} else {
		return ssl_write_all(io->ssl, buf, len);
	}
}

ssize_t io_read(io_t *io, void *buf, size_t len) {
	if (!io) return -1;
	if (io->type == IO_TYPE_FD) {
		ssize_t r = read(io->fd, buf, len);
		if (r < 0) return -1;
		return r;
	} else {
		return ssl_read(io->ssl, buf, len);
	}
}

int io_recvln(io_t *io, char **buf, int *bsize) {
	if (!io) return -1;
	if (io->type == IO_TYPE_FD) {
		return so_recvln(io->fd, buf, bsize);
	} else {
		return ssl_recvln(io->ssl, buf, bsize);
	}
}
