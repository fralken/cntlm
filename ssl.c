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
/* macOS Network.framework implementation */
#include <Network/Network.h>
#include <dispatch/dispatch.h>

struct ssl_conn {
    nw_connection_t conn;
    dispatch_queue_t queue;
};

/* funzione nw_noop_state_handler rimossa (non usata) */

ssl_conn_t *ssl_connect_host(const char *host, int port) {
    ssl_conn_t *c = NULL;
    char portbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%d", port);

    c = zmalloc(sizeof(*c));
    if (!c) return NULL;

    c->queue = dispatch_queue_create("cntlm.ssl.queue", DISPATCH_QUEUE_SERIAL);
    if (!c->queue) { free(c); return NULL; }

    nw_endpoint_t ep = nw_endpoint_create_host(host, portbuf);
    /* provide two empty configuration blocks to satisfy non-null requirements */
    nw_parameters_t params = nw_parameters_create_secure_tcp(
        ^(nw_protocol_options_t tls_options){ (void)tls_options; },
        ^(nw_protocol_options_t tcp_options){ (void)tcp_options; }
    );
    c->conn = nw_connection_create(ep, params);
    nw_release(ep);
    nw_release(params);

    if (!c->conn) {
        dispatch_release(c->queue);
        free(c);
        return NULL;
    }

    nw_connection_set_queue(c->conn, c->queue);
    /* use a semaphore + state variable because nw_connection_get_state
     * is not available in all SDKs. The handler stores the last state
     * and signals the semaphore when connection transitions to a final state.
     */
    __block nw_connection_state_t last_state = nw_connection_state_invalid;
    dispatch_semaphore_t stsem = dispatch_semaphore_create(0);
    nw_connection_set_state_changed_handler(c->conn, ^(nw_connection_state_t state, nw_error_t error) {
        /* mark error as used to silence -Wunused-parameter */
        (void)error;
        last_state = state;
        if (state == nw_connection_state_ready ||
            state == nw_connection_state_failed ||
            state == nw_connection_state_cancelled) {
            dispatch_semaphore_signal(stsem);
        }
    });
    nw_connection_start(c->conn);

    /* wait (up to ~2s) for ready/failed */
    int ready = 0;
    const long attempts = 200;
    for (long i = 0; i < attempts; ++i) {
        if (dispatch_semaphore_wait(stsem, dispatch_time(DISPATCH_TIME_NOW, 10000 * NSEC_PER_USEC)) == 0) {
            if (last_state == nw_connection_state_ready) ready = 1;
            break;
        }
        /* small sleep if semaphore wasn't signaled */
        usleep(10000);
    }
    dispatch_release(stsem);
    if (!ready) {
        nw_connection_cancel(c->conn);
        nw_release(c->conn);
        dispatch_release(c->queue);
        free(c);
        return NULL;
    }

    return c;
}

ssize_t ssl_write_all(ssl_conn_t *c, const void *buf, size_t len) {
    if (!c || !buf) return -1;
    __block ssize_t sent = -1;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    /* create dispatch_data for content and send it */
    dispatch_data_t data = dispatch_data_create(buf, len, NULL, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
    nw_connection_send(c->conn, data, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true, ^(nw_error_t error) {
        (void)error;
        if (error) sent = -1;
        else sent = (ssize_t)len;
        dispatch_semaphore_signal(sem);
    });
    if (data) dispatch_release(data);
    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
    dispatch_release(sem);
    return sent;
}
 
ssize_t ssl_read(ssl_conn_t *c, void *buf, size_t len) {
    if (!c || !buf) return -1;
    __block ssize_t got = -1;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    nw_connection_receive(c->conn, 1, len, ^(dispatch_data_t content, nw_content_context_t ctx, bool is_complete, nw_error_t error) {
        (void)ctx; (void)is_complete; (void)error;
        if (error) {
            got = -1;
        } else if (content == NULL) {
            got = 0;
        } else {
            size_t s = dispatch_data_get_size(content);
            if (s > 0) {
                dispatch_data_apply(content, ^bool(dispatch_data_t region, size_t offset, const void *buffer, size_t size) {
                    /* mark unused params to avoid warnings */
                    (void)region; (void)offset;
                    memcpy(buf, buffer, size);
                    return false;
                });
                got = (ssize_t)s;
            } else {
                got = 0;
            }
        }
        dispatch_semaphore_signal(sem);
    });
    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
    dispatch_release(sem);
    return got;
}

int ssl_recvln(ssl_conn_t *c, char **buf, int *bsize) {
    if (!c || !buf || !bsize) return -1;
    int pos = 0;
    char ch;
    int r;

    if (!*buf || *bsize <= 0) return -1;

    while (1) {
        r = (int)ssl_read(c, &ch, 1);
        if (r <= 0) return r;
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

void ssl_close_conn(ssl_conn_t *c) {
    if (!c) return;
    if (c->conn) {
        nw_connection_cancel(c->conn);
        nw_release(c->conn);
    }
    if (c->queue) dispatch_release(c->queue);
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

int ssl_recvln(ssl_conn_t *c, char **buf, int *bsize) {
    int pos = 0;
    char cch;
    int r;

    if (!c || !buf || !bsize) return -1;
    if (!*buf || *bsize <= 0) return -1;

    while (1) {
        r = (int)ssl_read(c, &cch, 1);
        if (r <= 0) return r;
        if (pos + 2 > *bsize) {
            int nb = (*bsize) * 2;
            char *n = realloc(*buf, nb);
            if (!n) return -1;
            *buf = n;
            *bsize = nb;
        }
        (*buf)[pos++] = cch;
        if (cch == '\n') break;
    }
    (*buf)[pos] = '\0';
    return pos;
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

/* ---------- io_t wrappers ---------- */

io_t *io_from_fd(int fd) {
    io_t *io = zmalloc(sizeof(*io));
    if (!io) return NULL;
    io->type = IO_TYPE_FD;
    io->fd = fd;
    io->ssl = NULL;
    io->own = 0; /* does not own fd */
    return io;
}

io_t *io_from_owned_fd(int fd) {
    io_t *io = io_from_fd(fd);
    if (io) io->own = 1;
    return io;
}

io_t *io_from_ssl(ssl_conn_t *c) {
    if (!c) return NULL;
    io_t *io = zmalloc(sizeof(*io));
    if (!io) return NULL;
    io->type = IO_TYPE_SSL;
    io->ssl = c;
    io->fd = -1;
    io->own = 1; /* owns ssl_conn */
    return io;
}

void io_close(io_t *io) {
    if (!io) return;
    if (io->type == IO_TYPE_SSL && io->ssl && io->own) {
        ssl_close_conn(io->ssl);
    }
    /* do not close plain fd here unless explicitly owned */
    if (io->type == IO_TYPE_FD && io->own && io->fd >= 0) {
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
