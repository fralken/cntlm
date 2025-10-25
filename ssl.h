#ifndef CNTLM_SSL_H
#define CNTLM_SSL_H

#include <sys/types.h>

/* Opaque SSL/TLS connection handle (platform-specific) */
typedef struct ssl_conn ssl_conn_t;

/* I/O abstraction type */
typedef enum {
    IO_TYPE_FD = 0,
    IO_TYPE_SSL
} io_type_t;

typedef struct io_s {
    io_type_t type;
    int fd;                /* valid if type == IO_TYPE_FD */
    ssl_conn_t *ssl;       /* valid if type == IO_TYPE_SSL */
    int own;               /* if 1, io_close will free/close underlying resource */
} io_t;

/* Platform TLS connect */
ssl_conn_t *ssl_connect_host(const char *host, int port);
void ssl_close_conn(ssl_conn_t *c);

/* Low-level SSL read/write helpers (used internally) */
ssize_t ssl_write_all(ssl_conn_t *c, const void *buf, size_t len);
ssize_t ssl_read(ssl_conn_t *c, void *buf, size_t len);
int ssl_recvln(ssl_conn_t *c, char **buf, int *bsize);

/* io_t helpers */
io_t *io_from_fd(int fd);               /* does NOT own fd */
io_t *io_from_owned_fd(int fd);         /* owns fd, io_close will close it */
io_t *io_from_ssl(ssl_conn_t *c);       /* owns ssl_conn; io_close will close it */
void io_close(io_t *io);                /* free and optionally close underlying */

ssize_t io_write_all(io_t *io, const void *buf, size_t len);
ssize_t io_read(io_t *io, void *buf, size_t len);
int io_recvln(io_t *io, char **buf, int *bsize);

#endif /* CNTLM_SSL_H */
