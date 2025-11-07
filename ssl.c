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

#if defined(__APPLE__)
/* macOS CFStream (CFNetwork) TLS implementation */
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
#elif defined(__CYGWIN__)
/* Windows/Cygwin SSPI (SChannel) implementation - uses system APIs only */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <sspi.h>
#include <schannel.h>
#include <security.h>

/* Linker note: on native Windows you need secur32; with Cygwin the build/link
   should pick the appropriate system libs. Update Makefile if necessary. */

struct ssl_conn {
    CredHandle	cred;
    CtxtHandle	ctx;
    SOCKET		sd;
    int		handshake_done;
    SecPkgContext_StreamSizes sizes;
    /* receive buffer for encrypted stream data */
    unsigned char *inbuf;
    size_t	inlen;
};

/* helper: send all bytes on socket */
static int send_all(SOCKET s, const void *buf, size_t len) {
    const unsigned char *p = buf;
    size_t left = len;
    while (left) {
        int w = send(s, (const char*)p, (int)left, 0);
        if (w <= 0) return 0;
        p += w; left -= w;
    }
    return 1;
}

/* helper: receive some bytes (non-fatal if would block) */
static int recv_some(SOCKET s, unsigned char *buf, int max) {
    int r = recv(s, (char*)buf, max, 0);
    if (r <= 0) return r;
    return r;
}

/* perform TLS handshake using InitializeSecurityContext (client) */
ssl_conn_t *ssl_connect_host(const char *host, int port) {
    struct addrinfo *addresses = NULL;
    if (!so_resolv(&addresses, host, port)) return NULL;
    int sd = so_connect(addresses);
    freeaddrinfo(addresses);
    if (sd < 0) return NULL;
    SOCKET s = (SOCKET)sd;

    /* Acquire credentials for Schannel */
    SEC_WCHAR *pszSchannel = NULL; /* not used with AcquireCredentialsHandleA */
    TimeStamp ts;
    CredHandle cred;
    SCHANNEL_CRED scCred;
    memset(&scCred, 0, sizeof(scCred));
    scCred.dwVersion = SCHANNEL_CRED_VERSION;
    scCred.grbitEnabledProtocols = 0; /* use defaults */
    scCred.cCreds = 0;
    scCred.paCred = NULL;

    SECURITY_STATUS sec = AcquireCredentialsHandleA(
        NULL,
        UNISP_NAME_A,
        SECPKG_CRED_OUTBOUND,
        NULL,
        &scCred,
        NULL,
        NULL,
        &cred,
        &ts);
    if (sec != SEC_E_OK) { closesocket(s); return NULL; }

    CtxtHandle ctx;
    BOOL haveCtx = FALSE;
    SecBufferDesc outBufDesc;
    SecBuffer outSecBuf;
    SecBufferDesc inBufDesc;
    SecBuffer inSecBuf;
    unsigned char inbuf[16384];
    int inlen = 0;
    unsigned char *pIn = inbuf;

    /* handshake loop */
    while (1) {
        /* Prepare output buffer */
        outSecBuf.BufferType = SECBUFFER_TOKEN;
        outSecBuf.cbBuffer = 0;
        outSecBuf.pvBuffer = NULL;
        outBufDesc.cBuffers = 1;
        outBufDesc.pBuffers = &outSecBuf;
        outBufDesc.ulVersion = SECBUFFER_VERSION;

        SecBufferDesc *pInDesc = NULL;
        SecBuffer inBuffer;
        if (inlen > 0) {
            inBuffer.BufferType = SECBUFFER_TOKEN;
            inBuffer.cbBuffer = inlen;
            inBuffer.pvBuffer = pIn;
            inBufDesc.cBuffers = 1;
            inBufDesc.pBuffers = &inBuffer;
            inBufDesc.ulVersion = SECBUFFER_VERSION;
            pInDesc = &inBufDesc;
        }

        unsigned long ctxAttr = 0;
        SECURITY_STATUS r;
        r = InitializeSecurityContextA(
            &cred,
            haveCtx ? &ctx : NULL,
            (SEC_CHAR*)host,
            ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY,
            0,
            SECURITY_NATIVE_DREP,
            pInDesc,
            0,
            haveCtx ? &ctx : &ctx,
            &outBufDesc,
            &ctxAttr,
            &ts);

        /* send output token if present */
        if (outSecBuf.cbBuffer && outSecBuf.pvBuffer) {
            if (!send_all(s, outSecBuf.pvBuffer, outSecBuf.cbBuffer)) {
                if (outSecBuf.pvBuffer) FreeContextBuffer(outSecBuf.pvBuffer);
                if (haveCtx) DeleteSecurityContext(&ctx);
                FreeCredentialsHandle(&cred);
                closesocket(s);
                return NULL;
            }
            FreeContextBuffer(outSecBuf.pvBuffer);
            outSecBuf.pvBuffer = NULL;
        }

        if (r == SEC_E_OK) {
            haveCtx = TRUE;
            break; /* handshake complete */
        } else if (r == SEC_I_CONTINUE_NEEDED || r == SEC_E_INCOMPLETE_MESSAGE || r == SEC_E_OK) {
            /* need to read more data */
            int rr = recv_some(s, inbuf + inlen, (int)(sizeof(inbuf) - inlen));
            if (rr <= 0) {
                /* error or closed */
                if (haveCtx) DeleteSecurityContext(&ctx);
                FreeCredentialsHandle(&cred);
                closesocket(s);
                return NULL;
            }
            inlen += rr;
            pIn = inbuf;
            /* loop and call InitializeSecurityContext again */
            haveCtx = TRUE; /* ensure we pass ctx next time */
            continue;
        } else {
            /* handshake failure */
            if (haveCtx) DeleteSecurityContext(&ctx);
            FreeCredentialsHandle(&cred);
            closesocket(s);
            return NULL;
        }
    }

    /* Query stream sizes */
    SecPkgContext_StreamSizes sizes;
    sec = QueryContextAttributes(&ctx, SECPKG_ATTR_STREAM_SIZES, &sizes);
    if (sec != SEC_E_OK) {
        DeleteSecurityContext(&ctx);
        FreeCredentialsHandle(&cred);
        closesocket(s);
        return NULL;
    }

    ssl_conn_t *c = zmalloc(sizeof(*c));
    if (!c) { DeleteSecurityContext(&ctx); FreeCredentialsHandle(&cred); closesocket(s); return NULL; }
    c->cred = cred;
    c->ctx = ctx;
    c->sd = s;
    c->handshake_done = 1;
    c->sizes = sizes;
    c->inbuf = NULL;
    c->inlen = 0;
    return c;
}

/* write: encrypt application data with EncryptMessage and send */
ssize_t ssl_write_all(ssl_conn_t *c, const void *buf, size_t len) {
    if (!c || !c->handshake_done) return -1;
    if (len == 0) return 0;

    /* allocate buffer: header + data + trailer */
    size_t hdr = c->sizes.cbHeader;
    size_t trailer = c->sizes.cbTrailer;
    size_t msglen = hdr + len + trailer;
    unsigned char *out = zmalloc(msglen);
    if (!out) return -1;

    /* place data in the middle */
    unsigned char *pdata = out + hdr;
    memcpy(pdata, buf, len);

    SecBuffer secBuff[4];
    secBuff[0].BufferType = SECBUFFER_STREAM_HEADER;
    secBuff[0].pvBuffer = out;
    secBuff[0].cbBuffer = (unsigned long)hdr;
    secBuff[1].BufferType = SECBUFFER_DATA;
    secBuff[1].pvBuffer = pdata;
    secBuff[1].cbBuffer = (unsigned long)len;
    secBuff[2].BufferType = SECBUFFER_STREAM_TRAILER;
    secBuff[2].pvBuffer = out + hdr + len;
    secBuff[2].cbBuffer = (unsigned long)trailer;
    secBuff[3].BufferType = SECBUFFER_EMPTY;
    SecBufferDesc msg;
    msg.ulVersion = SECBUFFER_VERSION;
    msg.cBuffers = 4;
    msg.pBuffers = secBuff;

    SECURITY_STATUS r = EncryptMessage(&c->ctx, 0, &msg, 0);
    if (r != SEC_E_OK) { free(out); return -1; }

    /* compute total size (header + data + trailer might have changed sizes) */
    size_t sendlen = 0;
    for (int i = 0; i < 3; ++i) sendlen += secBuff[i].cbBuffer;

    /* send all */
    int ok = send_all(c->sd, secBuff[0].pvBuffer, secBuff[0].cbBuffer) &&
             send_all(c->sd, secBuff[1].pvBuffer, secBuff[1].cbBuffer) &&
             send_all(c->sd, secBuff[2].pvBuffer, secBuff[2].cbBuffer);

    free(out);
    if (!ok) return -1;
    return (ssize_t)len;
}

/* read: receive encrypted stream bytes, call DecryptMessage, return plaintext */
ssize_t ssl_read(ssl_conn_t *c, void *buf, size_t len) {
    if (!c || !c->handshake_done) return -1;
    /* maintain a simple input buffer */
    if (!c->inbuf) {
        c->inbuf = zmalloc(16384);
        c->inlen = 0;
        if (!c->inbuf) return -1;
    }

    /* try decrypt loop: recv some bytes then call DecryptMessage */
    while (1) {
        /* prepare buffers */
        SecBuffer secBuff[4];
        secBuff[0].pvBuffer = c->inbuf;
        secBuff[0].cbBuffer = (unsigned long)c->inlen;
        secBuff[0].BufferType = SECBUFFER_STREAM;
        secBuff[1].BufferType = SECBUFFER_DATA;
        secBuff[1].pvBuffer = NULL;
        secBuff[1].cbBuffer = 0;
        secBuff[2].BufferType = SECBUFFER_EMPTY;
        secBuff[3].BufferType = SECBUFFER_EMPTY;
        SecBufferDesc msg; msg.ulVersion = SECBUFFER_VERSION; msg.cBuffers = 4; msg.pBuffers = secBuff;
        SECURITY_STATUS r = DecryptMessage(&c->ctx, &msg, 0, NULL);
        if (r == SEC_E_OK) {
            /* find data buffer */
            for (int i = 0; i < 4; ++i) {
                if (secBuff[i].BufferType == SECBUFFER_DATA && secBuff[i].cbBuffer > 0) {
                    size_t got = secBuff[i].cbBuffer;
                    size_t tocopy = (got > len) ? len : got;
                    memcpy(buf, secBuff[i].pvBuffer, tocopy);

                    /* if there are leftover bytes (stream), move them to front */
                    size_t left = 0;
                    if (secBuff[0].BufferType == SECBUFFER_STREAM && secBuff[0].cbBuffer > 0) {
                        left = secBuff[0].cbBuffer;
                        memmove(c->inbuf, secBuff[0].pvBuffer, left);
                    }
                    c->inlen = left;
                    return (ssize_t)tocopy;
                }
            }
            /* no data yet, continue to read */
        } else if (r == SEC_E_INCOMPLETE_MESSAGE) {
            /* need more data from socket */
            if (c->inlen >= 16384) return -1;
            int rr = recv_some(c->sd, c->inbuf + c->inlen, (int)(16384 - c->inlen));
            if (rr <= 0) return (rr == 0) ? 0 : -1;
            c->inlen += rr;
            continue;
        } else {
            /* fatal error */
            return -1;
        }
    }
}

void ssl_close_conn(ssl_conn_t *c) {
    if (!c) return;
    /* try to close TLS gracefully */
    if (c->handshake_done) {
        /* no explicit SSPI shutdown token here — just delete context */
        DeleteSecurityContext(&c->ctx);
    }
    FreeCredentialsHandle(&c->cred);
    if (c->sd) closesocket(c->sd);
    if (c->inbuf) free(c->inbuf);
    free(c);
}
#else
/* OpenSSL path for Linux/others */
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

/* ---------- io_t wrappers ---------- */

void io_from_fd(io_t *io, int fd) {
	io->type = IO_TYPE_FD;
	io->fd = fd;
	io->ssl = NULL;
}

void io_from_ssl(io_t *io, ssl_conn_t *c) {
	io->type = IO_TYPE_SSL;
	io->ssl = c;
	io->fd = -1;
}

void io_close(io_t *io) {
	if (!io) return;
	if (io->type == IO_TYPE_SSL && io->ssl) {
		ssl_close_conn(io->ssl);
	}
	if (io->type == IO_TYPE_FD && io->fd >= 0) {
		close(io->fd);
	}
}

ssize_t io_write_all(io_t *io, const void *buf, size_t len) {
	if (!io) return -1;
	if (io->type == IO_TYPE_FD) {
		return write_wrapper(io->fd, buf, len);
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
