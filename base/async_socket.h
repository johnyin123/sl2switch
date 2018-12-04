#ifndef __NBSOCK_H__
#define __NBSOCK_H__
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "debug.h"
#ifdef HAVE_TLS
#include <openssl/ssl.h>
#endif

#define DATA_BUFFER_SIZE        4096

static inline int setnonblocking(int fd)
{
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFD, 0) | O_NONBLOCK) == -1)
    {
        sock_inner_log(ERROR, "fcntl(%d) failed [%s]", fd, strerror(errno));
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

static inline int settcpnodelay(int fd)
{
    int on = 1;
    return setsockopt(fd, SOL_TCP, TCP_NODELAY, &on, sizeof(on));
}

typedef struct connection_t
{
    int sock;
    struct sockaddr_in in_addr;
    socklen_t in_len;
    char buffer[DATA_BUFFER_SIZE + 1];
    ssize_t nbytes;
#ifdef HAVE_TLS
    SSL_CTX *tls_ctx;
    SSL *tls;
    int handshaked:1;
#endif
    void *ctx;
} connection_t;

#ifdef HAVE_TLS
/*buf == NULL return pkey size */
int getpubkey(X509 *cert, unsigned char *buf, int len);
void dump_peer(FILE *fp, connection_t *c);
SSL_CTX *tls_ctx_init();
bool tls_ctx_ca  (SSL_CTX *ctx, const char *file);
bool tls_ctx_cert(SSL_CTX *ctx, const char *file);
bool tls_ctx_key (SSL_CTX *ctx, const char *file);
void tls_ctx_free(SSL_CTX *ctx);
void set_tls_ctx(connection_t *c, SSL_CTX *tls_ctx);
int tls_handshake(connection_t *c);
#endif

struct sock_operator
{
    ssize_t(*read) (connection_t *c);
    /*buf == NULL || nbyte ==0 return buf used */
    ssize_t(*getbuf) (connection_t *c, char *buf, int nbyte);
    ssize_t (*peekbuf)(connection_t *c, const char **ptr);
    ssize_t(*write) (connection_t *c, const void *buf, size_t nbyte);
    int (*socket) (connection_t *c, int domain, int type, int protocol);
    int (*accept) (connection_t *srv, connection_t *c);
    int (*listen) (connection_t *c, int port, int backlog);
    int (*close) (connection_t *c);
    int (*getfd) (connection_t *c);
    int (*connect) (connection_t *c, const char *ip, ushort port);
    void *(*get_ctx) (connection_t *c);
    void (*set_ctx) (connection_t *c, void *data);
    int (*check)(int fd);
};

extern struct sock_operator AsyncSocket;

#endif
