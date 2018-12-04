#include "async_socket.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <assert.h>

#ifdef HAVE_TLS
#include <openssl/err.h>
static void dump_cert(FILE *fp, X509 *cert)
{
    char *line;
    if (cert != NULL)
    {
        fprintf(fp, "数字证书信息:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        fprintf(fp, "证书: %s\n", line);
        OPENSSL_free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        fprintf(fp, "颁发者: %s\n", line);
        OPENSSL_free(line);
        X509_free(cert);
    }
    else
        fprintf(fp, "无证书信息！\n");
}
void dump_peer(FILE *fp, connection_t *c)
{
    dump_cert(fp, SSL_get_peer_certificate(c->tls));
    dump_cert(fp, SSL_get_certificate(c->tls));
}
/*
   FILE *fp = fopen(pkfile, "r");
   X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
   time_t tcheck=time(NULL);
   if (X509_cmp_time(X509_get_notAfter(x509), &tcheck) < 0) {
   printf("%s\n", "expire!");

   X509 *cert = SSL_get_peer_certificate(c->tls);
   X509_free(cert);
*/
int getpubkey(X509 *cert, unsigned char *buf, int len)
{
    int pkeyLen;
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if(pkey == NULL)
        return -1;
    pkeyLen = i2d_PublicKey(pkey, NULL);
    if((buf != NULL) && (len >= pkeyLen))
    {
        i2d_PublicKey(pkey, &buf);
    }
    EVP_PKEY_free(pkey);
    return pkeyLen;
}
static int verify_callback(int ok, X509_STORE_CTX *ctx)
{
    X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
    time_t tcheck=time(NULL);
    if(cert)
    {
        if (X509_cmp_time(X509_get_notAfter(cert), &tcheck) < 0)
        {
            fprintf(stderr, "expire!");
            return 0;
        }
        //dump_cert(stderr, cert);
        //int err = X509_STORE_CTX_get_error(ctx);
        //int depth = X509_STORE_CTX_get_error_depth(ctx);
        //SSL *ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
        //X509 *cert = SSL_get_certificate(ssl)
    }
    return ok;
}
SSL_CTX *tls_ctx_init()
{
    SSL_library_init();
    //SSL_load_error_strings();
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_method());
    if (ctx != NULL)
    {
        /* const char cipher_list[] = "ALL:!EXPORT:!LOW:!MEDIUM:!ADH:!MD5";
         * SSL_CTX_set_cipher_list(ctx, cipher_list);
         * add this will SIGSEGV
         */
        SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_CLIENT_ONCE, verify_callback);
        /* We accept only certificates signed only by the CA himself */
        SSL_CTX_set_verify_depth(ctx, 1);
        SSL_CTX_set_read_ahead(ctx, 1);
    }
    sock_inner_log(DEBUG, "tls_ctx_init %p", ctx);
    return ctx;
}
void tls_ctx_free(SSL_CTX *c)
{
    SSL_CTX_free(c);
}
bool tls_ctx_ca(SSL_CTX *c, const char *file)
{
    return (1 == SSL_CTX_load_verify_locations(c, file, NULL));
}

bool tls_ctx_cert(SSL_CTX *c, const char *file)
{
    //return (1 == SSL_CTX_use_certificate_chain_file(c->tls_ctx, file));
    return (1 == SSL_CTX_use_certificate_file(c, file, SSL_FILETYPE_PEM));
}

bool tls_ctx_key(SSL_CTX *c, const char *file)
{
    return (1 == SSL_CTX_use_PrivateKey_file(c, file, SSL_FILETYPE_PEM));
}
void set_tls_ctx(connection_t *c, SSL_CTX *tls_ctx)
{
    c->tls_ctx = tls_ctx;
}
int tls_handshake(connection_t *c)
{
    int rv, ssl_err;
    ERR_clear_error();
    if ((rv = SSL_do_handshake(c->tls)) != 1)
    {
        ssl_err = SSL_get_error(c->tls, rv);
        if (ssl_err != SSL_ERROR_WANT_READ && ssl_err != SSL_ERROR_WANT_WRITE)
        {
            sock_inner_log(INFO, "handshake(%d) ssl_err is: %d, rv=%d, closed", c->sock, ssl_err, rv);
            ERR_print_errors_fp(stderr);
            return EXIT_FAILURE;
        }
    }
    else
    {
        c->handshaked = 1;
        sock_inner_log(DEBUG, "handshake(%d) OK", c->sock);
    }
    return EXIT_SUCCESS;
}

static int tls_accept(connection_t *c)
{
    if ((c->tls = SSL_new(c->tls_ctx)) == NULL)
        return EXIT_FAILURE;
    sock_inner_log(DEBUG, "(%d)first invoke tls_accept tls = [%p]", c->sock, c->tls);
    if (SSL_set_fd(c->tls, c->sock) != 1)
    {
        SSL_free(c->tls);
        c->tls = NULL;
        return EXIT_FAILURE;
    }
    SSL_set_accept_state(c->tls);
    return tls_handshake(c);
}

static int tls_connect(connection_t *c)    /*like tls_accept */
{
    if ((c->tls = SSL_new(c->tls_ctx)) == NULL)
        return EXIT_FAILURE;
    sock_inner_log(DEBUG, "(%d)first invoke tls_connect tls [%p]", c->sock, c->tls);
    if (SSL_set_fd(c->tls, c->sock) != 1)
    {
        SSL_free(c->tls);
        c->tls = NULL;
        return EXIT_FAILURE;
    }
    SSL_set_connect_state(c->tls);
    return tls_handshake(c);
}

ssize_t tls_recv(connection_t *c, void *buf, int len)
{
    int rv = SSL_read(c->tls, buf, len);
    if (rv > 0)
        return rv;
    sock_inner_log(DEBUG, "SSL_read(%d, %d) rv = %d,ssl_err=%d, errno=%d", c->sock, len, rv, SSL_get_error(c->tls, rv), errno);
    return -1;
}

static int tls_send(connection_t *c, const void *buf, int len)
{
    int rv = SSL_write(c->tls, buf, len);
    if (rv > 0)
        return rv;
    sock_inner_log(DEBUG, "SSL_write(%d) rv = %d, ssl_err=%d, %s", c->sock, rv, SSL_get_error(c->tls, rv), strerror(errno));
    return rv;
}
#endif
static int async_getfd(connection_t *c)
{
    if(c) return c->sock;
    return -1;
}

static int async_check(int fd)
{
    //For most platforms, the code below is all we need
    char junk;
    if(0 == send(fd, &junk, 0, 0))
        return 0;
    return errno;
    /*
     * see man connect
     int status;
     socklen_t len = sizeof(status);
     getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &status, &len);
     if(status)
     report_error("getsockopt(SO_ERROR)", EINVAL);
     */
}

static int async_close(connection_t *c)
{
    sock_inner_log(DEBUG, "del socket(%d) OK", c->sock);
#ifdef HAVE_TLS
    if (c->tls_ctx && c->tls)
    {
        sock_inner_log(DEBUG, "del SSL (%p) OK", c->tls);
        SSL_shutdown(c->tls);
        SSL_free(c->tls);
        c->tls = NULL;
    }
#endif
    close(c->sock);
    return EXIT_SUCCESS;
}

static ssize_t async_read(connection_t *c)
{
    int n = 0;
loop:
#ifdef HAVE_TLS
    if (c->tls_ctx && c->tls)
        while(c->nbytes<DATA_BUFFER_SIZE)
        {
            if((n = tls_recv(c, c->buffer + c->nbytes, DATA_BUFFER_SIZE - c->nbytes))>0)
            {
                c->nbytes += n;
            }
            else
                break;
        }
    else
#endif
        while(c->nbytes<DATA_BUFFER_SIZE)
        {
            if((n = read(c->sock, c->buffer + c->nbytes, DATA_BUFFER_SIZE - c->nbytes)) > 0)
            {
                c->nbytes += n;
            }
            else
                break;
        }
    if (n < 0)
    {
        if (errno == EINTR)
            goto loop;
        if (errno == EAGAIN)
        {
            sock_inner_log(DEBUG, "async_read(%x) = %d, EAGAIN", c->sock, 0);
            return c->nbytes;
        }
        sock_inner_log(DEBUG, "async_read: peer closed");
        return -1;
    }
    sock_inner_log(DEBUG, "errno = %d, async_read(%x) = %Zd", errno, c->sock, c->nbytes);
    return c->nbytes>0 ? c->nbytes : -1;/*may be a part of date arrived */
}
static ssize_t async_peekbuf(connection_t *c, const char **ptr)
{
    *ptr = c->buffer;
    return c->nbytes;
}

static ssize_t async_getbuf(connection_t *c, char *buf, int nbyte)
{
    if(!buf || nbyte ==0)
        return c->nbytes;
    int n = (c->nbytes >= nbyte ? nbyte : c->nbytes);
    memcpy(buf, c->buffer, n);
    if (c->nbytes >= nbyte)
    {
        memmove(c->buffer, c->buffer + nbyte, c->nbytes - nbyte);
        c->nbytes -= nbyte;
    }
    else
        c->nbytes = 0;
    return n;
}

static ssize_t async_write(connection_t *c, const void *buf, size_t nbyte)
{
    int n;
    for (;;)
    {
#ifdef HAVE_TLS
        if (c->tls_ctx && c->tls)
            n = tls_send(c, buf, nbyte);
        else
#endif
            n = write(c->sock, buf, nbyte);
        if (n == 0)
        {
            sock_inner_log(DEBUG, "async_write: peer closed");
            return -1;
        }
        if (errno == EINTR)
            continue;
        sock_inner_log(DEBUG, "async_write(%x, %p, %zu) = %d", c->sock, buf, nbyte, n);
        return n;
    }
    sock_inner_log(DEBUG, "async_write(%x, %p, %zu) = %d", c->sock, buf, nbyte, n);
    return n;
}

#define INIT_CONN(c) do { assert(c); memset(c, 0, sizeof(connection_t)); }while(0)
static int async_socket(connection_t *c, int domain, int type, int protocol)
{
    INIT_CONN(c);
    if((c->sock = socket(domain, type | SOCK_NONBLOCK, protocol)) == -1)
        return EXIT_FAILURE;
    return EXIT_SUCCESS; 
}

static int async_listen(connection_t *srv, int port, int backlog)
{
    int flags = 1;
    setsockopt(srv->sock, SOL_SOCKET, SO_REUSEADDR, &flags, sizeof(flags));
    srv->in_addr.sin_family = AF_INET;
    srv->in_addr.sin_port = htons(port);
    srv->in_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    srv->in_len =  sizeof(struct sockaddr_in);
    if (bind(srv->sock, (struct sockaddr *)&srv->in_addr, srv->in_len) == -1)
    {
        sock_inner_log(ERROR, "bind: %s", strerror(errno));
        return EXIT_FAILURE;
    }
    if (listen(srv->sock, backlog) < 0)
    {
        sock_inner_log(ERROR, "listen: %s", strerror(errno));
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

static int async_accept(connection_t *srv, connection_t *c)
{
    struct sockaddr_in in_addr;
    socklen_t in_len;
    in_len = sizeof(struct sockaddr);
    INIT_CONN(c);
    while ((c->sock = accept(srv->sock, (struct sockaddr *)&in_addr, &in_len)) < 0)
    {
        if (errno == EINTR)
            continue;
        return EXIT_FAILURE;
    }
    c->in_addr = in_addr;
    c->in_len = in_len;
#ifdef HAVE_TLS
    if (srv->tls_ctx)
    {
        set_tls_ctx(c, srv->tls_ctx);
        if (tls_accept(c) == EXIT_FAILURE)
        {
            async_close(c);
            return EXIT_FAILURE;
        }
    }
#endif
    return setnonblocking(c->sock);
}

static void netaddr_set(const char *name, struct sockaddr_in *addr)
{
    if ((addr->sin_addr.s_addr = inet_addr(name)) == -1)
    {
        //it's not an IP.
        //not an ip, maybe a domain
        struct hostent *host;
        host = gethostbyname(name);
        if (host)
        {
            addr->sin_addr.s_addr = *(size_t *) host->h_addr_list[0];
            sock_inner_log(DEBUG, "Get IP: %s", inet_ntoa(addr->sin_addr));
        }
        else
        {
            sock_inner_log(DEBUG, "Failed to get ip by %s", name);
        }
    }
}

static int async_connect(connection_t *c, const char *ip, ushort port)
{
    c->in_addr.sin_family = PF_INET;
    netaddr_set(ip, &c->in_addr);
    c->in_addr.sin_port = htons(port);
    c->in_len = sizeof(struct sockaddr_in);
    sock_inner_log(DEBUG, "(%d) connect to [%s:%d].", c->sock, ip == NULL ? "0.0.0.0" : ip, port);
    if (connect(c->sock, (struct sockaddr *)&c->in_addr, c->in_len) < 0)
    {
        if (errno != EINPROGRESS)
        {
            sock_inner_log(ERROR, "connect [%s:%d] %s.", ip == NULL ? "0.0.0.0" : ip, port, strerror(errno));
            return EXIT_FAILURE;
        }
    }
//    while(async_check(c->sock) == EAGAIN)
//        usleep(5);

#ifdef HAVE_TLS
    if (c->tls_ctx)
    {
        if (tls_connect(c) == EXIT_FAILURE)
        {
            sock_inner_log(ERROR, "tls_connect(%d) [%s:%d] %s.", c->sock, ip == NULL ? "0.0.0.0" : ip, port, strerror(errno));
            close(c->sock);
            return EXIT_FAILURE;
        }
    }
#endif
    return EXIT_SUCCESS;
}

static void *async_get_data(connection_t *c)
{
    return c->ctx;
}

static void async_set_data(connection_t *c, void *data)
{
    c->ctx = data;
}

struct sock_operator AsyncSocket = {
    .peekbuf = async_peekbuf,
    .getbuf = async_getbuf,
    .read = async_read,
    .write = async_write,
    .socket = async_socket,
    .listen = async_listen,
    .accept = async_accept,
    .close = async_close,
    .getfd = async_getfd,
    .connect = async_connect,
    .get_ctx = async_get_data,
    .set_ctx = async_set_data,
    .check   = async_check,
};
