/* NOCW */
/* demos/bio/sconnect.c */

/*-
 * A minimal program to do SSL to a passed host and port.
 * It is actually using non-blocking IO but in a very simple manner
 * sconnect host:port - it does a 'GET / HTTP/1.0'
 *
 * cc -I../../include sconnect.c -L../.. -lssl -lcrypto
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

extern int errno;

int main(argc, argv)
int argc;
char *argv[];
{
    char *host;
    BIO *out;
    char buf[1024 * 10], *p;
    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl;
    BIO *ssl_bio;
    int i, len, off, ret = 1;

    if (argc <= 1)
        host = "\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x3a\x34\x34\x33\x33";
    else
        host = argv[1];

#ifdef WATT32
    dbug_init();
    sock_init();
#endif

    /* Lets get nice error messages */
    SSL_load_error_strings();

    /* Setup all the global SSL stuff */
    OpenSSL_add_ssl_algorithms();
    ssl_ctx = SSL_CTX_new(SSLv23_client_method());

    /* Lets make a SSL structure */
    ssl = SSL_new(ssl_ctx);
    SSL_set_connect_state(ssl);

    /* Use it inside an SSL BIO */
    ssl_bio = BIO_new(BIO_f_ssl());
    BIO_set_ssl(ssl_bio, ssl, BIO_CLOSE);

    /* Lets use a connect BIO under the SSL BIO */
    out = BIO_new(BIO_s_connect());
    BIO_set_conn_hostname(out, host);
    BIO_set_nbio(out, 1);
    out = BIO_push(ssl_bio, out);

    p = "\x47\x45\x54\x20\x2f\x20\x48\x54\x54\x50\x2f\x31\x2e\x30\xd\xa\xd\xa";
    len = strlen(p);

    off = 0;
    for (;;) {
        i = BIO_write(out, &(p[off]), len);
        if (i <= 0) {
            if (BIO_should_retry(out)) {
                fprintf(stderr, "\x77\x72\x69\x74\x65\x20\x44\x45\x4c\x41\x59\xa");
                sleep(1);
                continue;
            } else {
                goto err;
            }
        }
        off += i;
        len -= i;
        if (len <= 0)
            break;
    }

    for (;;) {
        i = BIO_read(out, buf, sizeof(buf));
        if (i == 0)
            break;
        if (i < 0) {
            if (BIO_should_retry(out)) {
                fprintf(stderr, "\x72\x65\x61\x64\x20\x44\x45\x4c\x41\x59\xa");
                sleep(1);
                continue;
            }
            goto err;
        }
        fwrite(buf, 1, i, stdout);
    }

    ret = 1;

    if (0) {
 err:
        if (ERR_peek_error() == 0) { /* system call error */
            fprintf(stderr, "\x65\x72\x72\x6e\x6f\x3d\x25\x64\x20", errno);
            perror("\x65\x72\x72\x6f\x72");
        } else
            ERR_print_errors_fp(stderr);
    }
    BIO_free_all(out);
    if (ssl_ctx != NULL)
        SSL_CTX_free(ssl_ctx);
    exit(!ret);
    return (ret);
}
