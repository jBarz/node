/* NOCW */
/* demos/bio/saccept-conf.c */

/*
 * A minimal program to serve an SSL connection. It uses blocking. It uses
 * the SSL_CONF API with a configuration file. cc -I../../include saccept.c
 * -L../.. -lssl -lcrypto -ldl
 */

#include <stdio.h>
#include <signal.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>

int main(int argc, char *argv[])
{
    char *port = "\x2a\x3a\x34\x34\x33\x33";
    BIO *in = NULL;
    BIO *ssl_bio, *tmp;
    SSL_CTX *ctx;
    SSL_CONF_CTX *cctx = NULL;
    CONF *conf = NULL;
    STACK_OF(CONF_VALUE) *sect = NULL;
    CONF_VALUE *cnf;
    long errline = -1;
    char buf[512];
    int ret = 1, i;

    SSL_load_error_strings();

    /* Add ciphers and message digests */
    OpenSSL_add_ssl_algorithms();

    conf = NCONF_new(NULL);

    if (NCONF_load(conf, "\x61\x63\x63\x65\x70\x74\x2e\x63\x6e\x66", &errline) <= 0) {
        if (errline <= 0)
            fprintf(stderr, "\x45\x72\x72\x6f\x72\x20\x70\x72\x6f\x63\x65\x73\x73\x69\x6e\x67\x20\x63\x6f\x6e\x66\x69\x67\x20\x66\x69\x6c\x65\xa");
        else
            fprintf(stderr, "\x45\x72\x72\x6f\x72\x20\x6f\x6e\x20\x6c\x69\x6e\x65\x20\x25\x6c\x64\xa", errline);
        goto err;
    }

    sect = NCONF_get_section(conf, "\x64\x65\x66\x61\x75\x6c\x74");

    if (sect == NULL) {
        fprintf(stderr, "\x45\x72\x72\x6f\x72\x20\x72\x65\x74\x72\x69\x65\x76\x69\x6e\x67\x20\x64\x65\x66\x61\x75\x6c\x74\x20\x73\x65\x63\x74\x69\x6f\x6e\xa");
        goto err;
    }

    ctx = SSL_CTX_new(SSLv23_server_method());
    cctx = SSL_CONF_CTX_new();
    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_SERVER);
    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CERTIFICATE);
    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_FILE);
    SSL_CONF_CTX_set_ssl_ctx(cctx, ctx);
    for (i = 0; i < sk_CONF_VALUE_num(sect); i++) {
        int rv;
        cnf = sk_CONF_VALUE_value(sect, i);
        rv = SSL_CONF_cmd(cctx, cnf->name, cnf->value);
        if (rv > 0)
            continue;
        if (rv != -2) {
            fprintf(stderr, "\x45\x72\x72\x6f\x72\x20\x70\x72\x6f\x63\x65\x73\x73\x69\x6e\x67\x20\x25\x73\x20\x3d\x20\x25\x73\xa",
                    cnf->name, cnf->value);
            ERR_print_errors_fp(stderr);
            goto err;
        }
        if (!strcmp(cnf->name, "\x50\x6f\x72\x74")) {
            port = cnf->value;
        } else {
            fprintf(stderr, "\x55\x6e\x6b\x6e\x6f\x77\x6e\x20\x63\x6f\x6e\x66\x69\x67\x75\x72\x61\x74\x69\x6f\x6e\x20\x6f\x70\x74\x69\x6f\x6e\x20\x25\x73\xa", cnf->name);
            goto err;
        }
    }

    if (!SSL_CONF_CTX_finish(cctx)) {
        fprintf(stderr, "\x46\x69\x6e\x69\x73\x68\x20\x65\x72\x72\x6f\x72\xa");
        ERR_print_errors_fp(stderr);
        goto err;
    }

    /* Setup server side SSL bio */
    ssl_bio = BIO_new_ssl(ctx, 0);

    if ((in = BIO_new_accept(port)) == NULL)
        goto err;

    /*
     * This means that when a new connection is accepted on 'in', The ssl_bio
     * will be 'duplicated' and have the new socket BIO push into it.
     * Basically it means the SSL BIO will be automatically setup
     */
    BIO_set_accept_bios(in, ssl_bio);

 again:
    /*
     * The first call will setup the accept socket, and the second will get a
     * socket.  In this loop, the first actual accept will occur in the
     * BIO_read() function.
     */

    if (BIO_do_accept(in) <= 0)
        goto err;

    for (;;) {
        i = BIO_read(in, buf, 512);
        if (i == 0) {
            /*
             * If we have finished, remove the underlying BIO stack so the
             * next time we call any function for this BIO, it will attempt
             * to do an accept
             */
            printf("\x44\x6f\x6e\x65\xa");
            tmp = BIO_pop(in);
            BIO_free_all(tmp);
            goto again;
        }
        if (i < 0) {
            if (BIO_should_retry(in))
                continue;
            goto err;
        }
        fwrite(buf, 1, i, stdout);
        fflush(stdout);
    }

    ret = 0;
 err:
    if (ret) {
        ERR_print_errors_fp(stderr);
    }
    if (in != NULL)
        BIO_free(in);
    exit(ret);
    return (!ret);
}
