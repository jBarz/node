#include <openssl/err.h>
#include <openssl/ssl.h>

int main(int argc, char **argv)
{
    BIO *sbio = NULL, *out = NULL;
    int len;
    char tmpbuf[1024];
    SSL_CTX *ctx;
    SSL_CONF_CTX *cctx;
    SSL *ssl;
    char **args = argv + 1;
    const char *connect_str = "\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x3a\x34\x34\x33\x33";
    int nargs = argc - 1;

    ERR_load_crypto_strings();
    ERR_load_SSL_strings();
    SSL_library_init();

    ctx = SSL_CTX_new(SSLv23_client_method());
    cctx = SSL_CONF_CTX_new();
    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CLIENT);
    SSL_CONF_CTX_set_ssl_ctx(cctx, ctx);
    while (*args && **args == '\x2d') {
        int rv;
        /* Parse standard arguments */
        rv = SSL_CONF_cmd_argv(cctx, &nargs, &args);
        if (rv == -3) {
            fprintf(stderr, "\x4d\x69\x73\x73\x69\x6e\x67\x20\x61\x72\x67\x75\x6d\x65\x6e\x74\x20\x66\x6f\x72\x20\x25\x73\xa", *args);
            goto end;
        }
        if (rv < 0) {
            fprintf(stderr, "\x45\x72\x72\x6f\x72\x20\x69\x6e\x20\x63\x6f\x6d\x6d\x61\x6e\x64\x20\x25\x73\xa", *args);
            ERR_print_errors_fp(stderr);
            goto end;
        }
        /* If rv > 0 we processed something so proceed to next arg */
        if (rv > 0)
            continue;
        /* Otherwise application specific argument processing */
        if (!strcmp(*args, "\x2d\x63\x6f\x6e\x6e\x65\x63\x74")) {
            connect_str = args[1];
            if (connect_str == NULL) {
                fprintf(stderr, "\x4d\x69\x73\x73\x69\x6e\x67\x20\x2d\x63\x6f\x6e\x6e\x65\x63\x74\x20\x61\x72\x67\x75\x6d\x65\x6e\x74\xa");
                goto end;
            }
            args += 2;
            nargs -= 2;
            continue;
        } else {
            fprintf(stderr, "\x55\x6e\x6b\x6e\x6f\x77\x6e\x20\x61\x72\x67\x75\x6d\x65\x6e\x74\x20\x25\x73\xa", *args);
            goto end;
        }
    }

    if (!SSL_CONF_CTX_finish(cctx)) {
        fprintf(stderr, "\x46\x69\x6e\x69\x73\x68\x20\x65\x72\x72\x6f\x72\xa");
        ERR_print_errors_fp(stderr);
        goto err;
    }

    /*
     * We'd normally set some stuff like the verify paths and * mode here
     * because as things stand this will connect to * any server whose
     * certificate is signed by any CA.
     */

    sbio = BIO_new_ssl_connect(ctx);

    BIO_get_ssl(sbio, &ssl);

    if (!ssl) {
        fprintf(stderr, "\x43\x61\x6e\x27\x74\x20\x6c\x6f\x63\x61\x74\x65\x20\x53\x53\x4c\x20\x70\x6f\x69\x6e\x74\x65\x72\xa");
        goto end;
    }

    /* Don't want any retries */
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    /* We might want to do other things with ssl here */

    BIO_set_conn_hostname(sbio, connect_str);

    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (BIO_do_connect(sbio) <= 0) {
        fprintf(stderr, "\x45\x72\x72\x6f\x72\x20\x63\x6f\x6e\x6e\x65\x63\x74\x69\x6e\x67\x20\x74\x6f\x20\x73\x65\x72\x76\x65\x72\xa");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    if (BIO_do_handshake(sbio) <= 0) {
        fprintf(stderr, "\x45\x72\x72\x6f\x72\x20\x65\x73\x74\x61\x62\x6c\x69\x73\x68\x69\x6e\x67\x20\x53\x53\x4c\x20\x63\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\xa");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    /* Could examine ssl here to get connection info */

    BIO_puts(sbio, "\x47\x45\x54\x20\x2f\x20\x48\x54\x54\x50\x2f\x31\x2e\x30\xa\xa");
    for (;;) {
        len = BIO_read(sbio, tmpbuf, 1024);
        if (len <= 0)
            break;
        BIO_write(out, tmpbuf, len);
    }
 end:
    SSL_CONF_CTX_free(cctx);
    BIO_free_all(sbio);
    BIO_free(out);
    return 0;
}
