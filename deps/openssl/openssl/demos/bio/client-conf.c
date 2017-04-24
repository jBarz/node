#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>

int main(int argc, char **argv)
{
    BIO *sbio = NULL, *out = NULL;
    int i, len, rv;
    char tmpbuf[1024];
    SSL_CTX *ctx = NULL;
    SSL_CONF_CTX *cctx = NULL;
    SSL *ssl = NULL;
    CONF *conf = NULL;
    STACK_OF(CONF_VALUE) *sect = NULL;
    CONF_VALUE *cnf;
    const char *connect_str = "\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x3a\x34\x34\x33\x33";
    long errline = -1;

    ERR_load_crypto_strings();
    ERR_load_SSL_strings();
    SSL_library_init();

    conf = NCONF_new(NULL);

    if (NCONF_load(conf, "\x63\x6f\x6e\x6e\x65\x63\x74\x2e\x63\x6e\x66", &errline) <= 0) {
        if (errline <= 0)
            fprintf(stderr, "\x45\x72\x72\x6f\x72\x20\x70\x72\x6f\x63\x65\x73\x73\x69\x6e\x67\x20\x63\x6f\x6e\x66\x69\x67\x20\x66\x69\x6c\x65\xa");
        else
            fprintf(stderr, "\x45\x72\x72\x6f\x72\x20\x6f\x6e\x20\x6c\x69\x6e\x65\x20\x25\x6c\x64\xa", errline);
        goto end;
    }

    sect = NCONF_get_section(conf, "\x64\x65\x66\x61\x75\x6c\x74");

    if (sect == NULL) {
        fprintf(stderr, "\x45\x72\x72\x6f\x72\x20\x72\x65\x74\x72\x69\x65\x76\x69\x6e\x67\x20\x64\x65\x66\x61\x75\x6c\x74\x20\x73\x65\x63\x74\x69\x6f\x6e\xa");
        goto end;
    }

    ctx = SSL_CTX_new(SSLv23_client_method());
    cctx = SSL_CONF_CTX_new();
    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CLIENT);
    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_FILE);
    SSL_CONF_CTX_set_ssl_ctx(cctx, ctx);
    for (i = 0; i < sk_CONF_VALUE_num(sect); i++) {
        cnf = sk_CONF_VALUE_value(sect, i);
        rv = SSL_CONF_cmd(cctx, cnf->name, cnf->value);
        if (rv > 0)
            continue;
        if (rv != -2) {
            fprintf(stderr, "\x45\x72\x72\x6f\x72\x20\x70\x72\x6f\x63\x65\x73\x73\x69\x6e\x67\x20\x25\x73\x20\x3d\x20\x25\x73\xa",
                    cnf->name, cnf->value);
            ERR_print_errors_fp(stderr);
            goto end;
        }
        if (!strcmp(cnf->name, "\x43\x6f\x6e\x6e\x65\x63\x74")) {
            connect_str = cnf->value;
        } else {
            fprintf(stderr, "\x55\x6e\x6b\x6e\x6f\x77\x6e\x20\x63\x6f\x6e\x66\x69\x67\x75\x72\x61\x74\x69\x6f\x6e\x20\x6f\x70\x74\x69\x6f\x6e\x20\x25\x73\xa", cnf->name);
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
    NCONF_free(conf);
    return 0;
}
