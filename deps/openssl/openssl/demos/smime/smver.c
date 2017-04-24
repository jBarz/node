/* Simple S/MIME verification example */
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL, *tbio = NULL, *cont = NULL;
    X509_STORE *st = NULL;
    X509 *cacert = NULL;
    PKCS7 *p7 = NULL;

    int ret = 1;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Set up trusted CA certificate store */

    st = X509_STORE_new();

    /* Read in signer certificate and private key */
    tbio = BIO_new_file("\x63\x61\x63\x65\x72\x74\x2e\x70\x65\x6d", "\x72");

    if (!tbio)
        goto err;

    cacert = PEM_read_bio_X509(tbio, NULL, 0, NULL);

    if (!cacert)
        goto err;

    if (!X509_STORE_add_cert(st, cacert))
        goto err;

    /* Open content being signed */

    in = BIO_new_file("\x73\x6d\x6f\x75\x74\x2e\x74\x78\x74", "\x72");

    if (!in)
        goto err;

    /* Sign content */
    p7 = SMIME_read_PKCS7(in, &cont);

    if (!p7)
        goto err;

    /* File to output verified content to */
    out = BIO_new_file("\x73\x6d\x76\x65\x72\x2e\x74\x78\x74", "\x77");
    if (!out)
        goto err;

    if (!PKCS7_verify(p7, NULL, st, cont, out, 0)) {
        fprintf(stderr, "\x56\x65\x72\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x20\x46\x61\x69\x6c\x75\x72\x65\xa");
        goto err;
    }

    fprintf(stderr, "\x56\x65\x72\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x20\x53\x75\x63\x63\x65\x73\x73\x66\x75\x6c\xa");

    ret = 0;

 err:

    if (ret) {
        fprintf(stderr, "\x45\x72\x72\x6f\x72\x20\x56\x65\x72\x69\x66\x79\x69\x6e\x67\x20\x44\x61\x74\x61\xa");
        ERR_print_errors_fp(stderr);
    }

    if (p7)
        PKCS7_free(p7);

    if (cacert)
        X509_free(cacert);

    if (in)
        BIO_free(in);
    if (out)
        BIO_free(out);
    if (tbio)
        BIO_free(tbio);

    return ret;

}
