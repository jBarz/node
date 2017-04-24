/* Simple S/MIME signing example */
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL, *tbio = NULL;
    X509 *scert = NULL;
    EVP_PKEY *skey = NULL;
    PKCS7 *p7 = NULL;
    int ret = 1;

    /*
     * For simple S/MIME signing use PKCS7_DETACHED. On OpenSSL 0.9.9 only:
     * for streaming detached set PKCS7_DETACHED|PKCS7_STREAM for streaming
     * non-detached set PKCS7_STREAM
     */
    int flags = PKCS7_DETACHED | PKCS7_STREAM;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Read in signer certificate and private key */
    tbio = BIO_new_file("\x73\x69\x67\x6e\x65\x72\x2e\x70\x65\x6d", "\x72");

    if (!tbio)
        goto err;

    scert = PEM_read_bio_X509(tbio, NULL, 0, NULL);

    BIO_reset(tbio);

    skey = PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);

    if (!scert || !skey)
        goto err;

    /* Open content being signed */

    in = BIO_new_file("\x73\x69\x67\x6e\x2e\x74\x78\x74", "\x72");

    if (!in)
        goto err;

    /* Sign content */
    p7 = PKCS7_sign(scert, skey, NULL, in, flags);

    if (!p7)
        goto err;

    out = BIO_new_file("\x73\x6d\x6f\x75\x74\x2e\x74\x78\x74", "\x77");
    if (!out)
        goto err;

    if (!(flags & PKCS7_STREAM))
        BIO_reset(in);

    /* Write out S/MIME message */
    if (!SMIME_write_PKCS7(out, p7, in, flags))
        goto err;

    ret = 0;

 err:

    if (ret) {
        fprintf(stderr, "\x45\x72\x72\x6f\x72\x20\x53\x69\x67\x6e\x69\x6e\x67\x20\x44\x61\x74\x61\xa");
        ERR_print_errors_fp(stderr);
    }

    if (p7)
        PKCS7_free(p7);
    if (scert)
        X509_free(scert);
    if (skey)
        EVP_PKEY_free(skey);

    if (in)
        BIO_free(in);
    if (out)
        BIO_free(out);
    if (tbio)
        BIO_free(tbio);

    return ret;

}
