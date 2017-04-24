/* Simple S/MIME uncompression example */
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL;
    CMS_ContentInfo *cms = NULL;
    int ret = 1;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Open compressed content */

    in = BIO_new_file("\x73\x6d\x63\x6f\x6d\x70\x2e\x74\x78\x74", "\x72");

    if (!in)
        goto err;

    /* Sign content */
    cms = SMIME_read_CMS(in, NULL);

    if (!cms)
        goto err;

    out = BIO_new_file("\x73\x6d\x75\x6e\x63\x6f\x6d\x70\x2e\x74\x78\x74", "\x77");
    if (!out)
        goto err;

    /* Uncompress S/MIME message */
    if (!CMS_uncompress(cms, out, NULL, 0))
        goto err;

    ret = 0;

 err:

    if (ret) {
        fprintf(stderr, "\x45\x72\x72\x6f\x72\x20\x55\x6e\x63\x6f\x6d\x70\x72\x65\x73\x73\x69\x6e\x67\x20\x44\x61\x74\x61\xa");
        ERR_print_errors_fp(stderr);
    }

    if (cms)
        CMS_ContentInfo_free(cms);

    if (in)
        BIO_free(in);
    if (out)
        BIO_free(out);

    return ret;

}
