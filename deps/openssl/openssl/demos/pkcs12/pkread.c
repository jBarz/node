/* pkread.c */

#include <stdio.h>
#include <stdlib.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>

/* Simple PKCS#12 file reader */

int main(int argc, char **argv)
{
    FILE *fp;
    EVP_PKEY *pkey;
    X509 *cert;
    STACK_OF(X509) *ca = NULL;
    PKCS12 *p12;
    int i;
    if (argc != 4) {
        fprintf(stderr, "\x55\x73\x61\x67\x65\x3a\x20\x70\x6b\x72\x65\x61\x64\x20\x70\x31\x32\x66\x69\x6c\x65\x20\x70\x61\x73\x73\x77\x6f\x72\x64\x20\x6f\x70\x66\x69\x6c\x65\xa");
        exit(1);
    }
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    if (!(fp = fopen(argv[1], "\x72\x62"))) {
        fprintf(stderr, "\x45\x72\x72\x6f\x72\x20\x6f\x70\x65\x6e\x69\x6e\x67\x20\x66\x69\x6c\x65\x20\x25\x73\xa", argv[1]);
        exit(1);
    }
    p12 = d2i_PKCS12_fp(fp, NULL);
    fclose(fp);
    if (!p12) {
        fprintf(stderr, "\x45\x72\x72\x6f\x72\x20\x72\x65\x61\x64\x69\x6e\x67\x20\x50\x4b\x43\x53\x23\x31\x32\x20\x66\x69\x6c\x65\xa");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if (!PKCS12_parse(p12, argv[2], &pkey, &cert, &ca)) {
        fprintf(stderr, "\x45\x72\x72\x6f\x72\x20\x70\x61\x72\x73\x69\x6e\x67\x20\x50\x4b\x43\x53\x23\x31\x32\x20\x66\x69\x6c\x65\xa");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    PKCS12_free(p12);
    if (!(fp = fopen(argv[3], "\x77"))) {
        fprintf(stderr, "\x45\x72\x72\x6f\x72\x20\x6f\x70\x65\x6e\x69\x6e\x67\x20\x66\x69\x6c\x65\x20\x25\x73\xa", argv[1]);
        exit(1);
    }
    if (pkey) {
        fprintf(fp, "\x2a\x2a\x2a\x50\x72\x69\x76\x61\x74\x65\x20\x4b\x65\x79\x2a\x2a\x2a\xa");
        PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
    }
    if (cert) {
        fprintf(fp, "\x2a\x2a\x2a\x55\x73\x65\x72\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x2a\x2a\x2a\xa");
        PEM_write_X509_AUX(fp, cert);
    }
    if (ca && sk_X509_num(ca)) {
        fprintf(fp, "\x2a\x2a\x2a\x4f\x74\x68\x65\x72\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73\x2a\x2a\x2a\xa");
        for (i = 0; i < sk_X509_num(ca); i++)
            PEM_write_X509_AUX(fp, sk_X509_value(ca, i));
    }
    fclose(fp);
    return 0;
}
