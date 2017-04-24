/* pkwrite.c */

#include <stdio.h>
#include <stdlib.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>

/* Simple PKCS#12 file creator */

int main(int argc, char **argv)
{
    FILE *fp;
    EVP_PKEY *pkey;
    X509 *cert;
    PKCS12 *p12;
    if (argc != 5) {
        fprintf(stderr, "\x55\x73\x61\x67\x65\x3a\x20\x70\x6b\x77\x72\x69\x74\x65\x20\x69\x6e\x66\x69\x6c\x65\x20\x70\x61\x73\x73\x77\x6f\x72\x64\x20\x6e\x61\x6d\x65\x20\x70\x31\x32\x66\x69\x6c\x65\xa");
        exit(1);
    }
    SSLeay_add_all_algorithms();
    ERR_load_crypto_strings();
    if (!(fp = fopen(argv[1], "\x72"))) {
        fprintf(stderr, "\x45\x72\x72\x6f\x72\x20\x6f\x70\x65\x6e\x69\x6e\x67\x20\x66\x69\x6c\x65\x20\x25\x73\xa", argv[1]);
        exit(1);
    }
    cert = PEM_read_X509(fp, NULL, NULL, NULL);
    rewind(fp);
    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    p12 = PKCS12_create(argv[2], argv[3], pkey, cert, NULL, 0, 0, 0, 0, 0);
    if (!p12) {
        fprintf(stderr, "\x45\x72\x72\x6f\x72\x20\x63\x72\x65\x61\x74\x69\x6e\x67\x20\x50\x4b\x43\x53\x23\x31\x32\x20\x73\x74\x72\x75\x63\x74\x75\x72\x65\xa");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if (!(fp = fopen(argv[4], "\x77\x62"))) {
        fprintf(stderr, "\x45\x72\x72\x6f\x72\x20\x6f\x70\x65\x6e\x69\x6e\x67\x20\x66\x69\x6c\x65\x20\x25\x73\xa", argv[1]);
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    i2d_PKCS12_fp(fp, p12);
    PKCS12_free(p12);
    fclose(fp);
    return 0;
}
