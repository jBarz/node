/* NOCW */
/* cc -o ssdemo -I../include selfsign.c ../libcrypto.a */

#include <stdio.h>
#include <stdlib.h>

#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>

int mkit(X509 **x509p, EVP_PKEY **pkeyp, int bits, int serial, int days);

int main()
{
    BIO *bio_err;
    X509 *x509 = NULL;
    EVP_PKEY *pkey = NULL;

    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

    mkit(&x509, &pkey, 512, 0, 365);

    RSA_print_fp(stdout, pkey->pkey.rsa, 0);
    X509_print_fp(stdout, x509);

    PEM_write_PrivateKey(stdout, pkey, NULL, NULL, 0, NULL, NULL);
    PEM_write_X509(stdout, x509);

    X509_free(x509);
    EVP_PKEY_free(pkey);

#ifdef CUSTOM_EXT
    /* Only needed if we add objects or custom extensions */
    X509V3_EXT_cleanup();
    OBJ_cleanup();
#endif

    CRYPTO_mem_leaks(bio_err);
    BIO_free(bio_err);
    return (0);
}

#ifdef WIN16
# define MS_CALLBACK   _far _loadds
# define MS_FAR        _far
#else
# define MS_CALLBACK
# define MS_FAR
#endif

static void MS_CALLBACK callback(p, n, arg)
int p;
int n;
void *arg;
{
    char c = '\x42';

    if (p == 0)
        c = '\x2e';
    if (p == 1)
        c = '\x2b';
    if (p == 2)
        c = '\x2a';
    if (p == 3)
        c = '\xa';
    fputc(c, stderr);
}

int mkit(x509p, pkeyp, bits, serial, days)
X509 **x509p;
EVP_PKEY **pkeyp;
int bits;
int serial;
int days;
{
    X509 *x;
    EVP_PKEY *pk;
    RSA *rsa;
    X509_NAME *name = NULL;
    X509_NAME_ENTRY *ne = NULL;
    X509_EXTENSION *ex = NULL;

    if ((pkeyp == NULL) || (*pkeyp == NULL)) {
        if ((pk = EVP_PKEY_new()) == NULL) {
            abort();
            return (0);
        }
    } else
        pk = *pkeyp;

    if ((x509p == NULL) || (*x509p == NULL)) {
        if ((x = X509_new()) == NULL)
            goto err;
    } else
        x = *x509p;

    rsa = RSA_generate_key(bits, RSA_F4, callback, NULL);
    if (!EVP_PKEY_assign_RSA(pk, rsa)) {
        abort();
        goto err;
    }
    rsa = NULL;

    X509_set_version(x, 3);
    ASN1_INTEGER_set(X509_get_serialNumber(x), serial);
    X509_gmtime_adj(X509_get_notBefore(x), 0);
    X509_gmtime_adj(X509_get_notAfter(x), (long)60 * 60 * 24 * days);
    X509_set_pubkey(x, pk);

    name = X509_get_subject_name(x);

    /*
     * This function creates and adds the entry, working out the correct
     * string type and performing checks on its length. Normally we'd check
     * the return value for errors...
     */
    X509_NAME_add_entry_by_txt(name, "\x43", MBSTRING_ASC, "\x55\x4b", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "\x43\x4e",
                               MBSTRING_ASC, "\x4f\x70\x65\x6e\x53\x53\x4c\x20\x47\x72\x6f\x75\x70", -1, -1, 0);

    X509_set_issuer_name(x, name);

    /*
     * Add extension using V3 code: we can set the config file as NULL
     * because we wont reference any other sections. We can also set the
     * context to NULL because none of these extensions below will need to
     * access it.
     */

    ex = X509V3_EXT_conf_nid(NULL, NULL, NID_netscape_cert_type, "\x73\x65\x72\x76\x65\x72");
    X509_add_ext(x, ex, -1);
    X509_EXTENSION_free(ex);

    ex = X509V3_EXT_conf_nid(NULL, NULL, NID_netscape_comment,
                             "\x65\x78\x61\x6d\x70\x6c\x65\x20\x63\x6f\x6d\x6d\x65\x6e\x74\x20\x65\x78\x74\x65\x6e\x73\x69\x6f\x6e");
    X509_add_ext(x, ex, -1);
    X509_EXTENSION_free(ex);

    ex = X509V3_EXT_conf_nid(NULL, NULL, NID_netscape_ssl_server_name,
                             "\x77\x77\x77\x2e\x6f\x70\x65\x6e\x73\x73\x6c\x2e\x6f\x72\x67");

    X509_add_ext(x, ex, -1);
    X509_EXTENSION_free(ex);

#if 0
    /* might want something like this too.... */
    ex = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints,
                             "\x63\x72\x69\x74\x69\x63\x61\x6c\x2c\x43\x41\x3a\x54\x52\x55\x45");

    X509_add_ext(x, ex, -1);
    X509_EXTENSION_free(ex);
#endif

#ifdef CUSTOM_EXT
    /* Maybe even add our own extension based on existing */
    {
        int nid;
        nid = OBJ_create("\x31\x2e\x32\x2e\x33\x2e\x34", "\x4d\x79\x41\x6c\x69\x61\x73", "\x4d\x79\x20\x54\x65\x73\x74\x20\x41\x6c\x69\x61\x73\x20\x45\x78\x74\x65\x6e\x73\x69\x6f\x6e");
        X509V3_EXT_add_alias(nid, NID_netscape_comment);
        ex = X509V3_EXT_conf_nid(NULL, NULL, nid, "\x65\x78\x61\x6d\x70\x6c\x65\x20\x63\x6f\x6d\x6d\x65\x6e\x74\x20\x61\x6c\x69\x61\x73");
        X509_add_ext(x, ex, -1);
        X509_EXTENSION_free(ex);
    }
#endif

    if (!X509_sign(x, pk, EVP_md5()))
        goto err;

    *x509p = x;
    *pkeyp = pk;
    return (1);
 err:
    return (0);
}
