/*
 * Certificate request creation. Demonstrates some request related
 * operations.
 */

#include <stdio.h>
#include <stdlib.h>

#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif

int mkreq(X509_REQ **x509p, EVP_PKEY **pkeyp, int bits, int serial, int days);
int add_ext(STACK_OF(X509_EXTENSION) *sk, int nid, char *value);

int main(int argc, char **argv)
{
    BIO *bio_err;
    X509_REQ *req = NULL;
    EVP_PKEY *pkey = NULL;

    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

    mkreq(&req, &pkey, 512, 0, 365);

    RSA_print_fp(stdout, pkey->pkey.rsa, 0);
    X509_REQ_print_fp(stdout, req);

    PEM_write_X509_REQ(stdout, req);

    X509_REQ_free(req);
    EVP_PKEY_free(pkey);

#ifndef OPENSSL_NO_ENGINE
    ENGINE_cleanup();
#endif
    CRYPTO_cleanup_all_ex_data();

    CRYPTO_mem_leaks(bio_err);
    BIO_free(bio_err);
    return (0);
}

static void callback(int p, int n, void *arg)
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

int mkreq(X509_REQ **req, EVP_PKEY **pkeyp, int bits, int serial, int days)
{
    X509_REQ *x;
    EVP_PKEY *pk;
    RSA *rsa;
    X509_NAME *name = NULL;
    STACK_OF(X509_EXTENSION) *exts = NULL;

    if ((pk = EVP_PKEY_new()) == NULL)
        goto err;

    if ((x = X509_REQ_new()) == NULL)
        goto err;

    rsa = RSA_generate_key(bits, RSA_F4, callback, NULL);
    if (!EVP_PKEY_assign_RSA(pk, rsa))
        goto err;

    rsa = NULL;

    X509_REQ_set_pubkey(x, pk);

    name = X509_REQ_get_subject_name(x);

    /*
     * This function creates and adds the entry, working out the correct
     * string type and performing checks on its length. Normally we'd check
     * the return value for errors...
     */
    X509_NAME_add_entry_by_txt(name, "\x43", MBSTRING_ASC, "\x55\x4b", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "\x43\x4e",
                               MBSTRING_ASC, "\x4f\x70\x65\x6e\x53\x53\x4c\x20\x47\x72\x6f\x75\x70", -1, -1, 0);

#ifdef REQUEST_EXTENSIONS
    /*
     * Certificate requests can contain extensions, which can be used to
     * indicate the extensions the requestor would like added to their
     * certificate. CAs might ignore them however or even choke if they are
     * present.
     */

    /*
     * For request extensions they are all packed in a single attribute. We
     * save them in a STACK and add them all at once later...
     */

    exts = sk_X509_EXTENSION_new_null();
    /* Standard extenions */

    add_ext(exts, NID_key_usage, "\x63\x72\x69\x74\x69\x63\x61\x6c\x2c\x64\x69\x67\x69\x74\x61\x6c\x53\x69\x67\x6e\x61\x74\x75\x72\x65\x2c\x6b\x65\x79\x45\x6e\x63\x69\x70\x68\x65\x72\x6d\x65\x6e\x74");

    /*
     * This is a typical use for request extensions: requesting a value for
     * subject alternative name.
     */

    add_ext(exts, NID_subject_alt_name, "\x65\x6d\x61\x69\x6c\x3a\x73\x74\x65\x76\x65\x40\x6f\x70\x65\x6e\x73\x73\x6c\x2e\x6f\x72\x67");

    /* Some Netscape specific extensions */
    add_ext(exts, NID_netscape_cert_type, "\x63\x6c\x69\x65\x6e\x74\x2c\x65\x6d\x61\x69\x6c");

# ifdef CUSTOM_EXT
    /* Maybe even add our own extension based on existing */
    {
        int nid;
        nid = OBJ_create("\x31\x2e\x32\x2e\x33\x2e\x34", "\x4d\x79\x41\x6c\x69\x61\x73", "\x4d\x79\x20\x54\x65\x73\x74\x20\x41\x6c\x69\x61\x73\x20\x45\x78\x74\x65\x6e\x73\x69\x6f\x6e");
        X509V3_EXT_add_alias(nid, NID_netscape_comment);
        add_ext(x, nid, "\x65\x78\x61\x6d\x70\x6c\x65\x20\x63\x6f\x6d\x6d\x65\x6e\x74\x20\x61\x6c\x69\x61\x73");
    }
# endif

    /* Now we've created the extensions we add them to the request */

    X509_REQ_add_extensions(x, exts);

    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

#endif

    if (!X509_REQ_sign(x, pk, EVP_sha1()))
        goto err;

    *req = x;
    *pkeyp = pk;
    return (1);
 err:
    return (0);
}

/*
 * Add extension using V3 code: we can set the config file as NULL because we
 * wont reference any other sections.
 */

int add_ext(STACK_OF(X509_EXTENSION) *sk, int nid, char *value)
{
    X509_EXTENSION *ex;
    ex = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
    if (!ex)
        return 0;
    sk_X509_EXTENSION_push(sk, ex);

    return 1;
}
