/* apps/crl.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "\x54\x68\x69\x73\x20\x70\x72\x6f\x64\x75\x63\x74\x20\x69\x6e\x63\x6c\x75\x64\x65\x73\x20\x73\x6f\x66\x74\x77\x61\x72\x65\x20\x77\x72\x69\x74\x74\x65\x6e\x20\x62\x79\x20\x54\x69\x6d\x20\x48\x75\x64\x73\x6f\x6e\x20\x28\x74\x6a\x68\x40\x63\x72\x79\x70\x74\x73\x6f\x66\x74\x2e\x63\x6f\x6d\x29"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "apps.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

#undef PROG
#define PROG    crl_main

#undef POSTFIX
#define POSTFIX "\x2e\x72\x76\x6b"

static const char *crl_usage[] = {
    "\x75\x73\x61\x67\x65\x3a\x20\x63\x72\x6c\x20\x61\x72\x67\x73\xa",
    "\xa",
    "\x20\x2d\x69\x6e\x66\x6f\x72\x6d\x20\x61\x72\x67\x20\x20\x20\x20\x20\x2d\x20\x69\x6e\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x2d\x20\x64\x65\x66\x61\x75\x6c\x74\x20\x50\x45\x4d\x20\x28\x44\x45\x52\x20\x6f\x72\x20\x50\x45\x4d\x29\xa",
    "\x20\x2d\x6f\x75\x74\x66\x6f\x72\x6d\x20\x61\x72\x67\x20\x20\x20\x20\x2d\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x2d\x20\x64\x65\x66\x61\x75\x6c\x74\x20\x50\x45\x4d\xa",
    "\x20\x2d\x74\x65\x78\x74\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x70\x72\x69\x6e\x74\x20\x6f\x75\x74\x20\x61\x20\x74\x65\x78\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x76\x65\x72\x73\x69\x6f\x6e\xa",
    "\x20\x2d\x69\x6e\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x69\x6e\x70\x75\x74\x20\x66\x69\x6c\x65\x20\x2d\x20\x64\x65\x66\x61\x75\x6c\x74\x20\x73\x74\x64\x69\x6e\xa",
    "\x20\x2d\x6f\x75\x74\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\x20\x2d\x20\x64\x65\x66\x61\x75\x6c\x74\x20\x73\x74\x64\x6f\x75\x74\xa",
    "\x20\x2d\x68\x61\x73\x68\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x70\x72\x69\x6e\x74\x20\x68\x61\x73\x68\x20\x76\x61\x6c\x75\x65\xa",
#ifndef OPENSSL_NO_MD5
    "\x20\x2d\x68\x61\x73\x68\x5f\x6f\x6c\x64\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x70\x72\x69\x6e\x74\x20\x6f\x6c\x64\x2d\x73\x74\x79\x6c\x65\x20\x28\x4d\x44\x35\x29\x20\x68\x61\x73\x68\x20\x76\x61\x6c\x75\x65\xa",
#endif
    "\x20\x2d\x66\x69\x6e\x67\x65\x72\x70\x72\x69\x6e\x74\x20\x20\x20\x20\x2d\x20\x70\x72\x69\x6e\x74\x20\x74\x68\x65\x20\x63\x72\x6c\x20\x66\x69\x6e\x67\x65\x72\x70\x72\x69\x6e\x74\xa",
    "\x20\x2d\x69\x73\x73\x75\x65\x72\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x70\x72\x69\x6e\x74\x20\x69\x73\x73\x75\x65\x72\x20\x44\x4e\xa",
    "\x20\x2d\x6c\x61\x73\x74\x75\x70\x64\x61\x74\x65\x20\x20\x20\x20\x20\x2d\x20\x6c\x61\x73\x74\x55\x70\x64\x61\x74\x65\x20\x66\x69\x65\x6c\x64\xa",
    "\x20\x2d\x6e\x65\x78\x74\x75\x70\x64\x61\x74\x65\x20\x20\x20\x20\x20\x2d\x20\x6e\x65\x78\x74\x55\x70\x64\x61\x74\x65\x20\x66\x69\x65\x6c\x64\xa",
    "\x20\x2d\x63\x72\x6c\x6e\x75\x6d\x62\x65\x72\x20\x20\x20\x20\x20\x20\x2d\x20\x70\x72\x69\x6e\x74\x20\x43\x52\x4c\x20\x6e\x75\x6d\x62\x65\x72\xa",
    "\x20\x2d\x6e\x6f\x6f\x75\x74\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x6e\x6f\x20\x43\x52\x4c\x20\x6f\x75\x74\x70\x75\x74\xa",
    "\x20\x2d\x43\x41\x66\x69\x6c\x65\x20\x20\x6e\x61\x6d\x65\x20\x20\x20\x2d\x20\x76\x65\x72\x69\x66\x79\x20\x43\x52\x4c\x20\x75\x73\x69\x6e\x67\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73\x20\x69\x6e\x20\x66\x69\x6c\x65\x20\x22\x6e\x61\x6d\x65\x22\xa",
    "\x20\x2d\x43\x41\x70\x61\x74\x68\x20\x20\x64\x69\x72\x20\x20\x20\x20\x2d\x20\x76\x65\x72\x69\x66\x79\x20\x43\x52\x4c\x20\x75\x73\x69\x6e\x67\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73\x20\x69\x6e\x20\x22\x64\x69\x72\x22\xa",
    "\x20\x2d\x6e\x61\x6d\x65\x6f\x70\x74\x20\x61\x72\x67\x20\x20\x20\x20\x2d\x20\x76\x61\x72\x69\x6f\x75\x73\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x6e\x61\x6d\x65\x20\x6f\x70\x74\x69\x6f\x6e\x73\xa",
    NULL
};

static BIO *bio_out = NULL;

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    unsigned long nmflag = 0;
    X509_CRL *x = NULL;
    char *CAfile = NULL, *CApath = NULL;
    int ret = 1, i, num, badops = 0, badsig = 0;
    BIO *out = NULL;
    int informat, outformat, keyformat;
    char *infile = NULL, *outfile = NULL, *crldiff = NULL, *keyfile = NULL;
    int hash = 0, issuer = 0, lastupdate = 0, nextupdate = 0, noout =
        0, text = 0;
#ifndef OPENSSL_NO_MD5
    int hash_old = 0;
#endif
    int fingerprint = 0, crlnumber = 0;
    const char **pp;
    X509_STORE *store = NULL;
    X509_STORE_CTX ctx;
    X509_LOOKUP *lookup = NULL;
    X509_OBJECT xobj;
    EVP_PKEY *pkey;
    int do_ver = 0;
    const EVP_MD *md_alg, *digest = EVP_sha1();

    apps_startup();

    if (bio_err == NULL)
        if ((bio_err = BIO_new(BIO_s_file())) != NULL)
            BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    if (!load_config(bio_err, NULL))
        goto end;

    if (bio_out == NULL)
        if ((bio_out = BIO_new(BIO_s_file())) != NULL) {
            BIO_set_fp(bio_out, stdout, BIO_NOCLOSE);
#ifdef OPENSSL_SYS_VMS
            {
                BIO *tmpbio = BIO_new(BIO_f_linebuffer());
                bio_out = BIO_push(tmpbio, bio_out);
            }
#endif
        }

    informat = FORMAT_PEM;
    outformat = FORMAT_PEM;
    keyformat = FORMAT_PEM;

    argc--;
    argv++;
    num = 0;
    while (argc >= 1) {
#ifdef undef
        if (strcmp(*argv, "\x2d\x70") == 0) {
            if (--argc < 1)
                goto bad;
            if (!args_from_file(++argv, Nargc, Nargv)) {
                goto end;
            }
        */}
#endif
        if (strcmp(*argv, "\x2d\x69\x6e\x66\x6f\x72\x6d") == 0) {
            if (--argc < 1)
                goto bad;
            informat = str2fmt(*(++argv));
        } else if (strcmp(*argv, "\x2d\x6f\x75\x74\x66\x6f\x72\x6d") == 0) {
            if (--argc < 1)
                goto bad;
            outformat = str2fmt(*(++argv));
        } else if (strcmp(*argv, "\x2d\x69\x6e") == 0) {
            if (--argc < 1)
                goto bad;
            infile = *(++argv);
        } else if (strcmp(*argv, "\x2d\x67\x65\x6e\x64\x65\x6c\x74\x61") == 0) {
            if (--argc < 1)
                goto bad;
            crldiff = *(++argv);
        } else if (strcmp(*argv, "\x2d\x6b\x65\x79") == 0) {
            if (--argc < 1)
                goto bad;
            keyfile = *(++argv);
        } else if (strcmp(*argv, "\x2d\x6b\x65\x79\x66\x6f\x72\x6d") == 0) {
            if (--argc < 1)
                goto bad;
            keyformat = str2fmt(*(++argv));
        } else if (strcmp(*argv, "\x2d\x6f\x75\x74") == 0) {
            if (--argc < 1)
                goto bad;
            outfile = *(++argv);
        } else if (strcmp(*argv, "\x2d\x43\x41\x70\x61\x74\x68") == 0) {
            if (--argc < 1)
                goto bad;
            CApath = *(++argv);
            do_ver = 1;
        } else if (strcmp(*argv, "\x2d\x43\x41\x66\x69\x6c\x65") == 0) {
            if (--argc < 1)
                goto bad;
            CAfile = *(++argv);
            do_ver = 1;
        } else if (strcmp(*argv, "\x2d\x76\x65\x72\x69\x66\x79") == 0)
            do_ver = 1;
        else if (strcmp(*argv, "\x2d\x74\x65\x78\x74") == 0)
            text = 1;
        else if (strcmp(*argv, "\x2d\x68\x61\x73\x68") == 0)
            hash = ++num;
#ifndef OPENSSL_NO_MD5
        else if (strcmp(*argv, "\x2d\x68\x61\x73\x68\x5f\x6f\x6c\x64") == 0)
            hash_old = ++num;
#endif
        else if (strcmp(*argv, "\x2d\x6e\x61\x6d\x65\x6f\x70\x74") == 0) {
            if (--argc < 1)
                goto bad;
            if (!set_name_ex(&nmflag, *(++argv)))
                goto bad;
        } else if (strcmp(*argv, "\x2d\x69\x73\x73\x75\x65\x72") == 0)
            issuer = ++num;
        else if (strcmp(*argv, "\x2d\x6c\x61\x73\x74\x75\x70\x64\x61\x74\x65") == 0)
            lastupdate = ++num;
        else if (strcmp(*argv, "\x2d\x6e\x65\x78\x74\x75\x70\x64\x61\x74\x65") == 0)
            nextupdate = ++num;
        else if (strcmp(*argv, "\x2d\x6e\x6f\x6f\x75\x74") == 0)
            noout = ++num;
        else if (strcmp(*argv, "\x2d\x66\x69\x6e\x67\x65\x72\x70\x72\x69\x6e\x74") == 0)
            fingerprint = ++num;
        else if (strcmp(*argv, "\x2d\x63\x72\x6c\x6e\x75\x6d\x62\x65\x72") == 0)
            crlnumber = ++num;
        else if (strcmp(*argv, "\x2d\x62\x61\x64\x73\x69\x67") == 0)
            badsig = 1;
        else if ((md_alg = EVP_get_digestbyname(*argv + 1))) {
            /* ok */
            digest = md_alg;
        } else {
            BIO_printf(bio_err, "\x75\x6e\x6b\x6e\x6f\x77\x6e\x20\x6f\x70\x74\x69\x6f\x6e\x20\x25\x73\xa", *argv);
            badops = 1;
            break;
        }
        argc--;
        argv++;
    }

    if (badops) {
 bad:
        for (pp = crl_usage; (*pp != NULL); pp++)
            BIO_printf(bio_err, "\x25\x73", *pp);
        goto end;
    }

    ERR_load_crypto_strings();
    x = load_crl(infile, informat);
    if (x == NULL) {
        goto end;
    }

    if (do_ver) {
        store = X509_STORE_new();
        lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
        if (lookup == NULL)
            goto end;
        if (!X509_LOOKUP_load_file(lookup, CAfile, X509_FILETYPE_PEM))
            X509_LOOKUP_load_file(lookup, NULL, X509_FILETYPE_DEFAULT);

        lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
        if (lookup == NULL)
            goto end;
        if (!X509_LOOKUP_add_dir(lookup, CApath, X509_FILETYPE_PEM))
            X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);
        ERR_clear_error();

        if (!X509_STORE_CTX_init(&ctx, store, NULL, NULL)) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x69\x6e\x69\x74\x69\x61\x6c\x69\x73\x69\x6e\x67\x20\x58\x35\x30\x39\x20\x73\x74\x6f\x72\x65\xa");
            goto end;
        }

        i = X509_STORE_get_by_subject(&ctx, X509_LU_X509,
                                      X509_CRL_get_issuer(x), &xobj);
        if (i <= 0) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x67\x65\x74\x74\x69\x6e\x67\x20\x43\x52\x4c\x20\x69\x73\x73\x75\x65\x72\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\xa");
            goto end;
        }
        pkey = X509_get_pubkey(xobj.data.x509);
        X509_OBJECT_free_contents(&xobj);
        if (!pkey) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x67\x65\x74\x74\x69\x6e\x67\x20\x43\x52\x4c\x20\x69\x73\x73\x75\x65\x72\x20\x70\x75\x62\x6c\x69\x63\x20\x6b\x65\x79\xa");
            goto end;
        }
        i = X509_CRL_verify(x, pkey);
        EVP_PKEY_free(pkey);
        if (i < 0)
            goto end;
        if (i == 0)
            BIO_printf(bio_err, "\x76\x65\x72\x69\x66\x79\x20\x66\x61\x69\x6c\x75\x72\x65\xa");
        else
            BIO_printf(bio_err, "\x76\x65\x72\x69\x66\x79\x20\x4f\x4b\xa");
    }

    if (crldiff) {
        X509_CRL *newcrl, *delta;
        if (!keyfile) {
            BIO_puts(bio_err, "\x4d\x69\x73\x73\x69\x6e\x67\x20\x43\x52\x4c\x20\x73\x69\x67\x6e\x69\x6e\x67\x20\x6b\x65\x79\xa");
            goto end;
        }
        newcrl = load_crl(crldiff, informat);
        if (!newcrl)
            goto end;
        pkey = load_key(bio_err, keyfile, keyformat, 0, NULL, NULL,
                        "\x43\x52\x4c\x20\x73\x69\x67\x6e\x69\x6e\x67\x20\x6b\x65\x79");
        if (!pkey) {
            X509_CRL_free(newcrl);
            goto end;
        }
        delta = X509_CRL_diff(x, newcrl, pkey, digest, 0);
        X509_CRL_free(newcrl);
        EVP_PKEY_free(pkey);
        if (delta) {
            X509_CRL_free(x);
            x = delta;
        } else {
            BIO_puts(bio_err, "\x45\x72\x72\x6f\x72\x20\x63\x72\x65\x61\x74\x69\x6e\x67\x20\x64\x65\x6c\x74\x61\x20\x43\x52\x4c\xa");
            goto end;
        }
    }

    if (num) {
        for (i = 1; i <= num; i++) {
            if (issuer == i) {
                print_name(bio_out, "\x69\x73\x73\x75\x65\x72\x3d", X509_CRL_get_issuer(x),
                           nmflag);
            }
            if (crlnumber == i) {
                ASN1_INTEGER *crlnum;
                crlnum = X509_CRL_get_ext_d2i(x, NID_crl_number, NULL, NULL);
                BIO_printf(bio_out, "\x63\x72\x6c\x4e\x75\x6d\x62\x65\x72\x3d");
                if (crlnum) {
                    i2a_ASN1_INTEGER(bio_out, crlnum);
                    ASN1_INTEGER_free(crlnum);
                } else
                    BIO_puts(bio_out, "\x3c\x4e\x4f\x4e\x45\x3e");
                BIO_printf(bio_out, "\xa");
            }
            if (hash == i) {
                BIO_printf(bio_out, "\x25\x30\x38\x6c\x78\xa",
                           X509_NAME_hash(X509_CRL_get_issuer(x)));
            }
#ifndef OPENSSL_NO_MD5
            if (hash_old == i) {
                BIO_printf(bio_out, "\x25\x30\x38\x6c\x78\xa",
                           X509_NAME_hash_old(X509_CRL_get_issuer(x)));
            }
#endif
            if (lastupdate == i) {
                BIO_printf(bio_out, "\x6c\x61\x73\x74\x55\x70\x64\x61\x74\x65\x3d");
                ASN1_TIME_print(bio_out, X509_CRL_get_lastUpdate(x));
                BIO_printf(bio_out, "\xa");
            }
            if (nextupdate == i) {
                BIO_printf(bio_out, "\x6e\x65\x78\x74\x55\x70\x64\x61\x74\x65\x3d");
                if (X509_CRL_get_nextUpdate(x))
                    ASN1_TIME_print(bio_out, X509_CRL_get_nextUpdate(x));
                else
                    BIO_printf(bio_out, "\x4e\x4f\x4e\x45");
                BIO_printf(bio_out, "\xa");
            }
            if (fingerprint == i) {
                int j;
                unsigned int n;
                unsigned char md[EVP_MAX_MD_SIZE];

                if (!X509_CRL_digest(x, digest, md, &n)) {
                    BIO_printf(bio_err, "\x6f\x75\x74\x20\x6f\x66\x20\x6d\x65\x6d\x6f\x72\x79\xa");
                    goto end;
                }
                BIO_printf(bio_out, "\x25\x73\x20\x46\x69\x6e\x67\x65\x72\x70\x72\x69\x6e\x74\x3d",
                           OBJ_nid2sn(EVP_MD_type(digest)));
                for (j = 0; j < (int)n; j++) {
                    BIO_printf(bio_out, "\x25\x30\x32\x58\x25\x63", md[j], (j + 1 == (int)n)
                               ? '\xa' : '\x3a');
                }
            }
        }
    }

    out = BIO_new(BIO_s_file());
    if (out == NULL) {
        ERR_print_errors(bio_err);
        goto end;
    }

    if (outfile == NULL) {
        BIO_set_fp(out, stdout, BIO_NOCLOSE);
#ifdef OPENSSL_SYS_VMS
        {
            BIO *tmpbio = BIO_new(BIO_f_linebuffer());
            out = BIO_push(tmpbio, out);
        }
#endif
    } else {
        if (BIO_write_filename(out, outfile) <= 0) {
            perror(outfile);
            goto end;
        }
    }

    if (text)
        X509_CRL_print(out, x);

    if (noout) {
        ret = 0;
        goto end;
    }

    if (badsig)
        x->signature->data[x->signature->length - 1] ^= 0x1;

    if (outformat == FORMAT_ASN1)
        i = (int)i2d_X509_CRL_bio(out, x);
    else if (outformat == FORMAT_PEM)
        i = PEM_write_bio_X509_CRL(out, x);
    else {
        BIO_printf(bio_err, "\x62\x61\x64\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\x20\x66\x6f\x72\x20\x6f\x75\x74\x66\x69\x6c\x65\xa");
        goto end;
    }
    if (!i) {
        BIO_printf(bio_err, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x77\x72\x69\x74\x65\x20\x43\x52\x4c\xa");
        goto end;
    }
    ret = 0;
 end:
    if (ret != 0)
        ERR_print_errors(bio_err);
    BIO_free_all(out);
    BIO_free_all(bio_out);
    bio_out = NULL;
    X509_CRL_free(x);
    if (store) {
        X509_STORE_CTX_cleanup(&ctx);
        X509_STORE_free(store);
    }
    apps_shutdown();
    OPENSSL_EXIT(ret);
}
