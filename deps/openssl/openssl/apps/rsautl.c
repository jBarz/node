/* rsautl.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2000.
 */
/* ====================================================================
 * Copyright (c) 2000 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "\x4f\x70\x65\x6e\x53\x53\x4c\x20\x54\x6f\x6f\x6c\x6b\x69\x74" and "\x4f\x70\x65\x6e\x53\x53\x4c\x20\x50\x72\x6f\x6a\x65\x63\x74" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "\x4f\x70\x65\x6e\x53\x53\x4c"
 *    nor may "\x4f\x70\x65\x6e\x53\x53\x4c" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_RSA

# include "apps.h"
# include <string.h>
# include <openssl/err.h>
# include <openssl/pem.h>
# include <openssl/rsa.h>

# define RSA_SIGN        1
# define RSA_VERIFY      2
# define RSA_ENCRYPT     3
# define RSA_DECRYPT     4

# define KEY_PRIVKEY     1
# define KEY_PUBKEY      2
# define KEY_CERT        3

static void usage(void);

# undef PROG

# define PROG rsautl_main

int MAIN(int argc, char **);

int MAIN(int argc, char **argv)
{
    ENGINE *e = NULL;
    BIO *in = NULL, *out = NULL;
    char *infile = NULL, *outfile = NULL;
    char *engine = NULL;
    char *keyfile = NULL;
    char rsa_mode = RSA_VERIFY, key_type = KEY_PRIVKEY;
    int keyform = FORMAT_PEM;
    char need_priv = 0, badarg = 0, rev = 0;
    char hexdump = 0, asn1parse = 0;
    X509 *x;
    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;
    unsigned char *rsa_in = NULL, *rsa_out = NULL, pad;
    char *passargin = NULL, *passin = NULL;
    int rsa_inlen, rsa_outlen = 0;
    int keysize;

    int ret = 1;

    argc--;
    argv++;

    if (!bio_err)
        bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

    if (!load_config(bio_err, NULL))
        goto end;
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    pad = RSA_PKCS1_PADDING;

    while (argc >= 1) {
        if (!strcmp(*argv, "\x2d\x69\x6e")) {
            if (--argc < 1)
                badarg = 1;
            else
                infile = *(++argv);
        } else if (!strcmp(*argv, "\x2d\x6f\x75\x74")) {
            if (--argc < 1)
                badarg = 1;
            else
                outfile = *(++argv);
        } else if (!strcmp(*argv, "\x2d\x69\x6e\x6b\x65\x79")) {
            if (--argc < 1)
                badarg = 1;
            else
                keyfile = *(++argv);
        } else if (!strcmp(*argv, "\x2d\x70\x61\x73\x73\x69\x6e")) {
            if (--argc < 1)
                badarg = 1;
            else
                passargin = *(++argv);
        } else if (strcmp(*argv, "\x2d\x6b\x65\x79\x66\x6f\x72\x6d") == 0) {
            if (--argc < 1)
                badarg = 1;
            else
                keyform = str2fmt(*(++argv));
# ifndef OPENSSL_NO_ENGINE
        } else if (!strcmp(*argv, "\x2d\x65\x6e\x67\x69\x6e\x65")) {
            if (--argc < 1)
                badarg = 1;
            else
                engine = *(++argv);
# endif
        } else if (!strcmp(*argv, "\x2d\x70\x75\x62\x69\x6e")) {
            key_type = KEY_PUBKEY;
        } else if (!strcmp(*argv, "\x2d\x63\x65\x72\x74\x69\x6e")) {
            key_type = KEY_CERT;
        } else if (!strcmp(*argv, "\x2d\x61\x73\x6e\x31\x70\x61\x72\x73\x65"))
            asn1parse = 1;
        else if (!strcmp(*argv, "\x2d\x68\x65\x78\x64\x75\x6d\x70"))
            hexdump = 1;
        else if (!strcmp(*argv, "\x2d\x72\x61\x77"))
            pad = RSA_NO_PADDING;
        else if (!strcmp(*argv, "\x2d\x6f\x61\x65\x70"))
            pad = RSA_PKCS1_OAEP_PADDING;
        else if (!strcmp(*argv, "\x2d\x73\x73\x6c"))
            pad = RSA_SSLV23_PADDING;
        else if (!strcmp(*argv, "\x2d\x70\x6b\x63\x73"))
            pad = RSA_PKCS1_PADDING;
        else if (!strcmp(*argv, "\x2d\x78\x39\x33\x31"))
            pad = RSA_X931_PADDING;
        else if (!strcmp(*argv, "\x2d\x73\x69\x67\x6e")) {
            rsa_mode = RSA_SIGN;
            need_priv = 1;
        } else if (!strcmp(*argv, "\x2d\x76\x65\x72\x69\x66\x79"))
            rsa_mode = RSA_VERIFY;
        else if (!strcmp(*argv, "\x2d\x72\x65\x76"))
            rev = 1;
        else if (!strcmp(*argv, "\x2d\x65\x6e\x63\x72\x79\x70\x74"))
            rsa_mode = RSA_ENCRYPT;
        else if (!strcmp(*argv, "\x2d\x64\x65\x63\x72\x79\x70\x74")) {
            rsa_mode = RSA_DECRYPT;
            need_priv = 1;
        } else
            badarg = 1;
        if (badarg) {
            usage();
            goto end;
        }
        argc--;
        argv++;
    }

    if (need_priv && (key_type != KEY_PRIVKEY)) {
        BIO_printf(bio_err, "\x41\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\x20\x69\x73\x20\x6e\x65\x65\x64\x65\x64\x20\x66\x6f\x72\x20\x74\x68\x69\x73\x20\x6f\x70\x65\x72\x61\x74\x69\x6f\x6e\xa");
        goto end;
    }
    e = setup_engine(bio_err, engine, 0);
    if (!app_passwd(bio_err, passargin, NULL, &passin, NULL)) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x67\x65\x74\x74\x69\x6e\x67\x20\x70\x61\x73\x73\x77\x6f\x72\x64\xa");
        goto end;
    }

/* FIXME: seed PRNG only if needed */
    app_RAND_load_file(NULL, bio_err, 0);

    switch (key_type) {
    case KEY_PRIVKEY:
        pkey = load_key(bio_err, keyfile, keyform, 0,
                        passin, e, "\x50\x72\x69\x76\x61\x74\x65\x20\x4b\x65\x79");
        break;

    case KEY_PUBKEY:
        pkey = load_pubkey(bio_err, keyfile, keyform, 0,
                           NULL, e, "\x50\x75\x62\x6c\x69\x63\x20\x4b\x65\x79");
        break;

    case KEY_CERT:
        x = load_cert(bio_err, keyfile, keyform, NULL, e, "\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65");
        if (x) {
            pkey = X509_get_pubkey(x);
            X509_free(x);
        }
        break;
    }

    if (!pkey) {
        return 1;
    }

    rsa = EVP_PKEY_get1_RSA(pkey);
    EVP_PKEY_free(pkey);

    if (!rsa) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x67\x65\x74\x74\x69\x6e\x67\x20\x52\x53\x41\x20\x6b\x65\x79\xa");
        ERR_print_errors(bio_err);
        goto end;
    }

    if (infile) {
        if (!(in = BIO_new_file(infile, "\x72\x62"))) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x52\x65\x61\x64\x69\x6e\x67\x20\x49\x6e\x70\x75\x74\x20\x46\x69\x6c\x65\xa");
            ERR_print_errors(bio_err);
            goto end;
        }
    } else
        in = BIO_new_fp(stdin, BIO_NOCLOSE);

    if (outfile) {
        if (!(out = BIO_new_file(outfile, "\x77\x62"))) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x57\x72\x69\x74\x69\x6e\x67\x20\x4f\x75\x74\x70\x75\x74\x20\x46\x69\x6c\x65\xa");
            ERR_print_errors(bio_err);
            goto end;
        }
    } else {
        out = BIO_new_fp(stdout, BIO_NOCLOSE);
# ifdef OPENSSL_SYS_VMS
        {
            BIO *tmpbio = BIO_new(BIO_f_linebuffer());
            out = BIO_push(tmpbio, out);
        }
# endif
    }

    keysize = RSA_size(rsa);

    rsa_in = OPENSSL_malloc(keysize * 2);
    rsa_out = OPENSSL_malloc(keysize);
    if (!rsa_in || !rsa_out) {
        BIO_printf(bio_err, "\x4f\x75\x74\x20\x6f\x66\x20\x6d\x65\x6d\x6f\x72\x79\xa");
        ERR_print_errors(bio_err);
        goto end;
    }

    /* Read the input data */
    rsa_inlen = BIO_read(in, rsa_in, keysize * 2);
    if (rsa_inlen < 0) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x72\x65\x61\x64\x69\x6e\x67\x20\x69\x6e\x70\x75\x74\x20\x44\x61\x74\x61\xa");
        exit(1);
    }
    if (rev) {
        int i;
        unsigned char ctmp;
        for (i = 0; i < rsa_inlen / 2; i++) {
            ctmp = rsa_in[i];
            rsa_in[i] = rsa_in[rsa_inlen - 1 - i];
            rsa_in[rsa_inlen - 1 - i] = ctmp;
        }
    }
    switch (rsa_mode) {

    case RSA_VERIFY:
        rsa_outlen = RSA_public_decrypt(rsa_inlen, rsa_in, rsa_out, rsa, pad);
        break;

    case RSA_SIGN:
        rsa_outlen =
            RSA_private_encrypt(rsa_inlen, rsa_in, rsa_out, rsa, pad);
        break;

    case RSA_ENCRYPT:
        rsa_outlen = RSA_public_encrypt(rsa_inlen, rsa_in, rsa_out, rsa, pad);
        break;

    case RSA_DECRYPT:
        rsa_outlen =
            RSA_private_decrypt(rsa_inlen, rsa_in, rsa_out, rsa, pad);
        break;

    }

    if (rsa_outlen < 0) {
        BIO_printf(bio_err, "\x52\x53\x41\x20\x6f\x70\x65\x72\x61\x74\x69\x6f\x6e\x20\x65\x72\x72\x6f\x72\xa");
        ERR_print_errors(bio_err);
        goto end;
    }
    ret = 0;
    if (asn1parse) {
        if (!ASN1_parse_dump(out, rsa_out, rsa_outlen, 1, -1)) {
            ERR_print_errors(bio_err);
        }
    } else if (hexdump)
        BIO_dump(out, (char *)rsa_out, rsa_outlen);
    else
        BIO_write(out, rsa_out, rsa_outlen);
 end:
    RSA_free(rsa);
    release_engine(e);
    BIO_free(in);
    BIO_free_all(out);
    if (rsa_in)
        OPENSSL_free(rsa_in);
    if (rsa_out)
        OPENSSL_free(rsa_out);
    if (passin)
        OPENSSL_free(passin);
    return ret;
}

static void usage()
{
    BIO_printf(bio_err, "\x55\x73\x61\x67\x65\x3a\x20\x72\x73\x61\x75\x74\x6c\x20\x5b\x6f\x70\x74\x69\x6f\x6e\x73\x5d\xa");
    BIO_printf(bio_err, "\x2d\x69\x6e\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x20\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x66\x69\x6c\x65\xa");
    BIO_printf(bio_err, "\x2d\x6f\x75\x74\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x20\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\xa");
    BIO_printf(bio_err, "\x2d\x69\x6e\x6b\x65\x79\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x6b\x65\x79\xa");
    BIO_printf(bio_err, "\x2d\x6b\x65\x79\x66\x6f\x72\x6d\x20\x61\x72\x67\x20\x20\x20\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\x20\x66\x6f\x72\x6d\x61\x74\x20\x2d\x20\x64\x65\x66\x61\x75\x6c\x74\x20\x50\x45\x4d\xa");
    BIO_printf(bio_err, "\x2d\x70\x75\x62\x69\x6e\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x69\x73\x20\x61\x6e\x20\x52\x53\x41\x20\x70\x75\x62\x6c\x69\x63\xa");
    BIO_printf(bio_err,
               "\x2d\x63\x65\x72\x74\x69\x6e\x20\x20\x20\x20\x20\x20\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x69\x73\x20\x61\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x63\x61\x72\x72\x79\x69\x6e\x67\x20\x61\x6e\x20\x52\x53\x41\x20\x70\x75\x62\x6c\x69\x63\x20\x6b\x65\x79\xa");
    BIO_printf(bio_err, "\x2d\x73\x73\x6c\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x75\x73\x65\x20\x53\x53\x4c\x20\x76\x32\x20\x70\x61\x64\x64\x69\x6e\x67\xa");
    BIO_printf(bio_err, "\x2d\x72\x61\x77\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x75\x73\x65\x20\x6e\x6f\x20\x70\x61\x64\x64\x69\x6e\x67\xa");
    BIO_printf(bio_err,
               "\x2d\x70\x6b\x63\x73\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x75\x73\x65\x20\x50\x4b\x43\x53\x23\x31\x20\x76\x31\x2e\x35\x20\x70\x61\x64\x64\x69\x6e\x67\x20\x28\x64\x65\x66\x61\x75\x6c\x74\x29\xa");
    BIO_printf(bio_err, "\x2d\x6f\x61\x65\x70\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x75\x73\x65\x20\x50\x4b\x43\x53\x23\x31\x20\x4f\x41\x45\x50\xa");
    BIO_printf(bio_err, "\x2d\x73\x69\x67\x6e\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x73\x69\x67\x6e\x20\x77\x69\x74\x68\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\xa");
    BIO_printf(bio_err, "\x2d\x76\x65\x72\x69\x66\x79\x20\x20\x20\x20\x20\x20\x20\x20\x20\x76\x65\x72\x69\x66\x79\x20\x77\x69\x74\x68\x20\x70\x75\x62\x6c\x69\x63\x20\x6b\x65\x79\xa");
    BIO_printf(bio_err, "\x2d\x65\x6e\x63\x72\x79\x70\x74\x20\x20\x20\x20\x20\x20\x20\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x77\x69\x74\x68\x20\x70\x75\x62\x6c\x69\x63\x20\x6b\x65\x79\xa");
    BIO_printf(bio_err, "\x2d\x64\x65\x63\x72\x79\x70\x74\x20\x20\x20\x20\x20\x20\x20\x20\x64\x65\x63\x72\x79\x70\x74\x20\x77\x69\x74\x68\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\xa");
    BIO_printf(bio_err, "\x2d\x68\x65\x78\x64\x75\x6d\x70\x20\x20\x20\x20\x20\x20\x20\x20\x68\x65\x78\x20\x64\x75\x6d\x70\x20\x6f\x75\x74\x70\x75\x74\xa");
# ifndef OPENSSL_NO_ENGINE
    BIO_printf(bio_err,
               "\x2d\x65\x6e\x67\x69\x6e\x65\x20\x65\x20\x20\x20\x20\x20\x20\x20\x75\x73\x65\x20\x65\x6e\x67\x69\x6e\x65\x20\x65\x2c\x20\x70\x6f\x73\x73\x69\x62\x6c\x79\x20\x61\x20\x68\x61\x72\x64\x77\x61\x72\x65\x20\x64\x65\x76\x69\x63\x65\x2e\xa");
    BIO_printf(bio_err, "\x2d\x70\x61\x73\x73\x69\x6e\x20\x61\x72\x67\x20\x20\x20\x20\x70\x61\x73\x73\x20\x70\x68\x72\x61\x73\x65\x20\x73\x6f\x75\x72\x63\x65\xa");
# endif

}

#else                           /* !OPENSSL_NO_RSA */

# if PEDANTIC
static void *dummy = &dummy;
# endif

#endif
