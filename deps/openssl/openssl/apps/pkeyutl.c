/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2006.
 */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
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

#include "apps.h"
#include <string.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#define KEY_PRIVKEY     1
#define KEY_PUBKEY      2
#define KEY_CERT        3

static void usage(void);

#undef PROG

#define PROG pkeyutl_main

static EVP_PKEY_CTX *init_ctx(int *pkeysize,
                              const char *keyfile, int keyform, int key_type,
                              char *passargin, int pkey_op, ENGINE *e,
                              int   impl);

static int setup_peer(BIO *err, EVP_PKEY_CTX *ctx, int peerform,
                      const char *file, ENGINE* e);

static int do_keyop(EVP_PKEY_CTX *ctx, int pkey_op,
                    unsigned char *out, size_t *poutlen,
                    unsigned char *in, size_t inlen);

int MAIN(int argc, char **);

int MAIN(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL;
    char *infile = NULL, *outfile = NULL, *sigfile = NULL;
    ENGINE *e = NULL;
    int pkey_op = EVP_PKEY_OP_SIGN, key_type = KEY_PRIVKEY;
    int keyform = FORMAT_PEM, peerform = FORMAT_PEM;
    char badarg = 0, rev = 0;
    char hexdump = 0, asn1parse = 0;
    EVP_PKEY_CTX *ctx = NULL;
    char *passargin = NULL;
    int keysize = -1;
    int engine_impl = 0;
    unsigned char *buf_in = NULL, *buf_out = NULL, *sig = NULL;
    size_t buf_outlen = 0;
    int buf_inlen = 0, siglen = -1;
    const char *inkey = NULL;
    const char *peerkey = NULL;
    STACK_OF(OPENSSL_STRING) *pkeyopts = NULL;

    int ret = 1, rv = -1;

    argc--;
    argv++;

    if (!bio_err)
        bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

    if (!load_config(bio_err, NULL))
        goto end;
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

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
        } else if (!strcmp(*argv, "\x2d\x73\x69\x67\x66\x69\x6c\x65")) {
            if (--argc < 1)
                badarg = 1;
            else
                sigfile = *(++argv);
        } else if (!strcmp(*argv, "\x2d\x69\x6e\x6b\x65\x79")) {
            if (--argc < 1)
                badarg = 1;
            else
                inkey = *++argv;
        } else if (!strcmp(*argv, "\x2d\x70\x65\x65\x72\x6b\x65\x79")) {
            if (--argc < 1)
                badarg = 1;
            else
                peerkey = *++argv;
        } else if (!strcmp(*argv, "\x2d\x70\x61\x73\x73\x69\x6e")) {
            if (--argc < 1)
                badarg = 1;
            else
                passargin = *(++argv);
        } else if (strcmp(*argv, "\x2d\x70\x65\x65\x72\x66\x6f\x72\x6d") == 0) {
            if (--argc < 1)
                badarg = 1;
            else
                peerform = str2fmt(*(++argv));
        } else if (strcmp(*argv, "\x2d\x6b\x65\x79\x66\x6f\x72\x6d") == 0) {
            if (--argc < 1)
                badarg = 1;
            else
                keyform = str2fmt(*(++argv));
        }
#ifndef OPENSSL_NO_ENGINE
        else if (!strcmp(*argv, "\x2d\x65\x6e\x67\x69\x6e\x65")) {
            if (--argc < 1)
                badarg = 1;
            else
                e = setup_engine(bio_err, *(++argv), 0);
        } else if (!strcmp(*argv, "\x2d\x65\x6e\x67\x69\x6e\x65\x5f\x69\x6d\x70\x6c")) {
                engine_impl = 1;
        }
#endif
        else if (!strcmp(*argv, "\x2d\x70\x75\x62\x69\x6e"))
            key_type = KEY_PUBKEY;
        else if (!strcmp(*argv, "\x2d\x63\x65\x72\x74\x69\x6e"))
            key_type = KEY_CERT;
        else if (!strcmp(*argv, "\x2d\x61\x73\x6e\x31\x70\x61\x72\x73\x65"))
            asn1parse = 1;
        else if (!strcmp(*argv, "\x2d\x68\x65\x78\x64\x75\x6d\x70"))
            hexdump = 1;
        else if (!strcmp(*argv, "\x2d\x73\x69\x67\x6e"))
            pkey_op = EVP_PKEY_OP_SIGN;
        else if (!strcmp(*argv, "\x2d\x76\x65\x72\x69\x66\x79"))
            pkey_op = EVP_PKEY_OP_VERIFY;
        else if (!strcmp(*argv, "\x2d\x76\x65\x72\x69\x66\x79\x72\x65\x63\x6f\x76\x65\x72"))
            pkey_op = EVP_PKEY_OP_VERIFYRECOVER;
        else if (!strcmp(*argv, "\x2d\x65\x6e\x63\x72\x79\x70\x74"))
            pkey_op = EVP_PKEY_OP_ENCRYPT;
        else if (!strcmp(*argv, "\x2d\x64\x65\x63\x72\x79\x70\x74"))
            pkey_op = EVP_PKEY_OP_DECRYPT;
        else if (!strcmp(*argv, "\x2d\x64\x65\x72\x69\x76\x65"))
            pkey_op = EVP_PKEY_OP_DERIVE;
        else if (!strcmp(*argv, "\x2d\x72\x65\x76"))
            rev = 1;
        else if (strcmp(*argv, "\x2d\x70\x6b\x65\x79\x6f\x70\x74") == 0) {
            if (--argc < 1)
                badarg = 1;
            else if ((pkeyopts == NULL &&
                     (pkeyopts = sk_OPENSSL_STRING_new_null()) == NULL) ||
                    sk_OPENSSL_STRING_push(pkeyopts, *++argv) == 0) {
                BIO_puts(bio_err, "\x6f\x75\x74\x20\x6f\x66\x20\x6d\x65\x6d\x6f\x72\x79\xa");
                goto end;
            }
        } else
            badarg = 1;
        if (badarg) {
            usage();
            goto end;
        }
        argc--;
        argv++;
    }

    if (inkey == NULL ||
        (peerkey != NULL && pkey_op != EVP_PKEY_OP_DERIVE)) {
        usage();
        goto end;
    }
    ctx = init_ctx(&keysize, inkey, keyform, key_type,
                   passargin, pkey_op, e, engine_impl);
    if (!ctx) {
        BIO_puts(bio_err, "\x45\x72\x72\x6f\x72\x20\x69\x6e\x69\x74\x69\x61\x6c\x69\x7a\x69\x6e\x67\x20\x63\x6f\x6e\x74\x65\x78\x74\xa");
        ERR_print_errors(bio_err);
        goto end;
    }
    if (peerkey != NULL && !setup_peer(bio_err, ctx, peerform, peerkey, e)) {
        BIO_puts(bio_err, "\x45\x72\x72\x6f\x72\x20\x73\x65\x74\x74\x69\x6e\x67\x20\x75\x70\x20\x70\x65\x65\x72\x20\x6b\x65\x79\xa");
        ERR_print_errors(bio_err);
        goto end;
    }
    if (pkeyopts != NULL) {
        int num = sk_OPENSSL_STRING_num(pkeyopts);
        int i;

        for (i = 0; i < num; ++i) {
            const char *opt = sk_OPENSSL_STRING_value(pkeyopts, i);

            if (pkey_ctrl_string(ctx, opt) <= 0) {
                BIO_puts(bio_err, "\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x20\x73\x65\x74\x74\x69\x6e\x67\x20\x65\x72\x72\x6f\x72\xa");
                ERR_print_errors(bio_err);
                goto end;
            }
        }
    }

    if (sigfile && (pkey_op != EVP_PKEY_OP_VERIFY)) {
        BIO_puts(bio_err, "\x53\x69\x67\x6e\x61\x74\x75\x72\x65\x20\x66\x69\x6c\x65\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\x20\x66\x6f\x72\x20\x6e\x6f\x6e\x20\x76\x65\x72\x69\x66\x79\xa");
        goto end;
    }

    if (!sigfile && (pkey_op == EVP_PKEY_OP_VERIFY)) {
        BIO_puts(bio_err, "\x4e\x6f\x20\x73\x69\x67\x6e\x61\x74\x75\x72\x65\x20\x66\x69\x6c\x65\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\x20\x66\x6f\x72\x20\x76\x65\x72\x69\x66\x79\xa");
        goto end;
    }

/* FIXME: seed PRNG only if needed */
    app_RAND_load_file(NULL, bio_err, 0);

    if (pkey_op != EVP_PKEY_OP_DERIVE) {
        if (infile) {
            if (!(in = BIO_new_file(infile, "\x72\x62"))) {
                BIO_puts(bio_err, "\x45\x72\x72\x6f\x72\x20\x4f\x70\x65\x6e\x69\x6e\x67\x20\x49\x6e\x70\x75\x74\x20\x46\x69\x6c\x65\xa");
                ERR_print_errors(bio_err);
                goto end;
            }
        } else
            in = BIO_new_fp(stdin, BIO_NOCLOSE);
    }

    if (outfile) {
        if (!(out = BIO_new_file(outfile, "\x77\x62"))) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x43\x72\x65\x61\x74\x69\x6e\x67\x20\x4f\x75\x74\x70\x75\x74\x20\x46\x69\x6c\x65\xa");
            ERR_print_errors(bio_err);
            goto end;
        }
    } else {
        out = BIO_new_fp(stdout, BIO_NOCLOSE);
#ifdef OPENSSL_SYS_VMS
        {
            BIO *tmpbio = BIO_new(BIO_f_linebuffer());
            out = BIO_push(tmpbio, out);
        }
#endif
    }

    if (sigfile) {
        BIO *sigbio = BIO_new_file(sigfile, "\x72\x62");
        if (!sigbio) {
            BIO_printf(bio_err, "\x43\x61\x6e\x27\x74\x20\x6f\x70\x65\x6e\x20\x73\x69\x67\x6e\x61\x74\x75\x72\x65\x20\x66\x69\x6c\x65\x20\x25\x73\xa", sigfile);
            goto end;
        }
        siglen = bio_to_mem(&sig, keysize * 10, sigbio);
        BIO_free(sigbio);
        if (siglen < 0) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x72\x65\x61\x64\x69\x6e\x67\x20\x73\x69\x67\x6e\x61\x74\x75\x72\x65\x20\x64\x61\x74\x61\xa");
            goto end;
        }
    }

    if (in) {
        /* Read the input data */
        buf_inlen = bio_to_mem(&buf_in, keysize * 10, in);
        if (buf_inlen < 0) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x72\x65\x61\x64\x69\x6e\x67\x20\x69\x6e\x70\x75\x74\x20\x44\x61\x74\x61\xa");
            exit(1);
        }
        if (rev) {
            size_t i;
            unsigned char ctmp;
            size_t l = (size_t)buf_inlen;
            for (i = 0; i < l / 2; i++) {
                ctmp = buf_in[i];
                buf_in[i] = buf_in[l - 1 - i];
                buf_in[l - 1 - i] = ctmp;
            }
        }
    }

    if (pkey_op == EVP_PKEY_OP_VERIFY) {
        rv = EVP_PKEY_verify(ctx, sig, (size_t)siglen,
                             buf_in, (size_t)buf_inlen);
        if (rv == 0)
            BIO_puts(out, "\x53\x69\x67\x6e\x61\x74\x75\x72\x65\x20\x56\x65\x72\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x20\x46\x61\x69\x6c\x75\x72\x65\xa");
        else if (rv == 1) {
            BIO_puts(out, "\x53\x69\x67\x6e\x61\x74\x75\x72\x65\x20\x56\x65\x72\x69\x66\x69\x65\x64\x20\x53\x75\x63\x63\x65\x73\x73\x66\x75\x6c\x6c\x79\xa");
            ret = 0;
        }
        if (rv >= 0)
            goto end;
    } else {
        rv = do_keyop(ctx, pkey_op, NULL, (size_t *)&buf_outlen,
                      buf_in, (size_t)buf_inlen);
        if (rv > 0 && buf_outlen != 0) {
            buf_out = OPENSSL_malloc(buf_outlen);
            if (!buf_out)
                rv = -1;
            else
                rv = do_keyop(ctx, pkey_op,
                              buf_out, (size_t *)&buf_outlen,
                              buf_in, (size_t)buf_inlen);
        }
    }

    if (rv <= 0) {
        BIO_printf(bio_err, "\x50\x75\x62\x6c\x69\x63\x20\x4b\x65\x79\x20\x6f\x70\x65\x72\x61\x74\x69\x6f\x6e\x20\x65\x72\x72\x6f\x72\xa");
        ERR_print_errors(bio_err);
        goto end;
    }
    ret = 0;
    if (asn1parse) {
        if (!ASN1_parse_dump(out, buf_out, buf_outlen, 1, -1))
            ERR_print_errors(bio_err);
    } else if (hexdump)
        BIO_dump(out, (char *)buf_out, buf_outlen);
    else
        BIO_write(out, buf_out, buf_outlen);

 end:
    if (ctx)
        EVP_PKEY_CTX_free(ctx);
    release_engine(e);
    BIO_free(in);
    BIO_free_all(out);
    if (buf_in != NULL)
        OPENSSL_free(buf_in);
    if (buf_out != NULL)
        OPENSSL_free(buf_out);
    if (sig != NULL)
        OPENSSL_free(sig);
    if (pkeyopts != NULL)
        sk_OPENSSL_STRING_free(pkeyopts);
    return ret;
}

static void usage()
{
    BIO_printf(bio_err, "\x55\x73\x61\x67\x65\x3a\x20\x70\x6b\x65\x79\x75\x74\x6c\x20\x5b\x6f\x70\x74\x69\x6f\x6e\x73\x5d\xa");
    BIO_printf(bio_err, "\x2d\x69\x6e\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x20\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x66\x69\x6c\x65\xa");
    BIO_printf(bio_err, "\x2d\x6f\x75\x74\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x20\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\xa");
    BIO_printf(bio_err,
               "\x2d\x73\x69\x67\x66\x69\x6c\x65\x20\x66\x69\x6c\x65\x20\x73\x69\x67\x6e\x61\x74\x75\x72\x65\x20\x66\x69\x6c\x65\x20\x28\x76\x65\x72\x69\x66\x79\x20\x6f\x70\x65\x72\x61\x74\x69\x6f\x6e\x20\x6f\x6e\x6c\x79\x29\xa");
    BIO_printf(bio_err, "\x2d\x69\x6e\x6b\x65\x79\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x6b\x65\x79\xa");
    BIO_printf(bio_err, "\x2d\x6b\x65\x79\x66\x6f\x72\x6d\x20\x61\x72\x67\x20\x20\x20\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\x20\x66\x6f\x72\x6d\x61\x74\x20\x2d\x20\x64\x65\x66\x61\x75\x6c\x74\x20\x50\x45\x4d\xa");
    BIO_printf(bio_err, "\x2d\x70\x75\x62\x69\x6e\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x69\x73\x20\x61\x20\x70\x75\x62\x6c\x69\x63\x20\x6b\x65\x79\xa");
    BIO_printf(bio_err,
               "\x2d\x63\x65\x72\x74\x69\x6e\x20\x20\x20\x20\x20\x20\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x69\x73\x20\x61\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x63\x61\x72\x72\x79\x69\x6e\x67\x20\x61\x20\x70\x75\x62\x6c\x69\x63\x20\x6b\x65\x79\xa");
    BIO_printf(bio_err, "\x2d\x70\x6b\x65\x79\x6f\x70\x74\x20\x58\x3a\x59\x20\x20\x20\x20\x70\x75\x62\x6c\x69\x63\x20\x6b\x65\x79\x20\x6f\x70\x74\x69\x6f\x6e\x73\xa");
    BIO_printf(bio_err, "\x2d\x73\x69\x67\x6e\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x73\x69\x67\x6e\x20\x77\x69\x74\x68\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\xa");
    BIO_printf(bio_err, "\x2d\x76\x65\x72\x69\x66\x79\x20\x20\x20\x20\x20\x20\x20\x20\x20\x76\x65\x72\x69\x66\x79\x20\x77\x69\x74\x68\x20\x70\x75\x62\x6c\x69\x63\x20\x6b\x65\x79\xa");
    BIO_printf(bio_err,
               "\x2d\x76\x65\x72\x69\x66\x79\x72\x65\x63\x6f\x76\x65\x72\x20\x20\x76\x65\x72\x69\x66\x79\x20\x77\x69\x74\x68\x20\x70\x75\x62\x6c\x69\x63\x20\x6b\x65\x79\x2c\x20\x72\x65\x63\x6f\x76\x65\x72\x20\x6f\x72\x69\x67\x69\x6e\x61\x6c\x20\x64\x61\x74\x61\xa");
    BIO_printf(bio_err, "\x2d\x65\x6e\x63\x72\x79\x70\x74\x20\x20\x20\x20\x20\x20\x20\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x77\x69\x74\x68\x20\x70\x75\x62\x6c\x69\x63\x20\x6b\x65\x79\xa");
    BIO_printf(bio_err, "\x2d\x64\x65\x63\x72\x79\x70\x74\x20\x20\x20\x20\x20\x20\x20\x20\x64\x65\x63\x72\x79\x70\x74\x20\x77\x69\x74\x68\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\xa");
    BIO_printf(bio_err, "\x2d\x64\x65\x72\x69\x76\x65\x20\x20\x20\x20\x20\x20\x20\x20\x20\x64\x65\x72\x69\x76\x65\x20\x73\x68\x61\x72\x65\x64\x20\x73\x65\x63\x72\x65\x74\xa");
    BIO_printf(bio_err, "\x2d\x68\x65\x78\x64\x75\x6d\x70\x20\x20\x20\x20\x20\x20\x20\x20\x68\x65\x78\x20\x64\x75\x6d\x70\x20\x6f\x75\x74\x70\x75\x74\xa");
#ifndef OPENSSL_NO_ENGINE
    BIO_printf(bio_err,
               "\x2d\x65\x6e\x67\x69\x6e\x65\x20\x65\x20\x20\x20\x20\x20\x20\x20\x75\x73\x65\x20\x65\x6e\x67\x69\x6e\x65\x20\x65\x2c\x20\x6d\x61\x79\x62\x65\x20\x61\x20\x68\x61\x72\x64\x77\x61\x72\x65\x20\x64\x65\x76\x69\x63\x65\x2c\x20\x66\x6f\x72\x20\x6c\x6f\x61\x64\x69\x6e\x67\x20\x6b\x65\x79\x73\x2e\xa");
    BIO_printf(bio_err, "\x2d\x65\x6e\x67\x69\x6e\x65\x5f\x69\x6d\x70\x6c\x20\x20\x20\x20\x61\x6c\x73\x6f\x20\x75\x73\x65\x20\x65\x6e\x67\x69\x6e\x65\x20\x67\x69\x76\x65\x6e\x20\x62\x79\x20\x2d\x65\x6e\x67\x69\x6e\x65\x20\x66\x6f\x72\x20\x63\x72\x79\x70\x74\x6f\x20\x6f\x70\x65\x72\x61\x74\x69\x6f\x6e\x73\xa");
#endif
    BIO_printf(bio_err, "\x2d\x70\x61\x73\x73\x69\x6e\x20\x61\x72\x67\x20\x20\x20\x20\x20\x70\x61\x73\x73\x20\x70\x68\x72\x61\x73\x65\x20\x73\x6f\x75\x72\x63\x65\xa");

}

static EVP_PKEY_CTX *init_ctx(int *pkeysize,
                              const char *keyfile, int keyform, int key_type,
                              char *passargin, int pkey_op, ENGINE *e,
                              int   engine_impl)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    ENGINE *impl = NULL;
    char *passin = NULL;
    int rv = -1;
    X509 *x;
    if (((pkey_op == EVP_PKEY_OP_SIGN) || (pkey_op == EVP_PKEY_OP_DECRYPT)
         || (pkey_op == EVP_PKEY_OP_DERIVE))
        && (key_type != KEY_PRIVKEY)) {
        BIO_printf(bio_err, "\x41\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\x20\x69\x73\x20\x6e\x65\x65\x64\x65\x64\x20\x66\x6f\x72\x20\x74\x68\x69\x73\x20\x6f\x70\x65\x72\x61\x74\x69\x6f\x6e\xa");
        goto end;
    }
    if (!app_passwd(bio_err, passargin, NULL, &passin, NULL)) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x67\x65\x74\x74\x69\x6e\x67\x20\x70\x61\x73\x73\x77\x6f\x72\x64\xa");
        goto end;
    }
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

    *pkeysize = EVP_PKEY_size(pkey);

    if (!pkey)
        goto end;
        
#ifndef OPENSSL_NO_ENGINE
    if (engine_impl)
	impl = e;
#endif
            
    ctx = EVP_PKEY_CTX_new(pkey, impl);
    
    EVP_PKEY_free(pkey);

    if (!ctx)
        goto end;

    switch (pkey_op) {
    case EVP_PKEY_OP_SIGN:
        rv = EVP_PKEY_sign_init(ctx);
        break;

    case EVP_PKEY_OP_VERIFY:
        rv = EVP_PKEY_verify_init(ctx);
        break;

    case EVP_PKEY_OP_VERIFYRECOVER:
        rv = EVP_PKEY_verify_recover_init(ctx);
        break;

    case EVP_PKEY_OP_ENCRYPT:
        rv = EVP_PKEY_encrypt_init(ctx);
        break;

    case EVP_PKEY_OP_DECRYPT:
        rv = EVP_PKEY_decrypt_init(ctx);
        break;

    case EVP_PKEY_OP_DERIVE:
        rv = EVP_PKEY_derive_init(ctx);
        break;
    }

    if (rv <= 0) {
        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;
    }

 end:

    if (passin)
        OPENSSL_free(passin);

    return ctx;

}

static int setup_peer(BIO *err, EVP_PKEY_CTX *ctx, int peerform,
                      const char *file, ENGINE* e)
{
    EVP_PKEY *peer = NULL;
    ENGINE* engine = NULL;
    int ret;

    if (peerform == FORMAT_ENGINE)
        engine = e;
    peer = load_pubkey(bio_err, file, peerform, 0, NULL, engine, "\x50\x65\x65\x72\x20\x4b\x65\x79");

    if (!peer) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x72\x65\x61\x64\x69\x6e\x67\x20\x70\x65\x65\x72\x20\x6b\x65\x79\x20\x25\x73\xa", file);
        ERR_print_errors(err);
        return 0;
    }

    ret = EVP_PKEY_derive_set_peer(ctx, peer);

    EVP_PKEY_free(peer);
    if (ret <= 0)
        ERR_print_errors(err);
    return ret;
}

static int do_keyop(EVP_PKEY_CTX *ctx, int pkey_op,
                    unsigned char *out, size_t *poutlen,
                    unsigned char *in, size_t inlen)
{
    int rv = 0;
    switch (pkey_op) {
    case EVP_PKEY_OP_VERIFYRECOVER:
        rv = EVP_PKEY_verify_recover(ctx, out, poutlen, in, inlen);
        break;

    case EVP_PKEY_OP_SIGN:
        rv = EVP_PKEY_sign(ctx, out, poutlen, in, inlen);
        break;

    case EVP_PKEY_OP_ENCRYPT:
        rv = EVP_PKEY_encrypt(ctx, out, poutlen, in, inlen);
        break;

    case EVP_PKEY_OP_DECRYPT:
        rv = EVP_PKEY_decrypt(ctx, out, poutlen, in, inlen);
        break;

    case EVP_PKEY_OP_DERIVE:
        rv = EVP_PKEY_derive(ctx, out, poutlen);
        break;

    }
    return rv;
}
