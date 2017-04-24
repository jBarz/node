/* apps/genpkey.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2006
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
#include <stdio.h>
#include <string.h>
#include "apps.h"
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif

static int init_keygen_file(BIO *err, EVP_PKEY_CTX **pctx,
                            const char *file, ENGINE *e);
static int genpkey_cb(EVP_PKEY_CTX *ctx);

#define PROG genpkey_main

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    ENGINE *e = NULL;
    char **args, *outfile = NULL;
    char *passarg = NULL;
    BIO *in = NULL, *out = NULL;
    const EVP_CIPHER *cipher = NULL;
    int outformat;
    int text = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    char *pass = NULL;
    int badarg = 0;
    int ret = 1, rv;

    int do_param = 0;

    if (bio_err == NULL)
        bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

    if (!load_config(bio_err, NULL))
        goto end;

    outformat = FORMAT_PEM;

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    args = argv + 1;
    while (!badarg && *args && *args[0] == '\x2d') {
        if (!strcmp(*args, "\x2d\x6f\x75\x74\x66\x6f\x72\x6d")) {
            if (args[1]) {
                args++;
                outformat = str2fmt(*args);
            } else
                badarg = 1;
        } else if (!strcmp(*args, "\x2d\x70\x61\x73\x73")) {
            if (!args[1])
                goto bad;
            passarg = *(++args);
        }
#ifndef OPENSSL_NO_ENGINE
        else if (strcmp(*args, "\x2d\x65\x6e\x67\x69\x6e\x65") == 0) {
            if (!args[1])
                goto bad;
            e = setup_engine(bio_err, *(++args), 0);
        }
#endif
        else if (!strcmp(*args, "\x2d\x70\x61\x72\x61\x6d\x66\x69\x6c\x65")) {
            if (!args[1])
                goto bad;
            args++;
            if (do_param == 1)
                goto bad;
            if (!init_keygen_file(bio_err, &ctx, *args, e))
                goto end;
        } else if (!strcmp(*args, "\x2d\x6f\x75\x74")) {
            if (args[1]) {
                args++;
                outfile = *args;
            } else
                badarg = 1;
        } else if (strcmp(*args, "\x2d\x61\x6c\x67\x6f\x72\x69\x74\x68\x6d") == 0) {
            if (!args[1])
                goto bad;
            if (!init_gen_str(bio_err, &ctx, *(++args), e, do_param))
                goto end;
        } else if (strcmp(*args, "\x2d\x70\x6b\x65\x79\x6f\x70\x74") == 0) {
            if (!args[1])
                goto bad;
            if (!ctx) {
                BIO_puts(bio_err, "\x4e\x6f\x20\x6b\x65\x79\x74\x79\x70\x65\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\xa");
                goto bad;
            } else if (pkey_ctrl_string(ctx, *(++args)) <= 0) {
                BIO_puts(bio_err, "\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x20\x73\x65\x74\x74\x69\x6e\x67\x20\x65\x72\x72\x6f\x72\xa");
                ERR_print_errors(bio_err);
                goto end;
            }
        } else if (strcmp(*args, "\x2d\x67\x65\x6e\x70\x61\x72\x61\x6d") == 0) {
            if (ctx)
                goto bad;
            do_param = 1;
        } else if (strcmp(*args, "\x2d\x74\x65\x78\x74") == 0)
            text = 1;
        else {
            cipher = EVP_get_cipherbyname(*args + 1);
            if (!cipher) {
                BIO_printf(bio_err, "\x55\x6e\x6b\x6e\x6f\x77\x6e\x20\x63\x69\x70\x68\x65\x72\x20\x25\x73\xa", *args + 1);
                badarg = 1;
            }
            if (do_param == 1)
                badarg = 1;
        }
        args++;
    }

    if (!ctx)
        badarg = 1;

    if (badarg) {
 bad:
        BIO_printf(bio_err, "\x55\x73\x61\x67\x65\x3a\x20\x67\x65\x6e\x70\x6b\x65\x79\x20\x5b\x6f\x70\x74\x69\x6f\x6e\x73\x5d\xa");
        BIO_printf(bio_err, "\x77\x68\x65\x72\x65\x20\x6f\x70\x74\x69\x6f\x6e\x73\x20\x6d\x61\x79\x20\x62\x65\xa");
        BIO_printf(bio_err, "\x2d\x6f\x75\x74\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err,
                   "\x2d\x6f\x75\x74\x66\x6f\x72\x6d\x20\x58\x20\x20\x20\x20\x20\x20\x20\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x28\x44\x45\x52\x20\x6f\x72\x20\x50\x45\x4d\x29\xa");
        BIO_printf(bio_err,
                   "\x2d\x70\x61\x73\x73\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\x20\x70\x61\x73\x73\x20\x70\x68\x72\x61\x73\x65\x20\x73\x6f\x75\x72\x63\x65\xa");
        BIO_printf(bio_err,
                   "\x2d\x3c\x63\x69\x70\x68\x65\x72\x3e\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x75\x73\x65\x20\x63\x69\x70\x68\x65\x72\x20\x3c\x63\x69\x70\x68\x65\x72\x3e\x20\x74\x6f\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x74\x68\x65\x20\x6b\x65\x79\xa");
#ifndef OPENSSL_NO_ENGINE
        BIO_printf(bio_err,
                   "\x2d\x65\x6e\x67\x69\x6e\x65\x20\x65\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x75\x73\x65\x20\x65\x6e\x67\x69\x6e\x65\x20\x65\x2c\x20\x70\x6f\x73\x73\x69\x62\x6c\x79\x20\x61\x20\x68\x61\x72\x64\x77\x61\x72\x65\x20\x64\x65\x76\x69\x63\x65\x2e\xa");
#endif
        BIO_printf(bio_err, "\x2d\x70\x61\x72\x61\x6d\x66\x69\x6c\x65\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\x20\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err, "\x2d\x61\x6c\x67\x6f\x72\x69\x74\x68\x6d\x20\x61\x6c\x67\x20\x20\x20\x20\x20\x74\x68\x65\x20\x70\x75\x62\x6c\x69\x63\x20\x6b\x65\x79\x20\x61\x6c\x67\x6f\x72\x69\x74\x68\x6d\xa");
        BIO_printf(bio_err,
                   "\x2d\x70\x6b\x65\x79\x6f\x70\x74\x20\x6f\x70\x74\x3a\x76\x61\x6c\x75\x65\x20\x73\x65\x74\x20\x74\x68\x65\x20\x70\x75\x62\x6c\x69\x63\x20\x6b\x65\x79\x20\x61\x6c\x67\x6f\x72\x69\x74\x68\x6d\x20\x6f\x70\x74\x69\x6f\x6e\x20\x3c\x6f\x70\x74\x3e\xa"
                   "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x74\x6f\x20\x76\x61\x6c\x75\x65\x20\x3c\x76\x61\x6c\x75\x65\x3e\xa");
        BIO_printf(bio_err,
                   "\x2d\x67\x65\x6e\x70\x61\x72\x61\x6d\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x67\x65\x6e\x65\x72\x61\x74\x65\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\x2c\x20\x6e\x6f\x74\x20\x6b\x65\x79\xa");
        BIO_printf(bio_err, "\x2d\x74\x65\x78\x74\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x70\x72\x69\x6e\x74\x20\x74\x68\x65\x20\x69\x6e\x20\x74\x65\x78\x74\xa");
        BIO_printf(bio_err,
                   "\x4e\x42\x3a\x20\x6f\x70\x74\x69\x6f\x6e\x73\x20\x6f\x72\x64\x65\x72\x20\x6d\x61\x79\x20\x62\x65\x20\x69\x6d\x70\x6f\x72\x74\x61\x6e\x74\x21\x20\x20\x53\x65\x65\x20\x74\x68\x65\x20\x6d\x61\x6e\x75\x61\x6c\x20\x70\x61\x67\x65\x2e\xa");
        goto end;
    }

    if (!app_passwd(bio_err, passarg, NULL, &pass, NULL)) {
        BIO_puts(bio_err, "\x45\x72\x72\x6f\x72\x20\x67\x65\x74\x74\x69\x6e\x67\x20\x70\x61\x73\x73\x77\x6f\x72\x64\xa");
        goto end;
    }

    if (outfile) {
        if (!(out = BIO_new_file(outfile, "\x77\x62"))) {
            BIO_printf(bio_err, "\x43\x61\x6e\x27\x74\x20\x6f\x70\x65\x6e\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\x20\x25\x73\xa", outfile);
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

    EVP_PKEY_CTX_set_cb(ctx, genpkey_cb);
    EVP_PKEY_CTX_set_app_data(ctx, bio_err);

    if (do_param) {
        if (EVP_PKEY_paramgen(ctx, &pkey) <= 0) {
            BIO_puts(bio_err, "\x45\x72\x72\x6f\x72\x20\x67\x65\x6e\x65\x72\x61\x74\x69\x6e\x67\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\xa");
            ERR_print_errors(bio_err);
            goto end;
        }
    } else {
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            BIO_puts(bio_err, "\x45\x72\x72\x6f\x72\x20\x67\x65\x6e\x65\x72\x61\x74\x69\x6e\x67\x20\x6b\x65\x79\xa");
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (do_param)
        rv = PEM_write_bio_Parameters(out, pkey);
    else if (outformat == FORMAT_PEM)
        rv = PEM_write_bio_PrivateKey(out, pkey, cipher, NULL, 0, NULL, pass);
    else if (outformat == FORMAT_ASN1)
        rv = i2d_PrivateKey_bio(out, pkey);
    else {
        BIO_printf(bio_err, "\x42\x61\x64\x20\x66\x6f\x72\x6d\x61\x74\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\x20\x66\x6f\x72\x20\x6b\x65\x79\xa");
        goto end;
    }

    if (rv <= 0) {
        BIO_puts(bio_err, "\x45\x72\x72\x6f\x72\x20\x77\x72\x69\x74\x69\x6e\x67\x20\x6b\x65\x79\xa");
        ERR_print_errors(bio_err);
    }

    if (text) {
        if (do_param)
            rv = EVP_PKEY_print_params(out, pkey, 0, NULL);
        else
            rv = EVP_PKEY_print_private(out, pkey, 0, NULL);

        if (rv <= 0) {
            BIO_puts(bio_err, "\x45\x72\x72\x6f\x72\x20\x70\x72\x69\x6e\x74\x69\x6e\x67\x20\x6b\x65\x79\xa");
            ERR_print_errors(bio_err);
        }
    }

    ret = 0;

 end:
    if (pkey)
        EVP_PKEY_free(pkey);
    if (ctx)
        EVP_PKEY_CTX_free(ctx);
    if (out)
        BIO_free_all(out);
    BIO_free(in);
    release_engine(e);
    if (pass)
        OPENSSL_free(pass);
    return ret;
}

static int init_keygen_file(BIO *err, EVP_PKEY_CTX **pctx,
                            const char *file, ENGINE *e)
{
    BIO *pbio;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    if (*pctx) {
        BIO_puts(err, "\x50\x61\x72\x61\x6d\x65\x74\x65\x72\x73\x20\x61\x6c\x72\x65\x61\x64\x79\x20\x73\x65\x74\x21\xa");
        return 0;
    }

    pbio = BIO_new_file(file, "\x72");
    if (!pbio) {
        BIO_printf(err, "\x43\x61\x6e\x27\x74\x20\x6f\x70\x65\x6e\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x20\x66\x69\x6c\x65\x20\x25\x73\xa", file);
        return 0;
    }

    pkey = PEM_read_bio_Parameters(pbio, NULL);
    BIO_free(pbio);

    if (!pkey) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x72\x65\x61\x64\x69\x6e\x67\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x20\x66\x69\x6c\x65\x20\x25\x73\xa", file);
        return 0;
    }

    ctx = EVP_PKEY_CTX_new(pkey, e);
    if (!ctx)
        goto err;
    if (EVP_PKEY_keygen_init(ctx) <= 0)
        goto err;
    EVP_PKEY_free(pkey);
    *pctx = ctx;
    return 1;

 err:
    BIO_puts(err, "\x45\x72\x72\x6f\x72\x20\x69\x6e\x69\x74\x69\x61\x6c\x69\x7a\x69\x6e\x67\x20\x63\x6f\x6e\x74\x65\x78\x74\xa");
    ERR_print_errors(err);
    if (ctx)
        EVP_PKEY_CTX_free(ctx);
    if (pkey)
        EVP_PKEY_free(pkey);
    return 0;

}

int init_gen_str(BIO *err, EVP_PKEY_CTX **pctx,
                 const char *algname, ENGINE *e, int do_param)
{
    EVP_PKEY_CTX *ctx = NULL;
    const EVP_PKEY_ASN1_METHOD *ameth;
    ENGINE *tmpeng = NULL;
    int pkey_id;

    if (*pctx) {
        BIO_puts(err, "\x41\x6c\x67\x6f\x72\x69\x74\x68\x6d\x20\x61\x6c\x72\x65\x61\x64\x79\x20\x73\x65\x74\x21\xa");
        return 0;
    }

    ameth = EVP_PKEY_asn1_find_str(&tmpeng, algname, -1);

#ifndef OPENSSL_NO_ENGINE
    if (!ameth && e)
        ameth = ENGINE_get_pkey_asn1_meth_str(e, algname, -1);
#endif

    if (!ameth) {
        BIO_printf(bio_err, "\x41\x6c\x67\x6f\x72\x69\x74\x68\x6d\x20\x25\x73\x20\x6e\x6f\x74\x20\x66\x6f\x75\x6e\x64\xa", algname);
        return 0;
    }

    ERR_clear_error();

    EVP_PKEY_asn1_get0_info(&pkey_id, NULL, NULL, NULL, NULL, ameth);
#ifndef OPENSSL_NO_ENGINE
    if (tmpeng)
        ENGINE_finish(tmpeng);
#endif
    ctx = EVP_PKEY_CTX_new_id(pkey_id, e);

    if (!ctx)
        goto err;
    if (do_param) {
        if (EVP_PKEY_paramgen_init(ctx) <= 0)
            goto err;
    } else {
        if (EVP_PKEY_keygen_init(ctx) <= 0)
            goto err;
    }

    *pctx = ctx;
    return 1;

 err:
    BIO_printf(err, "\x45\x72\x72\x6f\x72\x20\x69\x6e\x69\x74\x69\x61\x6c\x69\x7a\x69\x6e\x67\x20\x25\x73\x20\x63\x6f\x6e\x74\x65\x78\x74\xa", algname);
    ERR_print_errors(err);
    if (ctx)
        EVP_PKEY_CTX_free(ctx);
    return 0;

}

static int genpkey_cb(EVP_PKEY_CTX *ctx)
{
    char c = '\x2a';
    BIO *b = EVP_PKEY_CTX_get_app_data(ctx);
    int p;
    p = EVP_PKEY_CTX_get_keygen_info(ctx, 0);
    if (p == 0)
        c = '\x2e';
    if (p == 1)
        c = '\x2b';
    if (p == 2)
        c = '\x2a';
    if (p == 3)
        c = '\xa';
    BIO_write(b, &c, 1);
    (void)BIO_flush(b);
#ifdef LINT
    p = n;
#endif
    return 1;
}
