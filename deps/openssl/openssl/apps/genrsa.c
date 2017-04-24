/* apps/genrsa.c */
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

#include <openssl/opensslconf.h>
/*
 * Until the key-gen callbacks are modified to use newer prototypes, we allow
 * deprecated functions for openssl-internal code
 */
#ifdef OPENSSL_NO_DEPRECATED
# undef OPENSSL_NO_DEPRECATED
#endif

#ifndef OPENSSL_NO_RSA
# include <stdio.h>
# include <string.h>
# include <sys/types.h>
# include <sys/stat.h>
# include "apps.h"
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/bn.h>
# include <openssl/rsa.h>
# include <openssl/evp.h>
# include <openssl/x509.h>
# include <openssl/pem.h>
# include <openssl/rand.h>

# define DEFBITS 2048
# undef PROG
# define PROG genrsa_main

static int MS_CALLBACK genrsa_cb(int p, int n, BN_GENCB *cb);

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    BN_GENCB cb;
    ENGINE *e = NULL;
    int ret = 1;
    int i, num = DEFBITS;
    long l;
    const EVP_CIPHER *enc = NULL;
    unsigned long f4 = RSA_F4;
    char *outfile = NULL;
    char *passargout = NULL, *passout = NULL;
    char *engine = NULL;
    char *inrand = NULL;
    BIO *out = NULL;
    BIGNUM *bn = BN_new();
    RSA *rsa = NULL;

    if (!bn)
        goto err;

    apps_startup();
    BN_GENCB_set(&cb, genrsa_cb, bio_err);

    if (bio_err == NULL)
        if ((bio_err = BIO_new(BIO_s_file())) != NULL)
            BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    if (!load_config(bio_err, NULL))
        goto err;
    if ((out = BIO_new(BIO_s_file())) == NULL) {
        BIO_printf(bio_err, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x63\x72\x65\x61\x74\x65\x20\x42\x49\x4f\x20\x66\x6f\x72\x20\x6f\x75\x74\x70\x75\x74\xa");
        goto err;
    }

    argv++;
    argc--;
    for (;;) {
        if (argc <= 0)
            break;
        if (strcmp(*argv, "\x2d\x6f\x75\x74") == 0) {
            if (--argc < 1)
                goto bad;
            outfile = *(++argv);
        } else if (strcmp(*argv, "\x2d\x33") == 0)
            f4 = 3;
        else if (strcmp(*argv, "\x2d\x46\x34") == 0 || strcmp(*argv, "\x2d\x66\x34") == 0)
            f4 = RSA_F4;
# ifndef OPENSSL_NO_ENGINE
        else if (strcmp(*argv, "\x2d\x65\x6e\x67\x69\x6e\x65") == 0) {
            if (--argc < 1)
                goto bad;
            engine = *(++argv);
        }
# endif
        else if (strcmp(*argv, "\x2d\x72\x61\x6e\x64") == 0) {
            if (--argc < 1)
                goto bad;
            inrand = *(++argv);
        }
# ifndef OPENSSL_NO_DES
        else if (strcmp(*argv, "\x2d\x64\x65\x73") == 0)
            enc = EVP_des_cbc();
        else if (strcmp(*argv, "\x2d\x64\x65\x73\x33") == 0)
            enc = EVP_des_ede3_cbc();
# endif
# ifndef OPENSSL_NO_IDEA
        else if (strcmp(*argv, "\x2d\x69\x64\x65\x61") == 0)
            enc = EVP_idea_cbc();
# endif
# ifndef OPENSSL_NO_SEED
        else if (strcmp(*argv, "\x2d\x73\x65\x65\x64") == 0)
            enc = EVP_seed_cbc();
# endif
# ifndef OPENSSL_NO_AES
        else if (strcmp(*argv, "\x2d\x61\x65\x73\x31\x32\x38") == 0)
            enc = EVP_aes_128_cbc();
        else if (strcmp(*argv, "\x2d\x61\x65\x73\x31\x39\x32") == 0)
            enc = EVP_aes_192_cbc();
        else if (strcmp(*argv, "\x2d\x61\x65\x73\x32\x35\x36") == 0)
            enc = EVP_aes_256_cbc();
# endif
# ifndef OPENSSL_NO_CAMELLIA
        else if (strcmp(*argv, "\x2d\x63\x61\x6d\x65\x6c\x6c\x69\x61\x31\x32\x38") == 0)
            enc = EVP_camellia_128_cbc();
        else if (strcmp(*argv, "\x2d\x63\x61\x6d\x65\x6c\x6c\x69\x61\x31\x39\x32") == 0)
            enc = EVP_camellia_192_cbc();
        else if (strcmp(*argv, "\x2d\x63\x61\x6d\x65\x6c\x6c\x69\x61\x32\x35\x36") == 0)
            enc = EVP_camellia_256_cbc();
# endif
        else if (strcmp(*argv, "\x2d\x70\x61\x73\x73\x6f\x75\x74") == 0) {
            if (--argc < 1)
                goto bad;
            passargout = *(++argv);
        } else
            break;
        argv++;
        argc--;
    }
    if ((argc >= 1) && ((sscanf(*argv, "\x25\x64", &num) == 0) || (num < 0))) {
 bad:
        BIO_printf(bio_err, "\x75\x73\x61\x67\x65\x3a\x20\x67\x65\x6e\x72\x73\x61\x20\x5b\x61\x72\x67\x73\x5d\x20\x5b\x6e\x75\x6d\x62\x69\x74\x73\x5d\xa");
        BIO_printf(bio_err,
                   "\x20\x2d\x64\x65\x73\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x74\x68\x65\x20\x67\x65\x6e\x65\x72\x61\x74\x65\x64\x20\x6b\x65\x79\x20\x77\x69\x74\x68\x20\x44\x45\x53\x20\x69\x6e\x20\x63\x62\x63\x20\x6d\x6f\x64\x65\xa");
        BIO_printf(bio_err,
                   "\x20\x2d\x64\x65\x73\x33\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x74\x68\x65\x20\x67\x65\x6e\x65\x72\x61\x74\x65\x64\x20\x6b\x65\x79\x20\x77\x69\x74\x68\x20\x44\x45\x53\x20\x69\x6e\x20\x65\x64\x65\x20\x63\x62\x63\x20\x6d\x6f\x64\x65\x20\x28\x31\x36\x38\x20\x62\x69\x74\x20\x6b\x65\x79\x29\xa");
# ifndef OPENSSL_NO_IDEA
        BIO_printf(bio_err,
                   "\x20\x2d\x69\x64\x65\x61\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x74\x68\x65\x20\x67\x65\x6e\x65\x72\x61\x74\x65\x64\x20\x6b\x65\x79\x20\x77\x69\x74\x68\x20\x49\x44\x45\x41\x20\x69\x6e\x20\x63\x62\x63\x20\x6d\x6f\x64\x65\xa");
# endif
# ifndef OPENSSL_NO_SEED
        BIO_printf(bio_err, "\x20\x2d\x73\x65\x65\x64\xa");
        BIO_printf(bio_err,
                   "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x50\x45\x4d\x20\x6f\x75\x74\x70\x75\x74\x20\x77\x69\x74\x68\x20\x63\x62\x63\x20\x73\x65\x65\x64\xa");
# endif
# ifndef OPENSSL_NO_AES
        BIO_printf(bio_err, "\x20\x2d\x61\x65\x73\x31\x32\x38\x2c\x20\x2d\x61\x65\x73\x31\x39\x32\x2c\x20\x2d\x61\x65\x73\x32\x35\x36\xa");
        BIO_printf(bio_err,
                   "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x50\x45\x4d\x20\x6f\x75\x74\x70\x75\x74\x20\x77\x69\x74\x68\x20\x63\x62\x63\x20\x61\x65\x73\xa");
# endif
# ifndef OPENSSL_NO_CAMELLIA
        BIO_printf(bio_err, "\x20\x2d\x63\x61\x6d\x65\x6c\x6c\x69\x61\x31\x32\x38\x2c\x20\x2d\x63\x61\x6d\x65\x6c\x6c\x69\x61\x31\x39\x32\x2c\x20\x2d\x63\x61\x6d\x65\x6c\x6c\x69\x61\x32\x35\x36\xa");
        BIO_printf(bio_err,
                   "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x50\x45\x4d\x20\x6f\x75\x74\x70\x75\x74\x20\x77\x69\x74\x68\x20\x63\x62\x63\x20\x63\x61\x6d\x65\x6c\x6c\x69\x61\xa");
# endif
        BIO_printf(bio_err, "\x20\x2d\x6f\x75\x74\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x20\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x74\x68\x65\x20\x6b\x65\x79\x20\x74\x6f\x20\x27\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err,
                   "\x20\x2d\x70\x61\x73\x73\x6f\x75\x74\x20\x61\x72\x67\x20\x20\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\x20\x70\x61\x73\x73\x20\x70\x68\x72\x61\x73\x65\x20\x73\x6f\x75\x72\x63\x65\xa");
        BIO_printf(bio_err,
                   "\x20\x2d\x66\x34\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x75\x73\x65\x20\x46\x34\x20\x28\x30\x78\x31\x30\x30\x30\x31\x29\x20\x66\x6f\x72\x20\x74\x68\x65\x20\x45\x20\x76\x61\x6c\x75\x65\xa");
        BIO_printf(bio_err, "\x20\x2d\x33\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x75\x73\x65\x20\x33\x20\x66\x6f\x72\x20\x74\x68\x65\x20\x45\x20\x76\x61\x6c\x75\x65\xa");
# ifndef OPENSSL_NO_ENGINE
        BIO_printf(bio_err,
                   "\x20\x2d\x65\x6e\x67\x69\x6e\x65\x20\x65\x20\x20\x20\x20\x20\x20\x20\x75\x73\x65\x20\x65\x6e\x67\x69\x6e\x65\x20\x65\x2c\x20\x70\x6f\x73\x73\x69\x62\x6c\x79\x20\x61\x20\x68\x61\x72\x64\x77\x61\x72\x65\x20\x64\x65\x76\x69\x63\x65\x2e\xa");
# endif
        BIO_printf(bio_err, "\x20\x2d\x72\x61\x6e\x64\x20\x66\x69\x6c\x65\x25\x63\x66\x69\x6c\x65\x25\x63\x2e\x2e\x2e\xa", LIST_SEPARATOR_CHAR,
                   LIST_SEPARATOR_CHAR);
        BIO_printf(bio_err,
                   "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x6c\x6f\x61\x64\x20\x74\x68\x65\x20\x66\x69\x6c\x65\x20\x28\x6f\x72\x20\x74\x68\x65\x20\x66\x69\x6c\x65\x73\x20\x69\x6e\x20\x74\x68\x65\x20\x64\x69\x72\x65\x63\x74\x6f\x72\x79\x29\x20\x69\x6e\x74\x6f\xa");
        BIO_printf(bio_err, "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x74\x68\x65\x20\x72\x61\x6e\x64\x6f\x6d\x20\x6e\x75\x6d\x62\x65\x72\x20\x67\x65\x6e\x65\x72\x61\x74\x6f\x72\xa");
        goto err;
    }

    ERR_load_crypto_strings();

    if (!app_passwd(bio_err, NULL, passargout, NULL, &passout)) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x67\x65\x74\x74\x69\x6e\x67\x20\x70\x61\x73\x73\x77\x6f\x72\x64\xa");
        goto err;
    }
    e = setup_engine(bio_err, engine, 0);

    if (outfile == NULL) {
        BIO_set_fp(out, stdout, BIO_NOCLOSE);
# ifdef OPENSSL_SYS_VMS
        {
            BIO *tmpbio = BIO_new(BIO_f_linebuffer());
            out = BIO_push(tmpbio, out);
        }
# endif
    } else {
        if (BIO_write_filename(out, outfile) <= 0) {
            perror(outfile);
            goto err;
        }
    }

    if (!app_RAND_load_file(NULL, bio_err, 1) && inrand == NULL
        && !RAND_status()) {
        BIO_printf(bio_err,
                   "\x77\x61\x72\x6e\x69\x6e\x67\x2c\x20\x6e\x6f\x74\x20\x6d\x75\x63\x68\x20\x65\x78\x74\x72\x61\x20\x72\x61\x6e\x64\x6f\x6d\x20\x64\x61\x74\x61\x2c\x20\x63\x6f\x6e\x73\x69\x64\x65\x72\x20\x75\x73\x69\x6e\x67\x20\x74\x68\x65\x20\x2d\x72\x61\x6e\x64\x20\x6f\x70\x74\x69\x6f\x6e\xa");
    }
    if (inrand != NULL)
        BIO_printf(bio_err, "\x25\x6c\x64\x20\x73\x65\x6d\x69\x2d\x72\x61\x6e\x64\x6f\x6d\x20\x62\x79\x74\x65\x73\x20\x6c\x6f\x61\x64\x65\x64\xa",
                   app_RAND_load_files(inrand));

    BIO_printf(bio_err, "\x47\x65\x6e\x65\x72\x61\x74\x69\x6e\x67\x20\x52\x53\x41\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\x2c\x20\x25\x64\x20\x62\x69\x74\x20\x6c\x6f\x6e\x67\x20\x6d\x6f\x64\x75\x6c\x75\x73\xa",
               num);
# ifdef OPENSSL_NO_ENGINE
    rsa = RSA_new();
# else
    rsa = RSA_new_method(e);
# endif
    if (!rsa)
        goto err;

    if (!BN_set_word(bn, f4) || !RSA_generate_key_ex(rsa, num, bn, &cb))
        goto err;

    app_RAND_write_file(NULL, bio_err);

    /*
     * We need to do the following for when the base number size is < long,
     * esp windows 3.1 :-(.
     */
    l = 0L;
    for (i = 0; i < rsa->e->top; i++) {
# ifndef SIXTY_FOUR_BIT
        l <<= BN_BITS4;
        l <<= BN_BITS4;
# endif
        l += rsa->e->d[i];
    }
    BIO_printf(bio_err, "\x65\x20\x69\x73\x20\x25\x6c\x64\x20\x28\x30\x78\x25\x6c\x58\x29\xa", l, l);
    {
        PW_CB_DATA cb_data;
        cb_data.password = passout;
        cb_data.prompt_info = outfile;
        if (!PEM_write_bio_RSAPrivateKey(out, rsa, enc, NULL, 0,
                                         (pem_password_cb *)password_callback,
                                         &cb_data))
            goto err;
    }

    ret = 0;
 err:
    if (bn)
        BN_free(bn);
    if (rsa)
        RSA_free(rsa);
    if (out)
        BIO_free_all(out);
    release_engine(e);
    if (passout)
        OPENSSL_free(passout);
    if (ret != 0)
        ERR_print_errors(bio_err);
    apps_shutdown();
    OPENSSL_EXIT(ret);
}

static int MS_CALLBACK genrsa_cb(int p, int n, BN_GENCB *cb)
{
    char c = '\x2a';

    if (p == 0)
        c = '\x2e';
    if (p == 1)
        c = '\x2b';
    if (p == 2)
        c = '\x2a';
    if (p == 3)
        c = '\xa';
    BIO_write(cb->arg, &c, 1);
    (void)BIO_flush(cb->arg);
# ifdef LINT
    p = n;
# endif
    return 1;
}
#else                           /* !OPENSSL_NO_RSA */

# if PEDANTIC
static void *dummy = &dummy;
# endif

#endif
