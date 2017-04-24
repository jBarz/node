/* apps/gendh.c */
/* obsoleted by dhparam.c */
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

#ifndef OPENSSL_NO_DH
# include <stdio.h>
# include <string.h>
# include <sys/types.h>
# include <sys/stat.h>
# include "apps.h"
# include <openssl/bio.h>
# include <openssl/rand.h>
# include <openssl/err.h>
# include <openssl/bn.h>
# include <openssl/dh.h>
# include <openssl/x509.h>
# include <openssl/pem.h>

# define DEFBITS 2048
# undef PROG
# define PROG gendh_main

static int MS_CALLBACK dh_cb(int p, int n, BN_GENCB *cb);

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    BN_GENCB cb;
    DH *dh = NULL;
    int ret = 1, num = DEFBITS;
    int g = 2;
    char *outfile = NULL;
    char *inrand = NULL;
    char *engine = NULL;
    BIO *out = NULL;

    apps_startup();

    BN_GENCB_set(&cb, dh_cb, bio_err);
    if (bio_err == NULL)
        if ((bio_err = BIO_new(BIO_s_file())) != NULL)
            BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    if (!load_config(bio_err, NULL))
        goto end;

    argv++;
    argc--;
    for (;;) {
        if (argc <= 0)
            break;
        if (strcmp(*argv, "\x2d\x6f\x75\x74") == 0) {
            if (--argc < 1)
                goto bad;
            outfile = *(++argv);
        } else if (strcmp(*argv, "\x2d\x32") == 0)
            g = 2;
/*-     else if (strcmp(*argv,"-3") == 0)
                g=3; */
        else if (strcmp(*argv, "\x2d\x35") == 0)
            g = 5;
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
        } else
            break;
        argv++;
        argc--;
    }
    if ((argc >= 1) && ((sscanf(*argv, "\x25\x64", &num) == 0) || (num < 0))) {
 bad:
        BIO_printf(bio_err, "\x75\x73\x61\x67\x65\x3a\x20\x67\x65\x6e\x64\x68\x20\x5b\x61\x72\x67\x73\x5d\x20\x5b\x6e\x75\x6d\x62\x69\x74\x73\x5d\xa");
        BIO_printf(bio_err, "\x20\x2d\x6f\x75\x74\x20\x66\x69\x6c\x65\x20\x2d\x20\x6f\x75\x74\x70\x75\x74\x20\x74\x68\x65\x20\x6b\x65\x79\x20\x74\x6f\x20\x27\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err, "\x20\x2d\x32\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x75\x73\x65\x20\x32\x20\x61\x73\x20\x74\x68\x65\x20\x67\x65\x6e\x65\x72\x61\x74\x6f\x72\x20\x76\x61\x6c\x75\x65\xa");
        /*
         * BIO_printf(bio_err," -3 - use 3 as the generator value\n");
         */
        BIO_printf(bio_err, "\x20\x2d\x35\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x75\x73\x65\x20\x35\x20\x61\x73\x20\x74\x68\x65\x20\x67\x65\x6e\x65\x72\x61\x74\x6f\x72\x20\x76\x61\x6c\x75\x65\xa");
# ifndef OPENSSL_NO_ENGINE
        BIO_printf(bio_err,
                   "\x20\x2d\x65\x6e\x67\x69\x6e\x65\x20\x65\x20\x2d\x20\x75\x73\x65\x20\x65\x6e\x67\x69\x6e\x65\x20\x65\x2c\x20\x70\x6f\x73\x73\x69\x62\x6c\x79\x20\x61\x20\x68\x61\x72\x64\x77\x61\x72\x65\x20\x64\x65\x76\x69\x63\x65\x2e\xa");
# endif
        BIO_printf(bio_err, "\x20\x2d\x72\x61\x6e\x64\x20\x66\x69\x6c\x65\x25\x63\x66\x69\x6c\x65\x25\x63\x2e\x2e\x2e\xa", LIST_SEPARATOR_CHAR,
                   LIST_SEPARATOR_CHAR);
        BIO_printf(bio_err,
                   "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x6c\x6f\x61\x64\x20\x74\x68\x65\x20\x66\x69\x6c\x65\x20\x28\x6f\x72\x20\x74\x68\x65\x20\x66\x69\x6c\x65\x73\x20\x69\x6e\x20\x74\x68\x65\x20\x64\x69\x72\x65\x63\x74\x6f\x72\x79\x29\x20\x69\x6e\x74\x6f\xa");
        BIO_printf(bio_err, "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x74\x68\x65\x20\x72\x61\x6e\x64\x6f\x6d\x20\x6e\x75\x6d\x62\x65\x72\x20\x67\x65\x6e\x65\x72\x61\x74\x6f\x72\xa");
        goto end;
    }
    setup_engine(bio_err, engine, 0);

    out = BIO_new(BIO_s_file());
    if (out == NULL) {
        ERR_print_errors(bio_err);
        goto end;
    }

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
            goto end;
        }
    }

    if (!app_RAND_load_file(NULL, bio_err, 1) && inrand == NULL) {
        BIO_printf(bio_err,
                   "\x77\x61\x72\x6e\x69\x6e\x67\x2c\x20\x6e\x6f\x74\x20\x6d\x75\x63\x68\x20\x65\x78\x74\x72\x61\x20\x72\x61\x6e\x64\x6f\x6d\x20\x64\x61\x74\x61\x2c\x20\x63\x6f\x6e\x73\x69\x64\x65\x72\x20\x75\x73\x69\x6e\x67\x20\x74\x68\x65\x20\x2d\x72\x61\x6e\x64\x20\x6f\x70\x74\x69\x6f\x6e\xa");
    }
    if (inrand != NULL)
        BIO_printf(bio_err, "\x25\x6c\x64\x20\x73\x65\x6d\x69\x2d\x72\x61\x6e\x64\x6f\x6d\x20\x62\x79\x74\x65\x73\x20\x6c\x6f\x61\x64\x65\x64\xa",
                   app_RAND_load_files(inrand));

    BIO_printf(bio_err,
               "\x47\x65\x6e\x65\x72\x61\x74\x69\x6e\x67\x20\x44\x48\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\x2c\x20\x25\x64\x20\x62\x69\x74\x20\x6c\x6f\x6e\x67\x20\x73\x61\x66\x65\x20\x70\x72\x69\x6d\x65\x2c\x20\x67\x65\x6e\x65\x72\x61\x74\x6f\x72\x20\x25\x64\xa",
               num, g);
    BIO_printf(bio_err, "\x54\x68\x69\x73\x20\x69\x73\x20\x67\x6f\x69\x6e\x67\x20\x74\x6f\x20\x74\x61\x6b\x65\x20\x61\x20\x6c\x6f\x6e\x67\x20\x74\x69\x6d\x65\xa");

    if (((dh = DH_new()) == NULL)
        || !DH_generate_parameters_ex(dh, num, g, &cb))
        goto end;

    app_RAND_write_file(NULL, bio_err);

    if (!PEM_write_bio_DHparams(out, dh))
        goto end;
    ret = 0;
 end:
    if (ret != 0)
        ERR_print_errors(bio_err);
    if (out != NULL)
        BIO_free_all(out);
    if (dh != NULL)
        DH_free(dh);
    apps_shutdown();
    OPENSSL_EXIT(ret);
}

static int MS_CALLBACK dh_cb(int p, int n, BN_GENCB *cb)
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
#else                           /* !OPENSSL_NO_DH */

# if PEDANTIC
static void *dummy = &dummy;
# endif

#endif
