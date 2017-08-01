/* apps/dhparam.c */
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
/* ====================================================================
 * Copyright (c) 1998-2000 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "\x4f\x70\x65\x6e\x53\x53\x4c\x20\x54\x6f\x6f\x6c\x6b\x69\x74" and "\x4f\x70\x65\x6e\x53\x53\x4c\x20\x50\x72\x6f\x6a\x65\x63\x74" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "\x4f\x70\x65\x6e\x53\x53\x4c"
 *    nor may "\x4f\x70\x65\x6e\x53\x53\x4c" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
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

#include <openssl/opensslconf.h> /* for OPENSSL_NO_DH */
#ifndef OPENSSL_NO_DH
# include <stdio.h>
# include <stdlib.h>
# include <time.h>
# include <string.h>
# include "apps.h"
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/bn.h>
# include <openssl/dh.h>
# include <openssl/x509.h>
# include <openssl/pem.h>

# ifndef OPENSSL_NO_DSA
#  include <openssl/dsa.h>
# endif

# undef PROG
# define PROG    dhparam_main

# define DEFBITS 2048

/*-
 * -inform arg  - input format - default PEM (DER or PEM)
 * -outform arg - output format - default PEM
 * -in arg      - input file - default stdin
 * -out arg     - output file - default stdout
 * -dsaparam  - read or generate DSA parameters, convert to DH
 * -check       - check the parameters are ok
 * -noout
 * -text
 * -C
 */

static int MS_CALLBACK dh_cb(int p, int n, BN_GENCB *cb);

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    DH *dh = NULL;
    int i, badops = 0, text = 0;
# ifndef OPENSSL_NO_DSA
    int dsaparam = 0;
# endif
    BIO *in = NULL, *out = NULL;
    int informat, outformat, check = 0, noout = 0, C = 0, ret = 1;
    char *infile, *outfile, *prog;
    char *inrand = NULL;
    char *engine = NULL;
    ENGINE *e = NULL;
    int num = 0, g = 0;

    apps_startup();

    if (bio_err == NULL)
        if ((bio_err = BIO_new(BIO_s_file())) != NULL)
            BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    if (!load_config(bio_err, NULL))
        goto end;

    infile = NULL;
    outfile = NULL;
    informat = FORMAT_PEM;
    outformat = FORMAT_PEM;

    prog = argv[0];
    argc--;
    argv++;
    while (argc >= 1) {
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
        } else if (strcmp(*argv, "\x2d\x6f\x75\x74") == 0) {
            if (--argc < 1)
                goto bad;
            outfile = *(++argv);
        }
# ifndef OPENSSL_NO_ENGINE
        else if (strcmp(*argv, "\x2d\x65\x6e\x67\x69\x6e\x65") == 0) {
            if (--argc < 1)
                goto bad;
            engine = *(++argv);
        }
# endif
        else if (strcmp(*argv, "\x2d\x63\x68\x65\x63\x6b") == 0)
            check = 1;
        else if (strcmp(*argv, "\x2d\x74\x65\x78\x74") == 0)
            text = 1;
# ifndef OPENSSL_NO_DSA
        else if (strcmp(*argv, "\x2d\x64\x73\x61\x70\x61\x72\x61\x6d") == 0)
            dsaparam = 1;
# endif
        else if (strcmp(*argv, "\x2d\x43") == 0)
            C = 1;
        else if (strcmp(*argv, "\x2d\x6e\x6f\x6f\x75\x74") == 0)
            noout = 1;
        else if (strcmp(*argv, "\x2d\x32") == 0)
            g = 2;
        else if (strcmp(*argv, "\x2d\x35") == 0)
            g = 5;
        else if (strcmp(*argv, "\x2d\x72\x61\x6e\x64") == 0) {
            if (--argc < 1)
                goto bad;
            inrand = *(++argv);
        } else if (((sscanf(*argv, "\x25\x64", &num) == 0) || (num <= 0)))
            goto bad;
        argv++;
        argc--;
    }

    if (badops) {
 bad:
        BIO_printf(bio_err, "\x25\x73\x20\x5b\x6f\x70\x74\x69\x6f\x6e\x73\x5d\x20\x5b\x6e\x75\x6d\x62\x69\x74\x73\x5d\xa", prog);
        BIO_printf(bio_err, "\x77\x68\x65\x72\x65\x20\x6f\x70\x74\x69\x6f\x6e\x73\x20\x61\x72\x65\xa");
        BIO_printf(bio_err, "\x20\x2d\x69\x6e\x66\x6f\x72\x6d\x20\x61\x72\x67\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x2d\x20\x6f\x6e\x65\x20\x6f\x66\x20\x44\x45\x52\x20\x50\x45\x4d\xa");
        BIO_printf(bio_err,
                   "\x20\x2d\x6f\x75\x74\x66\x6f\x72\x6d\x20\x61\x72\x67\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x2d\x20\x6f\x6e\x65\x20\x6f\x66\x20\x44\x45\x52\x20\x50\x45\x4d\xa");
        BIO_printf(bio_err, "\x20\x2d\x69\x6e\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err, "\x20\x2d\x6f\x75\x74\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\xa");
# ifndef OPENSSL_NO_DSA
        BIO_printf(bio_err,
                   "\x20\x2d\x64\x73\x61\x70\x61\x72\x61\x6d\x20\x20\x20\x20\x20\x72\x65\x61\x64\x20\x6f\x72\x20\x67\x65\x6e\x65\x72\x61\x74\x65\x20\x44\x53\x41\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\x2c\x20\x63\x6f\x6e\x76\x65\x72\x74\x20\x74\x6f\x20\x44\x48\xa");
# endif
        BIO_printf(bio_err, "\x20\x2d\x63\x68\x65\x63\x6b\x20\x20\x20\x20\x20\x20\x20\x20\x63\x68\x65\x63\x6b\x20\x74\x68\x65\x20\x44\x48\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\xa");
        BIO_printf(bio_err,
                   "\x20\x2d\x74\x65\x78\x74\x20\x20\x20\x20\x20\x20\x20\x20\x20\x70\x72\x69\x6e\x74\x20\x61\x20\x74\x65\x78\x74\x20\x66\x6f\x72\x6d\x20\x6f\x66\x20\x74\x68\x65\x20\x44\x48\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\xa");
        BIO_printf(bio_err, "\x20\x2d\x43\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x4f\x75\x74\x70\x75\x74\x20\x43\x20\x63\x6f\x64\x65\xa");
        BIO_printf(bio_err,
                   "\x20\x2d\x32\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x67\x65\x6e\x65\x72\x61\x74\x65\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\x20\x75\x73\x69\x6e\x67\x20\x20\x32\x20\x61\x73\x20\x74\x68\x65\x20\x67\x65\x6e\x65\x72\x61\x74\x6f\x72\x20\x76\x61\x6c\x75\x65\xa");
        BIO_printf(bio_err,
                   "\x20\x2d\x35\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x67\x65\x6e\x65\x72\x61\x74\x65\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\x20\x75\x73\x69\x6e\x67\x20\x20\x35\x20\x61\x73\x20\x74\x68\x65\x20\x67\x65\x6e\x65\x72\x61\x74\x6f\x72\x20\x76\x61\x6c\x75\x65\xa");
        BIO_printf(bio_err,
                   "\x20\x6e\x75\x6d\x62\x69\x74\x73\x20\x20\x20\x20\x20\x20\x20\x6e\x75\x6d\x62\x65\x72\x20\x6f\x66\x20\x62\x69\x74\x73\x20\x69\x6e\x20\x74\x6f\x20\x67\x65\x6e\x65\x72\x61\x74\x65\x20\x28\x64\x65\x66\x61\x75\x6c\x74\x20\x32\x30\x34\x38\x29\xa");
# ifndef OPENSSL_NO_ENGINE
        BIO_printf(bio_err,
                   "\x20\x2d\x65\x6e\x67\x69\x6e\x65\x20\x65\x20\x20\x20\x20\x20\x75\x73\x65\x20\x65\x6e\x67\x69\x6e\x65\x20\x65\x2c\x20\x70\x6f\x73\x73\x69\x62\x6c\x79\x20\x61\x20\x68\x61\x72\x64\x77\x61\x72\x65\x20\x64\x65\x76\x69\x63\x65\x2e\xa");
# endif
        BIO_printf(bio_err, "\x20\x2d\x72\x61\x6e\x64\x20\x66\x69\x6c\x65\x25\x63\x66\x69\x6c\x65\x25\x63\x2e\x2e\x2e\xa", LIST_SEPARATOR_CHAR,
                   LIST_SEPARATOR_CHAR);
        BIO_printf(bio_err,
                   "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x6c\x6f\x61\x64\x20\x74\x68\x65\x20\x66\x69\x6c\x65\x20\x28\x6f\x72\x20\x74\x68\x65\x20\x66\x69\x6c\x65\x73\x20\x69\x6e\x20\x74\x68\x65\x20\x64\x69\x72\x65\x63\x74\x6f\x72\x79\x29\x20\x69\x6e\x74\x6f\xa");
        BIO_printf(bio_err, "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x74\x68\x65\x20\x72\x61\x6e\x64\x6f\x6d\x20\x6e\x75\x6d\x62\x65\x72\x20\x67\x65\x6e\x65\x72\x61\x74\x6f\x72\xa");
        BIO_printf(bio_err, "\x20\x2d\x6e\x6f\x6f\x75\x74\x20\x20\x20\x20\x20\x20\x20\x20\x6e\x6f\x20\x6f\x75\x74\x70\x75\x74\xa");
        goto end;
    }

    ERR_load_crypto_strings();

    e = setup_engine(bio_err, engine, 0);

    if (g && !num)
        num = DEFBITS;

# ifndef OPENSSL_NO_DSA
    if (dsaparam) {
        if (g) {
            BIO_printf(bio_err,
                       "\x67\x65\x6e\x65\x72\x61\x74\x6f\x72\x20\x6d\x61\x79\x20\x6e\x6f\x74\x20\x62\x65\x20\x63\x68\x6f\x73\x65\x6e\x20\x66\x6f\x72\x20\x44\x53\x41\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\xa");
            goto end;
        }
    } else
# endif
    {
        /* DH parameters */
        if (num && !g)
            g = 2;
    }

    if (num) {

        BN_GENCB cb;
        BN_GENCB_set(&cb, dh_cb, bio_err);
        if (!app_RAND_load_file(NULL, bio_err, 1) && inrand == NULL) {
            BIO_printf(bio_err,
                       "\x77\x61\x72\x6e\x69\x6e\x67\x2c\x20\x6e\x6f\x74\x20\x6d\x75\x63\x68\x20\x65\x78\x74\x72\x61\x20\x72\x61\x6e\x64\x6f\x6d\x20\x64\x61\x74\x61\x2c\x20\x63\x6f\x6e\x73\x69\x64\x65\x72\x20\x75\x73\x69\x6e\x67\x20\x74\x68\x65\x20\x2d\x72\x61\x6e\x64\x20\x6f\x70\x74\x69\x6f\x6e\xa");
        }
        if (inrand != NULL)
            BIO_printf(bio_err, "\x25\x6c\x64\x20\x73\x65\x6d\x69\x2d\x72\x61\x6e\x64\x6f\x6d\x20\x62\x79\x74\x65\x73\x20\x6c\x6f\x61\x64\x65\x64\xa",
                       app_RAND_load_files(inrand));

# ifndef OPENSSL_NO_DSA
        if (dsaparam) {
            DSA *dsa = DSA_new();

            BIO_printf(bio_err,
                       "\x47\x65\x6e\x65\x72\x61\x74\x69\x6e\x67\x20\x44\x53\x41\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\x2c\x20\x25\x64\x20\x62\x69\x74\x20\x6c\x6f\x6e\x67\x20\x70\x72\x69\x6d\x65\xa", num);
            if (!dsa
                || !DSA_generate_parameters_ex(dsa, num, NULL, 0, NULL, NULL,
                                               &cb)) {
                if (dsa)
                    DSA_free(dsa);
                ERR_print_errors(bio_err);
                goto end;
            }

            dh = DSA_dup_DH(dsa);
            DSA_free(dsa);
            if (dh == NULL) {
                ERR_print_errors(bio_err);
                goto end;
            }
        } else
# endif
        {
            dh = DH_new();
            BIO_printf(bio_err,
                       "\x47\x65\x6e\x65\x72\x61\x74\x69\x6e\x67\x20\x44\x48\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\x2c\x20\x25\x64\x20\x62\x69\x74\x20\x6c\x6f\x6e\x67\x20\x73\x61\x66\x65\x20\x70\x72\x69\x6d\x65\x2c\x20\x67\x65\x6e\x65\x72\x61\x74\x6f\x72\x20\x25\x64\xa",
                       num, g);
            BIO_printf(bio_err, "\x54\x68\x69\x73\x20\x69\x73\x20\x67\x6f\x69\x6e\x67\x20\x74\x6f\x20\x74\x61\x6b\x65\x20\x61\x20\x6c\x6f\x6e\x67\x20\x74\x69\x6d\x65\xa");
            if (!dh || !DH_generate_parameters_ex(dh, num, g, &cb)) {
                ERR_print_errors(bio_err);
                goto end;
            }
        }

        app_RAND_write_file(NULL, bio_err);
    } else {

        in = BIO_new(BIO_s_file());
        if (in == NULL) {
            ERR_print_errors(bio_err);
            goto end;
        }
        if (infile == NULL)
            BIO_set_fp(in, stdin, BIO_NOCLOSE);
        else {
            if (BIO_read_filename(in, infile) <= 0) {
                perror(infile);
                goto end;
            }
        }

        if (informat != FORMAT_ASN1 && informat != FORMAT_PEM) {
            BIO_printf(bio_err, "\x62\x61\x64\x20\x69\x6e\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\xa");
            goto end;
        }
# ifndef OPENSSL_NO_DSA
        if (dsaparam) {
            DSA *dsa;

            if (informat == FORMAT_ASN1)
                dsa = d2i_DSAparams_bio(in, NULL);
            else                /* informat == FORMAT_PEM */
                dsa = PEM_read_bio_DSAparams(in, NULL, NULL, NULL);

            if (dsa == NULL) {
                BIO_printf(bio_err, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x6c\x6f\x61\x64\x20\x44\x53\x41\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\xa");
                ERR_print_errors(bio_err);
                goto end;
            }

            dh = DSA_dup_DH(dsa);
            DSA_free(dsa);
            if (dh == NULL) {
                ERR_print_errors(bio_err);
                goto end;
            }
        } else
# endif
        {
            if (informat == FORMAT_ASN1) {
                /*
                 * We have no PEM header to determine what type of DH params it
                 * is. We'll just try both.
                 */
                dh = d2i_DHparams_bio(in, NULL);
                /* BIO_reset() returns 0 for success for file BIOs only!!! */
                if (dh == NULL && BIO_reset(in) == 0)
                    dh = d2i_DHxparams_bio(in, NULL);
            } else {
                /* informat == FORMAT_PEM */
                dh = PEM_read_bio_DHparams(in, NULL, NULL, NULL);
            }

            if (dh == NULL) {
                BIO_printf(bio_err, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x6c\x6f\x61\x64\x20\x44\x48\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\xa");
                ERR_print_errors(bio_err);
                goto end;
            }
        }

        /* dh != NULL */
    }

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

    if (text) {
        DHparams_print(out, dh);
    }

    if (check) {
        if (!DH_check(dh, &i)) {
            ERR_print_errors(bio_err);
            goto end;
        }
        if (i & DH_CHECK_P_NOT_PRIME)
            printf("\x70\x20\x76\x61\x6c\x75\x65\x20\x69\x73\x20\x6e\x6f\x74\x20\x70\x72\x69\x6d\x65\xa");
        if (i & DH_CHECK_P_NOT_SAFE_PRIME)
            printf("\x70\x20\x76\x61\x6c\x75\x65\x20\x69\x73\x20\x6e\x6f\x74\x20\x61\x20\x73\x61\x66\x65\x20\x70\x72\x69\x6d\x65\xa");
        if (i & DH_UNABLE_TO_CHECK_GENERATOR)
            printf("\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x63\x68\x65\x63\x6b\x20\x74\x68\x65\x20\x67\x65\x6e\x65\x72\x61\x74\x6f\x72\x20\x76\x61\x6c\x75\x65\xa");
        if (i & DH_NOT_SUITABLE_GENERATOR)
            printf("\x74\x68\x65\x20\x67\x20\x76\x61\x6c\x75\x65\x20\x69\x73\x20\x6e\x6f\x74\x20\x61\x20\x67\x65\x6e\x65\x72\x61\x74\x6f\x72\xa");
        if (i == 0)
            printf("\x44\x48\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\x20\x61\x70\x70\x65\x61\x72\x20\x74\x6f\x20\x62\x65\x20\x6f\x6b\x2e\xa");
    }
    if (C) {
        unsigned char *data;
        int len, l, bits;

        len = BN_num_bytes(dh->p);
        bits = BN_num_bits(dh->p);
        data = (unsigned char *)OPENSSL_malloc(len);
        if (data == NULL) {
            perror("\x4f\x50\x45\x4e\x53\x53\x4c\x5f\x6d\x61\x6c\x6c\x6f\x63");
            goto end;
        }
        printf("\x23\x69\x66\x6e\x64\x65\x66\x20\x48\x45\x41\x44\x45\x52\x5f\x44\x48\x5f\x48\xa"
               "\x23\x69\x6e\x63\x6c\x75\x64\x65\x20\x3c\x6f\x70\x65\x6e\x73\x73\x6c\x2f\x64\x68\x2e\x68\x3e\xa" "\x23\x65\x6e\x64\x69\x66\xa");
        printf("\x44\x48\x20\x2a\x67\x65\x74\x5f\x64\x68\x25\x64\x28\x29\xa\x9\x7b\xa", bits);

        l = BN_bn2bin(dh->p, data);
        printf("\x9\x73\x74\x61\x74\x69\x63\x20\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x63\x68\x61\x72\x20\x64\x68\x25\x64\x5f\x70\x5b\x5d\x3d\x7b", bits);
        for (i = 0; i < l; i++) {
            if ((i % 12) == 0)
                printf("\xa\x9\x9");
            printf("\x30\x78\x25\x30\x32\x58\x2c", data[i]);
        }
        printf("\xa\x9\x9\x7d\x3b\xa");

        l = BN_bn2bin(dh->g, data);
        printf("\x9\x73\x74\x61\x74\x69\x63\x20\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x63\x68\x61\x72\x20\x64\x68\x25\x64\x5f\x67\x5b\x5d\x3d\x7b", bits);
        for (i = 0; i < l; i++) {
            if ((i % 12) == 0)
                printf("\xa\x9\x9");
            printf("\x30\x78\x25\x30\x32\x58\x2c", data[i]);
        }
        printf("\xa\x9\x9\x7d\x3b\xa");

        printf("\x9D\x48\x20\x2a\x64\x68\x3b\xa\xa");
        printf("\x9\x69\x66\x20\x28\x28\x64\x68\x3d\x44\x48\x5f\x6e\x65\x77\x28\x29\x29\x20\x3d\x3d\x20\x4e\x55\x4c\x4c\x29\x20\x72\x65\x74\x75\x72\x6e\x28\x4e\x55\x4c\x4c\x29\x3b\xa");
        printf("\x9d\x68\x2d\x3e\x70\x3d\x42\x4e\x5f\x62\x69\x6e\x32\x62\x6e\x28\x64\x68\x25\x64\x5f\x70\x2c\x73\x69\x7a\x65\x6f\x66\x28\x64\x68\x25\x64\x5f\x70\x29\x2c\x4e\x55\x4c\x4c\x29\x3b\xa",
               bits, bits);
        printf("\x9d\x68\x2d\x3e\x67\x3d\x42\x4e\x5f\x62\x69\x6e\x32\x62\x6e\x28\x64\x68\x25\x64\x5f\x67\x2c\x73\x69\x7a\x65\x6f\x66\x28\x64\x68\x25\x64\x5f\x67\x29\x2c\x4e\x55\x4c\x4c\x29\x3b\xa",
               bits, bits);
        printf("\x9\x69\x66\x20\x28\x28\x64\x68\x2d\x3e\x70\x20\x3d\x3d\x20\x4e\x55\x4c\x4c\x29\x20\x7c\x7c\x20\x28\x64\x68\x2d\x3e\x67\x20\x3d\x3d\x20\x4e\x55\x4c\x4c\x29\x29\xa");
        printf("\x9\x9\x7b\x20\x44\x48\x5f\x66\x72\x65\x65\x28\x64\x68\x29\x3b\x20\x72\x65\x74\x75\x72\x6e\x28\x4e\x55\x4c\x4c\x29\x3b\x20\x7d\xa");
        if (dh->length)
            printf("\x9d\x68\x2d\x3e\x6c\x65\x6e\x67\x74\x68\x20\x3d\x20\x25\x6c\x64\x3b\xa", dh->length);
        printf("\x9\x72\x65\x74\x75\x72\x6e\x28\x64\x68\x29\x3b\xa\x9\x7d\xa");
        OPENSSL_free(data);
    }

    if (!noout) {
        if (outformat == FORMAT_ASN1) {
            if (dh->q != NULL)
                i = i2d_DHxparams_bio(out, dh);
            else
                i = i2d_DHparams_bio(out, dh);
        } else if (outformat == FORMAT_PEM) {
            if (dh->q != NULL)
                i = PEM_write_bio_DHxparams(out, dh);
            else
                i = PEM_write_bio_DHparams(out, dh);
        } else {
            BIO_printf(bio_err, "\x62\x61\x64\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\x20\x66\x6f\x72\x20\x6f\x75\x74\x66\x69\x6c\x65\xa");
            goto end;
        }
        if (!i) {
            BIO_printf(bio_err, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x77\x72\x69\x74\x65\x20\x44\x48\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\xa");
            ERR_print_errors(bio_err);
            goto end;
        }
    }
    ret = 0;
 end:
    if (in != NULL)
        BIO_free(in);
    if (out != NULL)
        BIO_free_all(out);
    if (dh != NULL)
        DH_free(dh);
    release_engine(e);
    apps_shutdown();
    OPENSSL_EXIT(ret);
}

/* dh_cb is identical to dsa_cb in apps/dsaparam.c */
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
