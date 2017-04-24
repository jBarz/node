/* apps/dh.c */
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

# undef PROG
# define PROG    dh_main

/*-
 * -inform arg  - input format - default PEM (DER or PEM)
 * -outform arg - output format - default PEM
 * -in arg      - input file - default stdin
 * -out arg     - output file - default stdout
 * -check       - check the parameters are ok
 * -noout
 * -text
 * -C
 */

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    DH *dh = NULL;
    int i, badops = 0, text = 0;
    BIO *in = NULL, *out = NULL;
    int informat, outformat, check = 0, noout = 0, C = 0, ret = 1;
    char *infile, *outfile, *prog;
    char *engine;

    apps_startup();

    if (bio_err == NULL)
        if ((bio_err = BIO_new(BIO_s_file())) != NULL)
            BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    if (!load_config(bio_err, NULL))
        goto end;

    engine = NULL;
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
        else if (strcmp(*argv, "\x2d\x43") == 0)
            C = 1;
        else if (strcmp(*argv, "\x2d\x6e\x6f\x6f\x75\x74") == 0)
            noout = 1;
        else {
            BIO_printf(bio_err, "\x75\x6e\x6b\x6e\x6f\x77\x6e\x20\x6f\x70\x74\x69\x6f\x6e\x20\x25\x73\xa", *argv);
            badops = 1;
            break;
        }
        argc--;
        argv++;
    }

    if (badops) {
 bad:
        BIO_printf(bio_err, "\x25\x73\x20\x5b\x6f\x70\x74\x69\x6f\x6e\x73\x5d\x20\x3c\x69\x6e\x66\x69\x6c\x65\x20\x3e\x6f\x75\x74\x66\x69\x6c\x65\xa", prog);
        BIO_printf(bio_err, "\x77\x68\x65\x72\x65\x20\x6f\x70\x74\x69\x6f\x6e\x73\x20\x61\x72\x65\xa");
        BIO_printf(bio_err, "\x20\x2d\x69\x6e\x66\x6f\x72\x6d\x20\x61\x72\x67\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x2d\x20\x6f\x6e\x65\x20\x6f\x66\x20\x44\x45\x52\x20\x50\x45\x4d\xa");
        BIO_printf(bio_err,
                   "\x20\x2d\x6f\x75\x74\x66\x6f\x72\x6d\x20\x61\x72\x67\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x2d\x20\x6f\x6e\x65\x20\x6f\x66\x20\x44\x45\x52\x20\x50\x45\x4d\xa");
        BIO_printf(bio_err, "\x20\x2d\x69\x6e\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err, "\x20\x2d\x6f\x75\x74\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err, "\x20\x2d\x63\x68\x65\x63\x6b\x20\x20\x20\x20\x20\x20\x20\x20\x63\x68\x65\x63\x6b\x20\x74\x68\x65\x20\x44\x48\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\xa");
        BIO_printf(bio_err,
                   "\x20\x2d\x74\x65\x78\x74\x20\x20\x20\x20\x20\x20\x20\x20\x20\x70\x72\x69\x6e\x74\x20\x61\x20\x74\x65\x78\x74\x20\x66\x6f\x72\x6d\x20\x6f\x66\x20\x74\x68\x65\x20\x44\x48\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\xa");
        BIO_printf(bio_err, "\x20\x2d\x43\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x4f\x75\x74\x70\x75\x74\x20\x43\x20\x63\x6f\x64\x65\xa");
        BIO_printf(bio_err, "\x20\x2d\x6e\x6f\x6f\x75\x74\x20\x20\x20\x20\x20\x20\x20\x20\x6e\x6f\x20\x6f\x75\x74\x70\x75\x74\xa");
# ifndef OPENSSL_NO_ENGINE
        BIO_printf(bio_err,
                   "\x20\x2d\x65\x6e\x67\x69\x6e\x65\x20\x65\x20\x20\x20\x20\x20\x75\x73\x65\x20\x65\x6e\x67\x69\x6e\x65\x20\x65\x2c\x20\x70\x6f\x73\x73\x69\x62\x6c\x79\x20\x61\x20\x68\x61\x72\x64\x77\x61\x72\x65\x20\x64\x65\x76\x69\x63\x65\x2e\xa");
# endif
        goto end;
    }

    ERR_load_crypto_strings();

    setup_engine(bio_err, engine, 0);

    in = BIO_new(BIO_s_file());
    out = BIO_new(BIO_s_file());
    if ((in == NULL) || (out == NULL)) {
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

    if (informat == FORMAT_ASN1)
        dh = d2i_DHparams_bio(in, NULL);
    else if (informat == FORMAT_PEM)
        dh = PEM_read_bio_DHparams(in, NULL, NULL, NULL);
    else {
        BIO_printf(bio_err, "\x62\x61\x64\x20\x69\x6e\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\xa");
        goto end;
    }
    if (dh == NULL) {
        BIO_printf(bio_err, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x6c\x6f\x61\x64\x20\x44\x48\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\xa");
        ERR_print_errors(bio_err);
        goto end;
    }

    if (text) {
        DHparams_print(out, dh);
# ifdef undef
        printf("\x70\x3d");
        BN_print(stdout, dh->p);
        printf("\xa\x67\x3d");
        BN_print(stdout, dh->g);
        printf("\xa");
        if (dh->length != 0)
            printf("\x72\x65\x63\x6f\x6d\x6d\x65\x6e\x64\x65\x64\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6c\x65\x6e\x67\x74\x68\x3d\x25\x6c\x64\xa", dh->length);
# endif
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
        l = BN_bn2bin(dh->p, data);
        printf("\x73\x74\x61\x74\x69\x63\x20\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x63\x68\x61\x72\x20\x64\x68\x25\x64\x5f\x70\x5b\x5d\x3d\x7b", bits);
        for (i = 0; i < l; i++) {
            if ((i % 12) == 0)
                printf("\xa\x9");
            printf("\x30\x78\x25\x30\x32\x58\x2c", data[i]);
        }
        printf("\xa\x9\x7d\x3b\xa");

        l = BN_bn2bin(dh->g, data);
        printf("\x73\x74\x61\x74\x69\x63\x20\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x63\x68\x61\x72\x20\x64\x68\x25\x64\x5f\x67\x5b\x5d\x3d\x7b", bits);
        for (i = 0; i < l; i++) {
            if ((i % 12) == 0)
                printf("\xa\x9");
            printf("\x30\x78\x25\x30\x32\x58\x2c", data[i]);
        }
        printf("\xa\x9\x7d\x3b\xa\xa");

        printf("\x44\x48\x20\x2a\x67\x65\x74\x5f\x64\x68\x25\x64\x28\x29\xa\x9\x7b\xa", bits);
        printf("\x9D\x48\x20\x2a\x64\x68\x3b\xa\xa");
        printf("\x9\x69\x66\x20\x28\x28\x64\x68\x3d\x44\x48\x5f\x6e\x65\x77\x28\x29\x29\x20\x3d\x3d\x20\x4e\x55\x4c\x4c\x29\x20\x72\x65\x74\x75\x72\x6e\x28\x4e\x55\x4c\x4c\x29\x3b\xa");
        printf("\x9d\x68\x2d\x3e\x70\x3d\x42\x4e\x5f\x62\x69\x6e\x32\x62\x6e\x28\x64\x68\x25\x64\x5f\x70\x2c\x73\x69\x7a\x65\x6f\x66\x28\x64\x68\x25\x64\x5f\x70\x29\x2c\x4e\x55\x4c\x4c\x29\x3b\xa",
               bits, bits);
        printf("\x9d\x68\x2d\x3e\x67\x3d\x42\x4e\x5f\x62\x69\x6e\x32\x62\x6e\x28\x64\x68\x25\x64\x5f\x67\x2c\x73\x69\x7a\x65\x6f\x66\x28\x64\x68\x25\x64\x5f\x67\x29\x2c\x4e\x55\x4c\x4c\x29\x3b\xa",
               bits, bits);
        printf("\x9\x69\x66\x20\x28\x28\x64\x68\x2d\x3e\x70\x20\x3d\x3d\x20\x4e\x55\x4c\x4c\x29\x20\x7c\x7c\x20\x28\x64\x68\x2d\x3e\x67\x20\x3d\x3d\x20\x4e\x55\x4c\x4c\x29\x29\xa");
        printf("\x9\x9\x72\x65\x74\x75\x72\x6e\x28\x4e\x55\x4c\x4c\x29\x3b\xa");
        printf("\x9\x72\x65\x74\x75\x72\x6e\x28\x64\x68\x29\x3b\xa\x9\x7d\xa");
        OPENSSL_free(data);
    }

    if (!noout) {
        if (outformat == FORMAT_ASN1)
            i = i2d_DHparams_bio(out, dh);
        else if (outformat == FORMAT_PEM)
            i = PEM_write_bio_DHparams(out, dh);
        else {
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
    apps_shutdown();
    OPENSSL_EXIT(ret);
}
#else                           /* !OPENSSL_NO_DH */

# if PEDANTIC
static void *dummy = &dummy;
# endif

#endif
