/* apps/ec.c */
/*
 * Written by Nils Larsch for the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 1998-2005 The OpenSSL Project.  All rights reserved.
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

#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_EC
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include "apps.h"
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/evp.h>
# include <openssl/pem.h>

# undef PROG
# define PROG    ec_main

/*-
 * -inform arg    - input format - default PEM (one of DER, NET or PEM)
 * -outform arg   - output format - default PEM
 * -in arg        - input file - default stdin
 * -out arg       - output file - default stdout
 * -des           - encrypt output if PEM format with DES in cbc mode
 * -text          - print a text version
 * -param_out     - print the elliptic curve parameters
 * -conv_form arg - specifies the point encoding form
 * -param_enc arg - specifies the parameter encoding
 */

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    int ret = 1;
    EC_KEY *eckey = NULL;
    const EC_GROUP *group;
    int i, badops = 0;
    const EVP_CIPHER *enc = NULL;
    BIO *in = NULL, *out = NULL;
    int informat, outformat, text = 0, noout = 0;
    int pubin = 0, pubout = 0, param_out = 0;
    char *infile, *outfile, *prog, *engine;
    ENGINE *e = NULL;
    char *passargin = NULL, *passargout = NULL;
    char *passin = NULL, *passout = NULL;
    point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;
    int new_form = 0;
    int asn1_flag = OPENSSL_EC_NAMED_CURVE;
    int new_asn1_flag = 0;

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
        } else if (strcmp(*argv, "\x2d\x70\x61\x73\x73\x69\x6e") == 0) {
            if (--argc < 1)
                goto bad;
            passargin = *(++argv);
        } else if (strcmp(*argv, "\x2d\x70\x61\x73\x73\x6f\x75\x74") == 0) {
            if (--argc < 1)
                goto bad;
            passargout = *(++argv);
        } else if (strcmp(*argv, "\x2d\x65\x6e\x67\x69\x6e\x65") == 0) {
            if (--argc < 1)
                goto bad;
            engine = *(++argv);
        } else if (strcmp(*argv, "\x2d\x6e\x6f\x6f\x75\x74") == 0)
            noout = 1;
        else if (strcmp(*argv, "\x2d\x74\x65\x78\x74") == 0)
            text = 1;
        else if (strcmp(*argv, "\x2d\x63\x6f\x6e\x76\x5f\x66\x6f\x72\x6d") == 0) {
            if (--argc < 1)
                goto bad;
            ++argv;
            new_form = 1;
            if (strcmp(*argv, "\x63\x6f\x6d\x70\x72\x65\x73\x73\x65\x64") == 0)
                form = POINT_CONVERSION_COMPRESSED;
            else if (strcmp(*argv, "\x75\x6e\x63\x6f\x6d\x70\x72\x65\x73\x73\x65\x64") == 0)
                form = POINT_CONVERSION_UNCOMPRESSED;
            else if (strcmp(*argv, "\x68\x79\x62\x72\x69\x64") == 0)
                form = POINT_CONVERSION_HYBRID;
            else
                goto bad;
        } else if (strcmp(*argv, "\x2d\x70\x61\x72\x61\x6d\x5f\x65\x6e\x63") == 0) {
            if (--argc < 1)
                goto bad;
            ++argv;
            new_asn1_flag = 1;
            if (strcmp(*argv, "\x6e\x61\x6d\x65\x64\x5f\x63\x75\x72\x76\x65") == 0)
                asn1_flag = OPENSSL_EC_NAMED_CURVE;
            else if (strcmp(*argv, "\x65\x78\x70\x6c\x69\x63\x69\x74") == 0)
                asn1_flag = 0;
            else
                goto bad;
        } else if (strcmp(*argv, "\x2d\x70\x61\x72\x61\x6d\x5f\x6f\x75\x74") == 0)
            param_out = 1;
        else if (strcmp(*argv, "\x2d\x70\x75\x62\x69\x6e") == 0)
            pubin = 1;
        else if (strcmp(*argv, "\x2d\x70\x75\x62\x6f\x75\x74") == 0)
            pubout = 1;
        else if ((enc = EVP_get_cipherbyname(&(argv[0][1]))) == NULL) {
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
        BIO_printf(bio_err, "\x20\x2d\x69\x6e\x66\x6f\x72\x6d\x20\x61\x72\x67\x20\x20\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x2d\x20"
                   "\x44\x45\x52\x20\x6f\x72\x20\x50\x45\x4d\xa");
        BIO_printf(bio_err, "\x20\x2d\x6f\x75\x74\x66\x6f\x72\x6d\x20\x61\x72\x67\x20\x20\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x2d\x20"
                   "\x44\x45\x52\x20\x6f\x72\x20\x50\x45\x4d\xa");
        BIO_printf(bio_err, "\x20\x2d\x69\x6e\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err, "\x20\x2d\x70\x61\x73\x73\x69\x6e\x20\x61\x72\x67\x20\x20\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x66\x69\x6c\x65\x20\x70\x61\x73\x73\x20"
                   "\x70\x68\x72\x61\x73\x65\x20\x73\x6f\x75\x72\x63\x65\xa");
        BIO_printf(bio_err, "\x20\x2d\x6f\x75\x74\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err, "\x20\x2d\x70\x61\x73\x73\x6f\x75\x74\x20\x61\x72\x67\x20\x20\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\x20\x70\x61\x73\x73\x20"
                   "\x70\x68\x72\x61\x73\x65\x20\x73\x6f\x75\x72\x63\x65\xa");
        BIO_printf(bio_err, "\x20\x2d\x65\x6e\x67\x69\x6e\x65\x20\x65\x20\x20\x20\x20\x20\x20\x20\x75\x73\x65\x20\x65\x6e\x67\x69\x6e\x65\x20\x65\x2c\x20"
                   "\x70\x6f\x73\x73\x69\x62\x6c\x79\x20\x61\x20\x68\x61\x72\x64\x77\x61\x72\x65\x20\x64\x65\x76\x69\x63\x65\x2e\xa");
        BIO_printf(bio_err, "\x20\x2d\x64\x65\x73\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x50\x45\x4d\x20\x6f\x75\x74\x70\x75\x74\x2c\x20"
                   "\x69\x6e\x73\x74\x65\x61\x64\x20\x6f\x66\x20\x27\x64\x65\x73\x27\x20\x65\x76\x65\x72\x79\x20\x6f\x74\x68\x65\x72\x20\xa"
                   "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x63\x69\x70\x68\x65\x72\x20"
                   "\x73\x75\x70\x70\x6f\x72\x74\x65\x64\x20\x62\x79\x20\x4f\x70\x65\x6e\x53\x53\x4c\x20\x63\x61\x6e\x20\x62\x65\x20\x75\x73\x65\x64\xa");
        BIO_printf(bio_err, "\x20\x2d\x74\x65\x78\x74\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x70\x72\x69\x6e\x74\x20\x74\x68\x65\x20\x6b\x65\x79\xa");
        BIO_printf(bio_err, "\x20\x2d\x6e\x6f\x6f\x75\x74\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x64\x6f\x6e\x27\x74\x20\x70\x72\x69\x6e\x74\x20\x6b\x65\x79\x20\x6f\x75\x74\xa");
        BIO_printf(bio_err, "\x20\x2d\x70\x61\x72\x61\x6d\x5f\x6f\x75\x74\x20\x20\x20\x20\x20\x20\x70\x72\x69\x6e\x74\x20\x74\x68\x65\x20\x65\x6c\x6c\x69\x70\x74\x69\x63\x20"
                   "\x63\x75\x72\x76\x65\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\xa");
        BIO_printf(bio_err, "\x20\x2d\x63\x6f\x6e\x76\x5f\x66\x6f\x72\x6d\x20\x61\x72\x67\x20\x20\x73\x70\x65\x63\x69\x66\x69\x65\x73\x20\x74\x68\x65\x20"
                   "\x70\x6f\x69\x6e\x74\x20\x63\x6f\x6e\x76\x65\x72\x73\x69\x6f\x6e\x20\x66\x6f\x72\x6d\x20\xa");
        BIO_printf(bio_err, "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x70\x6f\x73\x73\x69\x62\x6c\x65\x20\x76\x61\x6c\x75\x65\x73\x3a"
                   "\x20\x63\x6f\x6d\x70\x72\x65\x73\x73\x65\x64\xa");
        BIO_printf(bio_err, "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20"
                   "\x20\x75\x6e\x63\x6f\x6d\x70\x72\x65\x73\x73\x65\x64\x20\x28\x64\x65\x66\x61\x75\x6c\x74\x29\xa");
        BIO_printf(bio_err, "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20" "\x20\x68\x79\x62\x72\x69\x64\xa");
        BIO_printf(bio_err, "\x20\x2d\x70\x61\x72\x61\x6d\x5f\x65\x6e\x63\x20\x61\x72\x67\x20\x20\x73\x70\x65\x63\x69\x66\x69\x65\x73\x20\x74\x68\x65\x20\x77\x61\x79"
                   "\x20\x74\x68\x65\x20\x65\x63\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\x20\x61\x72\x65\x20\x65\x6e\x63\x6f\x64\x65\x64\xa");
        BIO_printf(bio_err, "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x69\x6e\x20\x74\x68\x65\x20\x61\x73\x6e\x31\x20\x64\x65\x72\x20" "\x65\x6e\x63\x6f\x64\x69\x6e\x67\xa");
        BIO_printf(bio_err, "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x70\x6f\x73\x73\x69\x62\x6c\x65\x20\x76\x61\x6c\x75\x65\x73\x3a"
                   "\x20\x6e\x61\x6d\x65\x64\x5f\x63\x75\x72\x76\x65\x20\x28\x64\x65\x66\x61\x75\x6c\x74\x29\xa");
        BIO_printf(bio_err, "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20"
                   "\x65\x78\x70\x6c\x69\x63\x69\x74\xa");
        goto end;
    }

    ERR_load_crypto_strings();

    e = setup_engine(bio_err, engine, 0);

    if (!app_passwd(bio_err, passargin, passargout, &passin, &passout)) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x67\x65\x74\x74\x69\x6e\x67\x20\x70\x61\x73\x73\x77\x6f\x72\x64\x73\xa");
        goto end;
    }

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

    BIO_printf(bio_err, "\x72\x65\x61\x64\x20\x45\x43\x20\x6b\x65\x79\xa");
    if (informat == FORMAT_ASN1) {
        if (pubin)
            eckey = d2i_EC_PUBKEY_bio(in, NULL);
        else
            eckey = d2i_ECPrivateKey_bio(in, NULL);
    } else if (informat == FORMAT_PEM) {
        if (pubin)
            eckey = PEM_read_bio_EC_PUBKEY(in, NULL, NULL, NULL);
        else
            eckey = PEM_read_bio_ECPrivateKey(in, NULL, NULL, passin);
    } else {
        BIO_printf(bio_err, "\x62\x61\x64\x20\x69\x6e\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\x20\x66\x6f\x72\x20\x6b\x65\x79\xa");
        goto end;
    }
    if (eckey == NULL) {
        BIO_printf(bio_err, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x6c\x6f\x61\x64\x20\x4b\x65\x79\xa");
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

    group = EC_KEY_get0_group(eckey);

    if (new_form)
        EC_KEY_set_conv_form(eckey, form);

    if (new_asn1_flag)
        EC_KEY_set_asn1_flag(eckey, asn1_flag);

    if (text)
        if (!EC_KEY_print(out, eckey, 0)) {
            perror(outfile);
            ERR_print_errors(bio_err);
            goto end;
        }

    if (noout) {
        ret = 0;
        goto end;
    }

    BIO_printf(bio_err, "\x77\x72\x69\x74\x69\x6e\x67\x20\x45\x43\x20\x6b\x65\x79\xa");
    if (outformat == FORMAT_ASN1) {
        if (param_out)
            i = i2d_ECPKParameters_bio(out, group);
        else if (pubin || pubout)
            i = i2d_EC_PUBKEY_bio(out, eckey);
        else
            i = i2d_ECPrivateKey_bio(out, eckey);
    } else if (outformat == FORMAT_PEM) {
        if (param_out)
            i = PEM_write_bio_ECPKParameters(out, group);
        else if (pubin || pubout)
            i = PEM_write_bio_EC_PUBKEY(out, eckey);
        else
            i = PEM_write_bio_ECPrivateKey(out, eckey, enc,
                                           NULL, 0, NULL, passout);
    } else {
        BIO_printf(bio_err, "\x62\x61\x64\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\x20\x66\x6f\x72\x20" "\x6f\x75\x74\x66\x69\x6c\x65\xa");
        goto end;
    }

    if (!i) {
        BIO_printf(bio_err, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x77\x72\x69\x74\x65\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\xa");
        ERR_print_errors(bio_err);
    } else
        ret = 0;
 end:
    if (in)
        BIO_free(in);
    if (out)
        BIO_free_all(out);
    if (eckey)
        EC_KEY_free(eckey);
    release_engine(e);
    if (passin)
        OPENSSL_free(passin);
    if (passout)
        OPENSSL_free(passout);
    apps_shutdown();
    OPENSSL_EXIT(ret);
}
#else                           /* !OPENSSL_NO_EC */

# if PEDANTIC
static void *dummy = &dummy;
# endif

#endif
