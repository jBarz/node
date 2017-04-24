/* apps/pkcs7.c */
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
#include <time.h>
#include "apps.h"
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/pem.h>

#undef PROG
#define PROG    pkcs7_main

/*-
 * -inform arg  - input format - default PEM (DER or PEM)
 * -outform arg - output format - default PEM
 * -in arg      - input file - default stdin
 * -out arg     - output file - default stdout
 * -print_certs
 */

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    PKCS7 *p7 = NULL;
    int i, badops = 0;
    BIO *in = NULL, *out = NULL;
    int informat, outformat;
    char *infile, *outfile, *prog;
    int print_certs = 0, text = 0, noout = 0, p7_print = 0;
    int ret = 1;
    char *engine = NULL;
    ENGINE *e = NULL;

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
        } else if (strcmp(*argv, "\x2d\x6e\x6f\x6f\x75\x74") == 0)
            noout = 1;
        else if (strcmp(*argv, "\x2d\x74\x65\x78\x74") == 0)
            text = 1;
        else if (strcmp(*argv, "\x2d\x70\x72\x69\x6e\x74") == 0)
            p7_print = 1;
        else if (strcmp(*argv, "\x2d\x70\x72\x69\x6e\x74\x5f\x63\x65\x72\x74\x73") == 0)
            print_certs = 1;
#ifndef OPENSSL_NO_ENGINE
        else if (strcmp(*argv, "\x2d\x65\x6e\x67\x69\x6e\x65") == 0) {
            if (--argc < 1)
                goto bad;
            engine = *(++argv);
        }
#endif
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
        BIO_printf(bio_err, "\x20\x2d\x69\x6e\x66\x6f\x72\x6d\x20\x61\x72\x67\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x2d\x20\x44\x45\x52\x20\x6f\x72\x20\x50\x45\x4d\xa");
        BIO_printf(bio_err, "\x20\x2d\x6f\x75\x74\x66\x6f\x72\x6d\x20\x61\x72\x67\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x2d\x20\x44\x45\x52\x20\x6f\x72\x20\x50\x45\x4d\xa");
        BIO_printf(bio_err, "\x20\x2d\x69\x6e\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err, "\x20\x2d\x6f\x75\x74\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err,
                   "\x20\x2d\x70\x72\x69\x6e\x74\x5f\x63\x65\x72\x74\x73\x20\x20\x70\x72\x69\x6e\x74\x20\x61\x6e\x79\x20\x63\x65\x72\x74\x73\x20\x6f\x72\x20\x63\x72\x6c\x20\x69\x6e\x20\x74\x68\x65\x20\x69\x6e\x70\x75\x74\xa");
        BIO_printf(bio_err,
                   "\x20\x2d\x74\x65\x78\x74\x20\x20\x20\x20\x20\x20\x20\x20\x20\x70\x72\x69\x6e\x74\x20\x66\x75\x6c\x6c\x20\x64\x65\x74\x61\x69\x6c\x73\x20\x6f\x66\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73\xa");
        BIO_printf(bio_err, "\x20\x2d\x6e\x6f\x6f\x75\x74\x20\x20\x20\x20\x20\x20\x20\x20\x64\x6f\x6e\x27\x74\x20\x6f\x75\x74\x70\x75\x74\x20\x65\x6e\x63\x6f\x64\x65\x64\x20\x64\x61\x74\x61\xa");
#ifndef OPENSSL_NO_ENGINE
        BIO_printf(bio_err,
                   "\x20\x2d\x65\x6e\x67\x69\x6e\x65\x20\x65\x20\x20\x20\x20\x20\x75\x73\x65\x20\x65\x6e\x67\x69\x6e\x65\x20\x65\x2c\x20\x70\x6f\x73\x73\x69\x62\x6c\x79\x20\x61\x20\x68\x61\x72\x64\x77\x61\x72\x65\x20\x64\x65\x76\x69\x63\x65\x2e\xa");
#endif
        ret = 1;
        goto end;
    }

    ERR_load_crypto_strings();

    e = setup_engine(bio_err, engine, 0);

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
            BIO_printf(bio_err, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x6c\x6f\x61\x64\x20\x69\x6e\x70\x75\x74\x20\x66\x69\x6c\x65\xa");
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (informat == FORMAT_ASN1)
        p7 = d2i_PKCS7_bio(in, NULL);
    else if (informat == FORMAT_PEM)
        p7 = PEM_read_bio_PKCS7(in, NULL, NULL, NULL);
    else {
        BIO_printf(bio_err, "\x62\x61\x64\x20\x69\x6e\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\x20\x66\x6f\x72\x20\x70\x6b\x63\x73\x37\x20\x6f\x62\x6a\x65\x63\x74\xa");
        goto end;
    }
    if (p7 == NULL) {
        BIO_printf(bio_err, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x6c\x6f\x61\x64\x20\x50\x4b\x43\x53\x37\x20\x6f\x62\x6a\x65\x63\x74\xa");
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

    if (p7_print)
        PKCS7_print_ctx(out, p7, 0, NULL);

    if (print_certs) {
        STACK_OF(X509) *certs = NULL;
        STACK_OF(X509_CRL) *crls = NULL;

        i = OBJ_obj2nid(p7->type);
        switch (i) {
        case NID_pkcs7_signed:
            if (p7->d.sign != NULL) {
                certs = p7->d.sign->cert;
                crls = p7->d.sign->crl;
            }
            break;
        case NID_pkcs7_signedAndEnveloped:
            if (p7->d.signed_and_enveloped != NULL) {
                certs = p7->d.signed_and_enveloped->cert;
                crls = p7->d.signed_and_enveloped->crl;
            }
            break;
        default:
            break;
        }

        if (certs != NULL) {
            X509 *x;

            for (i = 0; i < sk_X509_num(certs); i++) {
                x = sk_X509_value(certs, i);
                if (text)
                    X509_print(out, x);
                else
                    dump_cert_text(out, x);

                if (!noout)
                    PEM_write_bio_X509(out, x);
                BIO_puts(out, "\xa");
            }
        }
        if (crls != NULL) {
            X509_CRL *crl;

            for (i = 0; i < sk_X509_CRL_num(crls); i++) {
                crl = sk_X509_CRL_value(crls, i);

                X509_CRL_print(out, crl);

                if (!noout)
                    PEM_write_bio_X509_CRL(out, crl);
                BIO_puts(out, "\xa");
            }
        }

        ret = 0;
        goto end;
    }

    if (!noout) {
        if (outformat == FORMAT_ASN1)
            i = i2d_PKCS7_bio(out, p7);
        else if (outformat == FORMAT_PEM)
            i = PEM_write_bio_PKCS7(out, p7);
        else {
            BIO_printf(bio_err, "\x62\x61\x64\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\x20\x66\x6f\x72\x20\x6f\x75\x74\x66\x69\x6c\x65\xa");
            goto end;
        }

        if (!i) {
            BIO_printf(bio_err, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x77\x72\x69\x74\x65\x20\x70\x6b\x63\x73\x37\x20\x6f\x62\x6a\x65\x63\x74\xa");
            ERR_print_errors(bio_err);
            goto end;
        }
    }
    ret = 0;
 end:
    if (p7 != NULL)
        PKCS7_free(p7);
    release_engine(e);
    if (in != NULL)
        BIO_free(in);
    if (out != NULL)
        BIO_free_all(out);
    apps_shutdown();
    OPENSSL_EXIT(ret);
}
