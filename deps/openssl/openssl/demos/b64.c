/* demos/b64.c */
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
#include "../apps/apps.h"
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#undef SIZE
#undef BSIZE
#undef PROG

#define SIZE    (512)
#define BSIZE   (8*1024)
#define PROG    enc_main

int main(argc, argv)
int argc;
char **argv;
{
    char *strbuf = NULL;
    unsigned char *buff = NULL, *bufsize = NULL;
    int bsize = BSIZE, verbose = 0;
    int ret = 1, inl;
    char *str = NULL;
    char *hkey = NULL, *hiv = NULL;
    int enc = 1, printkey = 0, i, base64 = 0;
    int debug = 0;
    EVP_CIPHER *cipher = NULL, *c;
    char *inf = NULL, *outf = NULL;
    BIO *in = NULL, *out = NULL, *b64 = NULL, *benc = NULL, *rbio =
        NULL, *wbio = NULL;
#define PROG_NAME_SIZE  39

    apps_startup();

    if (bio_err == NULL)
        if ((bio_err = BIO_new(BIO_s_file())) != NULL)
            BIO_set_fp(bio_err, stderr, BIO_NOCLOSE);

    base64 = 1;

    argc--;
    argv++;
    while (argc >= 1) {
        if (strcmp(*argv, "\x2d\x65") == 0)
            enc = 1;
        if (strcmp(*argv, "\x2d\x69\x6e") == 0) {
            if (--argc < 1)
                goto bad;
            inf = *(++argv);
        } else if (strcmp(*argv, "\x2d\x6f\x75\x74") == 0) {
            if (--argc < 1)
                goto bad;
            outf = *(++argv);
        } else if (strcmp(*argv, "\x2d\x64") == 0)
            enc = 0;
        else if (strcmp(*argv, "\x2d\x76") == 0)
            verbose = 1;
        else if (strcmp(*argv, "\x2d\x64\x65\x62\x75\x67") == 0)
            debug = 1;
        else if (strcmp(*argv, "\x2d\x62\x75\x66\x73\x69\x7a\x65") == 0) {
            if (--argc < 1)
                goto bad;
            bufsize = (unsigned char *)*(++argv);
        } else {
            BIO_printf(bio_err, "\x75\x6e\x6b\x6e\x6f\x77\x6e\x20\x6f\x70\x74\x69\x6f\x6e\x20\x27\x25\x73\x27\xa", *argv);
 bad:
            BIO_printf(bio_err, "\x6f\x70\x74\x69\x6f\x6e\x73\x20\x61\x72\x65\xa");
            BIO_printf(bio_err, "\x25\x2d\x31\x34\x73\x20\x69\x6e\x70\x75\x74\x20\x66\x69\x6c\x65\xa", "\x2d\x69\x6e\x20\x3c\x66\x69\x6c\x65\x3e");
            BIO_printf(bio_err, "\x25\x2d\x31\x34\x73\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\xa", "\x2d\x6f\x75\x74\x20\x3c\x66\x69\x6c\x65\x3e");
            BIO_printf(bio_err, "\x25\x2d\x31\x34\x73\x20\x65\x6e\x63\x6f\x64\x65\xa", "\x2d\x65");
            BIO_printf(bio_err, "\x25\x2d\x31\x34\x73\x20\x64\x65\x63\x6f\x64\x65\xa", "\x2d\x64");
            BIO_printf(bio_err, "\x25\x2d\x31\x34\x73\x20\x62\x75\x66\x66\x65\x72\x20\x73\x69\x7a\x65\xa", "\x2d\x62\x75\x66\x73\x69\x7a\x65\x20\x3c\x6e\x3e");

            goto end;
        }
        argc--;
        argv++;
    }

    if (bufsize != NULL) {
        int i;
        unsigned long n;

        for (n = 0; *bufsize; bufsize++) {
            i = *bufsize;
            if ((i <= '\x39') && (i >= '\x30'))
                n = n * 10 + i - '\x30';
            else if (i == '\x6b') {
                n *= 1024;
                bufsize++;
                break;
            }
        }
        if (*bufsize != '\x0') {
            BIO_printf(bio_err, "\x69\x6e\x76\x61\x6c\x69\x64\x20\x27\x62\x75\x66\x73\x69\x7a\x65\x27\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\x2e\xa");
            goto end;
        }

        /* It must be large enough for a base64 encoded line */
        if (n < 80)
            n = 80;

        bsize = (int)n;
        if (verbose)
            BIO_printf(bio_err, "\x62\x75\x66\x73\x69\x7a\x65\x3d\x25\x64\xa", bsize);
    }

    strbuf = OPENSSL_malloc(SIZE);
    buff = (unsigned char *)OPENSSL_malloc(EVP_ENCODE_LENGTH(bsize));
    if ((buff == NULL) || (strbuf == NULL)) {
        BIO_printf(bio_err, "\x4f\x50\x45\x4e\x53\x53\x4c\x5f\x6d\x61\x6c\x6c\x6f\x63\x20\x66\x61\x69\x6c\x75\x72\x65\xa");
        goto end;
    }

    in = BIO_new(BIO_s_file());
    out = BIO_new(BIO_s_file());
    if ((in == NULL) || (out == NULL)) {
        ERR_print_errors(bio_err);
        goto end;
    }
    if (debug) {
        BIO_set_callback(in, BIO_debug_callback);
        BIO_set_callback(out, BIO_debug_callback);
        BIO_set_callback_arg(in, bio_err);
        BIO_set_callback_arg(out, bio_err);
    }

    if (inf == NULL)
        BIO_set_fp(in, stdin, BIO_NOCLOSE);
    else {
        if (BIO_read_filename(in, inf) <= 0) {
            perror(inf);
            goto end;
        }
    }

    if (outf == NULL)
        BIO_set_fp(out, stdout, BIO_NOCLOSE);
    else {
        if (BIO_write_filename(out, outf) <= 0) {
            perror(outf);
            goto end;
        }
    }

    rbio = in;
    wbio = out;

    if (base64) {
        if ((b64 = BIO_new(BIO_f_base64())) == NULL)
            goto end;
        if (debug) {
            BIO_set_callback(b64, BIO_debug_callback);
            BIO_set_callback_arg(b64, bio_err);
        }
        if (enc)
            wbio = BIO_push(b64, wbio);
        else
            rbio = BIO_push(b64, rbio);
    }

    for (;;) {
        inl = BIO_read(rbio, (char *)buff, bsize);
        if (inl <= 0)
            break;
        if (BIO_write(wbio, (char *)buff, inl) != inl) {
            BIO_printf(bio_err, "\x65\x72\x72\x6f\x72\x20\x77\x72\x69\x74\x69\x6e\x67\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\xa");
            goto end;
        }
    }
    BIO_flush(wbio);

    ret = 0;
    if (verbose) {
        BIO_printf(bio_err, "\x62\x79\x74\x65\x73\x20\x72\x65\x61\x64\x20\x20\x20\x3a\x25\x38\x6c\x64\xa", BIO_number_read(in));
        BIO_printf(bio_err, "\x62\x79\x74\x65\x73\x20\x77\x72\x69\x74\x74\x65\x6e\x3a\x25\x38\x6c\x64\xa", BIO_number_written(out));
    }
 end:
    if (strbuf != NULL)
        OPENSSL_free(strbuf);
    if (buff != NULL)
        OPENSSL_free(buff);
    if (in != NULL)
        BIO_free(in);
    if (out != NULL)
        BIO_free(out);
    if (benc != NULL)
        BIO_free(benc);
    if (b64 != NULL)
        BIO_free(b64);
    EXIT(ret);
}
