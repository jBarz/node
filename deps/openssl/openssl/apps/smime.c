/* smime.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 1999-2004 The OpenSSL Project.  All rights reserved.
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

/* S/MIME utility function */

#include <stdio.h>
#include <string.h>
#include "apps.h"
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#undef PROG
#define PROG smime_main
static int save_certs(char *signerfile, STACK_OF(X509) *signers);
static int smime_cb(int ok, X509_STORE_CTX *ctx);

#define SMIME_OP        0x10
#define SMIME_IP        0x20
#define SMIME_SIGNERS   0x40
#define SMIME_ENCRYPT   (1 | SMIME_OP)
#define SMIME_DECRYPT   (2 | SMIME_IP)
#define SMIME_SIGN      (3 | SMIME_OP | SMIME_SIGNERS)
#define SMIME_VERIFY    (4 | SMIME_IP)
#define SMIME_PK7OUT    (5 | SMIME_IP | SMIME_OP)
#define SMIME_RESIGN    (6 | SMIME_IP | SMIME_OP | SMIME_SIGNERS)

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    ENGINE *e = NULL;
    int operation = 0;
    int ret = 0;
    char **args;
    const char *inmode = "\x72", *outmode = "\x77";
    char *infile = NULL, *outfile = NULL;
    char *signerfile = NULL, *recipfile = NULL;
    STACK_OF(OPENSSL_STRING) *sksigners = NULL, *skkeys = NULL;
    char *certfile = NULL, *keyfile = NULL, *contfile = NULL;
    const EVP_CIPHER *cipher = NULL;
    PKCS7 *p7 = NULL;
    X509_STORE *store = NULL;
    X509 *cert = NULL, *recip = NULL, *signer = NULL;
    EVP_PKEY *key = NULL;
    STACK_OF(X509) *encerts = NULL, *other = NULL;
    BIO *in = NULL, *out = NULL, *indata = NULL;
    int badarg = 0;
    int flags = PKCS7_DETACHED;
    char *to = NULL, *from = NULL, *subject = NULL;
    char *CAfile = NULL, *CApath = NULL;
    char *passargin = NULL, *passin = NULL;
    char *inrand = NULL;
    int need_rand = 0;
    int indef = 0;
    const EVP_MD *sign_md = NULL;
    int informat = FORMAT_SMIME, outformat = FORMAT_SMIME;
    int keyform = FORMAT_PEM;
    char *engine = NULL;

    X509_VERIFY_PARAM *vpm = NULL;

    args = argv + 1;
    ret = 1;

    apps_startup();

    if (bio_err == NULL) {
        if ((bio_err = BIO_new(BIO_s_file())) != NULL)
            BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);
    }

    if (!load_config(bio_err, NULL))
        goto end;

    while (!badarg && *args && *args[0] == '\x2d') {
        if (!strcmp(*args, "\x2d\x65\x6e\x63\x72\x79\x70\x74"))
            operation = SMIME_ENCRYPT;
        else if (!strcmp(*args, "\x2d\x64\x65\x63\x72\x79\x70\x74"))
            operation = SMIME_DECRYPT;
        else if (!strcmp(*args, "\x2d\x73\x69\x67\x6e"))
            operation = SMIME_SIGN;
        else if (!strcmp(*args, "\x2d\x72\x65\x73\x69\x67\x6e"))
            operation = SMIME_RESIGN;
        else if (!strcmp(*args, "\x2d\x76\x65\x72\x69\x66\x79"))
            operation = SMIME_VERIFY;
        else if (!strcmp(*args, "\x2d\x70\x6b\x37\x6f\x75\x74"))
            operation = SMIME_PK7OUT;
#ifndef OPENSSL_NO_DES
        else if (!strcmp(*args, "\x2d\x64\x65\x73\x33"))
            cipher = EVP_des_ede3_cbc();
        else if (!strcmp(*args, "\x2d\x64\x65\x73"))
            cipher = EVP_des_cbc();
#endif
#ifndef OPENSSL_NO_SEED
        else if (!strcmp(*args, "\x2d\x73\x65\x65\x64"))
            cipher = EVP_seed_cbc();
#endif
#ifndef OPENSSL_NO_RC2
        else if (!strcmp(*args, "\x2d\x72\x63\x32\x2d\x34\x30"))
            cipher = EVP_rc2_40_cbc();
        else if (!strcmp(*args, "\x2d\x72\x63\x32\x2d\x31\x32\x38"))
            cipher = EVP_rc2_cbc();
        else if (!strcmp(*args, "\x2d\x72\x63\x32\x2d\x36\x34"))
            cipher = EVP_rc2_64_cbc();
#endif
#ifndef OPENSSL_NO_AES
        else if (!strcmp(*args, "\x2d\x61\x65\x73\x31\x32\x38"))
            cipher = EVP_aes_128_cbc();
        else if (!strcmp(*args, "\x2d\x61\x65\x73\x31\x39\x32"))
            cipher = EVP_aes_192_cbc();
        else if (!strcmp(*args, "\x2d\x61\x65\x73\x32\x35\x36"))
            cipher = EVP_aes_256_cbc();
#endif
#ifndef OPENSSL_NO_CAMELLIA
        else if (!strcmp(*args, "\x2d\x63\x61\x6d\x65\x6c\x6c\x69\x61\x31\x32\x38"))
            cipher = EVP_camellia_128_cbc();
        else if (!strcmp(*args, "\x2d\x63\x61\x6d\x65\x6c\x6c\x69\x61\x31\x39\x32"))
            cipher = EVP_camellia_192_cbc();
        else if (!strcmp(*args, "\x2d\x63\x61\x6d\x65\x6c\x6c\x69\x61\x32\x35\x36"))
            cipher = EVP_camellia_256_cbc();
#endif
        else if (!strcmp(*args, "\x2d\x74\x65\x78\x74"))
            flags |= PKCS7_TEXT;
        else if (!strcmp(*args, "\x2d\x6e\x6f\x69\x6e\x74\x65\x72\x6e"))
            flags |= PKCS7_NOINTERN;
        else if (!strcmp(*args, "\x2d\x6e\x6f\x76\x65\x72\x69\x66\x79"))
            flags |= PKCS7_NOVERIFY;
        else if (!strcmp(*args, "\x2d\x6e\x6f\x63\x68\x61\x69\x6e"))
            flags |= PKCS7_NOCHAIN;
        else if (!strcmp(*args, "\x2d\x6e\x6f\x63\x65\x72\x74\x73"))
            flags |= PKCS7_NOCERTS;
        else if (!strcmp(*args, "\x2d\x6e\x6f\x61\x74\x74\x72"))
            flags |= PKCS7_NOATTR;
        else if (!strcmp(*args, "\x2d\x6e\x6f\x64\x65\x74\x61\x63\x68"))
            flags &= ~PKCS7_DETACHED;
        else if (!strcmp(*args, "\x2d\x6e\x6f\x73\x6d\x69\x6d\x65\x63\x61\x70"))
            flags |= PKCS7_NOSMIMECAP;
        else if (!strcmp(*args, "\x2d\x62\x69\x6e\x61\x72\x79"))
            flags |= PKCS7_BINARY;
        else if (!strcmp(*args, "\x2d\x6e\x6f\x73\x69\x67\x73"))
            flags |= PKCS7_NOSIGS;
        else if (!strcmp(*args, "\x2d\x73\x74\x72\x65\x61\x6d"))
            indef = 1;
        else if (!strcmp(*args, "\x2d\x69\x6e\x64\x65\x66"))
            indef = 1;
        else if (!strcmp(*args, "\x2d\x6e\x6f\x69\x6e\x64\x65\x66"))
            indef = 0;
        else if (!strcmp(*args, "\x2d\x6e\x6f\x6f\x6c\x64\x6d\x69\x6d\x65"))
            flags |= PKCS7_NOOLDMIMETYPE;
        else if (!strcmp(*args, "\x2d\x63\x72\x6c\x66\x65\x6f\x6c"))
            flags |= PKCS7_CRLFEOL;
        else if (!strcmp(*args, "\x2d\x72\x61\x6e\x64")) {
            if (!args[1])
                goto argerr;
            args++;
            inrand = *args;
            need_rand = 1;
        }
#ifndef OPENSSL_NO_ENGINE
        else if (!strcmp(*args, "\x2d\x65\x6e\x67\x69\x6e\x65")) {
            if (!args[1])
                goto argerr;
            engine = *++args;
        }
#endif
        else if (!strcmp(*args, "\x2d\x70\x61\x73\x73\x69\x6e")) {
            if (!args[1])
                goto argerr;
            passargin = *++args;
        } else if (!strcmp(*args, "\x2d\x74\x6f")) {
            if (!args[1])
                goto argerr;
            to = *++args;
        } else if (!strcmp(*args, "\x2d\x66\x72\x6f\x6d")) {
            if (!args[1])
                goto argerr;
            from = *++args;
        } else if (!strcmp(*args, "\x2d\x73\x75\x62\x6a\x65\x63\x74")) {
            if (!args[1])
                goto argerr;
            subject = *++args;
        } else if (!strcmp(*args, "\x2d\x73\x69\x67\x6e\x65\x72")) {
            if (!args[1])
                goto argerr;
            /* If previous -signer argument add signer to list */

            if (signerfile) {
                if (!sksigners)
                    sksigners = sk_OPENSSL_STRING_new_null();
                sk_OPENSSL_STRING_push(sksigners, signerfile);
                if (!keyfile)
                    keyfile = signerfile;
                if (!skkeys)
                    skkeys = sk_OPENSSL_STRING_new_null();
                sk_OPENSSL_STRING_push(skkeys, keyfile);
                keyfile = NULL;
            }
            signerfile = *++args;
        } else if (!strcmp(*args, "\x2d\x72\x65\x63\x69\x70")) {
            if (!args[1])
                goto argerr;
            recipfile = *++args;
        } else if (!strcmp(*args, "\x2d\x6d\x64")) {
            if (!args[1])
                goto argerr;
            sign_md = EVP_get_digestbyname(*++args);
            if (sign_md == NULL) {
                BIO_printf(bio_err, "\x55\x6e\x6b\x6e\x6f\x77\x6e\x20\x64\x69\x67\x65\x73\x74\x20\x25\x73\xa", *args);
                goto argerr;
            }
        } else if (!strcmp(*args, "\x2d\x69\x6e\x6b\x65\x79")) {
            if (!args[1])
                goto argerr;
            /* If previous -inkey arument add signer to list */
            if (keyfile) {
                if (!signerfile) {
                    BIO_puts(bio_err, "\x49\x6c\x6c\x65\x67\x61\x6c\x20\x2d\x69\x6e\x6b\x65\x79\x20\x77\x69\x74\x68\x6f\x75\x74\x20\x2d\x73\x69\x67\x6e\x65\x72\xa");
                    goto argerr;
                }
                if (!sksigners)
                    sksigners = sk_OPENSSL_STRING_new_null();
                sk_OPENSSL_STRING_push(sksigners, signerfile);
                signerfile = NULL;
                if (!skkeys)
                    skkeys = sk_OPENSSL_STRING_new_null();
                sk_OPENSSL_STRING_push(skkeys, keyfile);
            }
            keyfile = *++args;
        } else if (!strcmp(*args, "\x2d\x6b\x65\x79\x66\x6f\x72\x6d")) {
            if (!args[1])
                goto argerr;
            keyform = str2fmt(*++args);
        } else if (!strcmp(*args, "\x2d\x63\x65\x72\x74\x66\x69\x6c\x65")) {
            if (!args[1])
                goto argerr;
            certfile = *++args;
        } else if (!strcmp(*args, "\x2d\x43\x41\x66\x69\x6c\x65")) {
            if (!args[1])
                goto argerr;
            CAfile = *++args;
        } else if (!strcmp(*args, "\x2d\x43\x41\x70\x61\x74\x68")) {
            if (!args[1])
                goto argerr;
            CApath = *++args;
        } else if (!strcmp(*args, "\x2d\x69\x6e")) {
            if (!args[1])
                goto argerr;
            infile = *++args;
        } else if (!strcmp(*args, "\x2d\x69\x6e\x66\x6f\x72\x6d")) {
            if (!args[1])
                goto argerr;
            informat = str2fmt(*++args);
        } else if (!strcmp(*args, "\x2d\x6f\x75\x74\x66\x6f\x72\x6d")) {
            if (!args[1])
                goto argerr;
            outformat = str2fmt(*++args);
        } else if (!strcmp(*args, "\x2d\x6f\x75\x74")) {
            if (!args[1])
                goto argerr;
            outfile = *++args;
        } else if (!strcmp(*args, "\x2d\x63\x6f\x6e\x74\x65\x6e\x74")) {
            if (!args[1])
                goto argerr;
            contfile = *++args;
        } else if (args_verify(&args, NULL, &badarg, bio_err, &vpm))
            continue;
        else if ((cipher = EVP_get_cipherbyname(*args + 1)) == NULL)
            badarg = 1;
        args++;
    }

    if (!(operation & SMIME_SIGNERS) && (skkeys || sksigners)) {
        BIO_puts(bio_err, "\x4d\x75\x6c\x74\x69\x70\x6c\x65\x20\x73\x69\x67\x6e\x65\x72\x73\x20\x6f\x72\x20\x6b\x65\x79\x73\x20\x6e\x6f\x74\x20\x61\x6c\x6c\x6f\x77\x65\x64\xa");
        goto argerr;
    }

    if (operation & SMIME_SIGNERS) {
        /* Check to see if any final signer needs to be appended */
        if (keyfile && !signerfile) {
            BIO_puts(bio_err, "\x49\x6c\x6c\x65\x67\x61\x6c\x20\x2d\x69\x6e\x6b\x65\x79\x20\x77\x69\x74\x68\x6f\x75\x74\x20\x2d\x73\x69\x67\x6e\x65\x72\xa");
            goto argerr;
        }
        if (signerfile) {
            if (!sksigners)
                sksigners = sk_OPENSSL_STRING_new_null();
            sk_OPENSSL_STRING_push(sksigners, signerfile);
            if (!skkeys)
                skkeys = sk_OPENSSL_STRING_new_null();
            if (!keyfile)
                keyfile = signerfile;
            sk_OPENSSL_STRING_push(skkeys, keyfile);
        }
        if (!sksigners) {
            BIO_printf(bio_err, "\x4e\x6f\x20\x73\x69\x67\x6e\x65\x72\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\xa");
            badarg = 1;
        }
        signerfile = NULL;
        keyfile = NULL;
        need_rand = 1;
    } else if (operation == SMIME_DECRYPT) {
        if (!recipfile && !keyfile) {
            BIO_printf(bio_err,
                       "\x4e\x6f\x20\x72\x65\x63\x69\x70\x69\x65\x6e\x74\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x6f\x72\x20\x6b\x65\x79\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\xa");
            badarg = 1;
        }
    } else if (operation == SMIME_ENCRYPT) {
        if (!*args) {
            BIO_printf(bio_err, "\x4e\x6f\x20\x72\x65\x63\x69\x70\x69\x65\x6e\x74\x28\x73\x29\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x28\x73\x29\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\xa");
            badarg = 1;
        }
        need_rand = 1;
    } else if (!operation)
        badarg = 1;

    if (badarg) {
 argerr:
        BIO_printf(bio_err, "\x55\x73\x61\x67\x65\x20\x73\x6d\x69\x6d\x65\x20\x5b\x6f\x70\x74\x69\x6f\x6e\x73\x5d\x20\x63\x65\x72\x74\x2e\x70\x65\x6d\x20\x2e\x2e\x2e\xa");
        BIO_printf(bio_err, "\x77\x68\x65\x72\x65\x20\x6f\x70\x74\x69\x6f\x6e\x73\x20\x61\x72\x65\xa");
        BIO_printf(bio_err, "\x2d\x65\x6e\x63\x72\x79\x70\x74\x20\x20\x20\x20\x20\x20\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x6d\x65\x73\x73\x61\x67\x65\xa");
        BIO_printf(bio_err, "\x2d\x64\x65\x63\x72\x79\x70\x74\x20\x20\x20\x20\x20\x20\x20\x64\x65\x63\x72\x79\x70\x74\x20\x65\x6e\x63\x72\x79\x70\x74\x65\x64\x20\x6d\x65\x73\x73\x61\x67\x65\xa");
        BIO_printf(bio_err, "\x2d\x73\x69\x67\x6e\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x73\x69\x67\x6e\x20\x6d\x65\x73\x73\x61\x67\x65\xa");
        BIO_printf(bio_err, "\x2d\x76\x65\x72\x69\x66\x79\x20\x20\x20\x20\x20\x20\x20\x20\x76\x65\x72\x69\x66\x79\x20\x73\x69\x67\x6e\x65\x64\x20\x6d\x65\x73\x73\x61\x67\x65\xa");
        BIO_printf(bio_err, "\x2d\x70\x6b\x37\x6f\x75\x74\x20\x20\x20\x20\x20\x20\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x50\x4b\x43\x53\x23\x37\x20\x73\x74\x72\x75\x63\x74\x75\x72\x65\xa");
#ifndef OPENSSL_NO_DES
        BIO_printf(bio_err, "\x2d\x64\x65\x73\x33\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x77\x69\x74\x68\x20\x74\x72\x69\x70\x6c\x65\x20\x44\x45\x53\xa");
        BIO_printf(bio_err, "\x2d\x64\x65\x73\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x77\x69\x74\x68\x20\x44\x45\x53\xa");
#endif
#ifndef OPENSSL_NO_SEED
        BIO_printf(bio_err, "\x2d\x73\x65\x65\x64\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x77\x69\x74\x68\x20\x53\x45\x45\x44\xa");
#endif
#ifndef OPENSSL_NO_RC2
        BIO_printf(bio_err, "\x2d\x72\x63\x32\x2d\x34\x30\x20\x20\x20\x20\x20\x20\x20\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x77\x69\x74\x68\x20\x52\x43\x32\x2d\x34\x30\x20\x28\x64\x65\x66\x61\x75\x6c\x74\x29\xa");
        BIO_printf(bio_err, "\x2d\x72\x63\x32\x2d\x36\x34\x20\x20\x20\x20\x20\x20\x20\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x77\x69\x74\x68\x20\x52\x43\x32\x2d\x36\x34\xa");
        BIO_printf(bio_err, "\x2d\x72\x63\x32\x2d\x31\x32\x38\x20\x20\x20\x20\x20\x20\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x77\x69\x74\x68\x20\x52\x43\x32\x2d\x31\x32\x38\xa");
#endif
#ifndef OPENSSL_NO_AES
        BIO_printf(bio_err, "\x2d\x61\x65\x73\x31\x32\x38\x2c\x20\x2d\x61\x65\x73\x31\x39\x32\x2c\x20\x2d\x61\x65\x73\x32\x35\x36\xa");
        BIO_printf(bio_err,
                   "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x50\x45\x4d\x20\x6f\x75\x74\x70\x75\x74\x20\x77\x69\x74\x68\x20\x63\x62\x63\x20\x61\x65\x73\xa");
#endif
#ifndef OPENSSL_NO_CAMELLIA
        BIO_printf(bio_err, "\x2d\x63\x61\x6d\x65\x6c\x6c\x69\x61\x31\x32\x38\x2c\x20\x2d\x63\x61\x6d\x65\x6c\x6c\x69\x61\x31\x39\x32\x2c\x20\x2d\x63\x61\x6d\x65\x6c\x6c\x69\x61\x32\x35\x36\xa");
        BIO_printf(bio_err,
                   "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x50\x45\x4d\x20\x6f\x75\x74\x70\x75\x74\x20\x77\x69\x74\x68\x20\x63\x62\x63\x20\x63\x61\x6d\x65\x6c\x6c\x69\x61\xa");
#endif
        BIO_printf(bio_err,
                   "\x2d\x6e\x6f\x69\x6e\x74\x65\x72\x6e\x20\x20\x20\x20\x20\x20\x64\x6f\x6e\x27\x74\x20\x73\x65\x61\x72\x63\x68\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73\x20\x69\x6e\x20\x6d\x65\x73\x73\x61\x67\x65\x20\x66\x6f\x72\x20\x73\x69\x67\x6e\x65\x72\xa");
        BIO_printf(bio_err,
                   "\x2d\x6e\x6f\x73\x69\x67\x73\x20\x20\x20\x20\x20\x20\x20\x20\x64\x6f\x6e\x27\x74\x20\x76\x65\x72\x69\x66\x79\x20\x6d\x65\x73\x73\x61\x67\x65\x20\x73\x69\x67\x6e\x61\x74\x75\x72\x65\xa");
        BIO_printf(bio_err,
                   "\x2d\x6e\x6f\x76\x65\x72\x69\x66\x79\x20\x20\x20\x20\x20\x20\x64\x6f\x6e\x27\x74\x20\x76\x65\x72\x69\x66\x79\x20\x73\x69\x67\x6e\x65\x72\x73\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\xa");
        BIO_printf(bio_err,
                   "\x2d\x6e\x6f\x63\x65\x72\x74\x73\x20\x20\x20\x20\x20\x20\x20\x64\x6f\x6e\x27\x74\x20\x69\x6e\x63\x6c\x75\x64\x65\x20\x73\x69\x67\x6e\x65\x72\x73\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x77\x68\x65\x6e\x20\x73\x69\x67\x6e\x69\x6e\x67\xa");
        BIO_printf(bio_err, "\x2d\x6e\x6f\x64\x65\x74\x61\x63\x68\x20\x20\x20\x20\x20\x20\x75\x73\x65\x20\x6f\x70\x61\x71\x75\x65\x20\x73\x69\x67\x6e\x69\x6e\x67\xa");
        BIO_printf(bio_err,
                   "\x2d\x6e\x6f\x61\x74\x74\x72\x20\x20\x20\x20\x20\x20\x20\x20\x64\x6f\x6e\x27\x74\x20\x69\x6e\x63\x6c\x75\x64\x65\x20\x61\x6e\x79\x20\x73\x69\x67\x6e\x65\x64\x20\x61\x74\x74\x72\x69\x62\x75\x74\x65\x73\xa");
        BIO_printf(bio_err,
                   "\x2d\x62\x69\x6e\x61\x72\x79\x20\x20\x20\x20\x20\x20\x20\x20\x64\x6f\x6e\x27\x74\x20\x74\x72\x61\x6e\x73\x6c\x61\x74\x65\x20\x6d\x65\x73\x73\x61\x67\x65\x20\x74\x6f\x20\x74\x65\x78\x74\xa");
        BIO_printf(bio_err, "\x2d\x63\x65\x72\x74\x66\x69\x6c\x65\x20\x66\x69\x6c\x65\x20\x6f\x74\x68\x65\x72\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73\x20\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err, "\x2d\x73\x69\x67\x6e\x65\x72\x20\x66\x69\x6c\x65\x20\x20\x20\x73\x69\x67\x6e\x65\x72\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err,
                   "\x2d\x72\x65\x63\x69\x70\x20\x20\x66\x69\x6c\x65\x20\x20\x20\x72\x65\x63\x69\x70\x69\x65\x6e\x74\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x66\x69\x6c\x65\x20\x66\x6f\x72\x20\x64\x65\x63\x72\x79\x70\x74\x69\x6f\x6e\xa");
        BIO_printf(bio_err, "\x2d\x69\x6e\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err,
                   "\x2d\x69\x6e\x66\x6f\x72\x6d\x20\x61\x72\x67\x20\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x53\x4d\x49\x4d\x45\x20\x28\x64\x65\x66\x61\x75\x6c\x74\x29\x2c\x20\x50\x45\x4d\x20\x6f\x72\x20\x44\x45\x52\xa");
        BIO_printf(bio_err,
                   "\x2d\x69\x6e\x6b\x65\x79\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\x20\x28\x69\x66\x20\x6e\x6f\x74\x20\x73\x69\x67\x6e\x65\x72\x20\x6f\x72\x20\x72\x65\x63\x69\x70\x69\x65\x6e\x74\x29\xa");
        BIO_printf(bio_err,
                   "\x2d\x6b\x65\x79\x66\x6f\x72\x6d\x20\x61\x72\x67\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\x20\x66\x6f\x72\x6d\x61\x74\x20\x28\x50\x45\x4d\x20\x6f\x72\x20\x45\x4e\x47\x49\x4e\x45\x29\xa");
        BIO_printf(bio_err, "\x2d\x6f\x75\x74\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err,
                   "\x2d\x6f\x75\x74\x66\x6f\x72\x6d\x20\x61\x72\x67\x20\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x53\x4d\x49\x4d\x45\x20\x28\x64\x65\x66\x61\x75\x6c\x74\x29\x2c\x20\x50\x45\x4d\x20\x6f\x72\x20\x44\x45\x52\xa");
        BIO_printf(bio_err,
                   "\x2d\x63\x6f\x6e\x74\x65\x6e\x74\x20\x66\x69\x6c\x65\x20\x20\x73\x75\x70\x70\x6c\x79\x20\x6f\x72\x20\x6f\x76\x65\x72\x72\x69\x64\x65\x20\x63\x6f\x6e\x74\x65\x6e\x74\x20\x66\x6f\x72\x20\x64\x65\x74\x61\x63\x68\x65\x64\x20\x73\x69\x67\x6e\x61\x74\x75\x72\x65\xa");
        BIO_printf(bio_err, "\x2d\x74\x6f\x20\x61\x64\x64\x72\x20\x20\x20\x20\x20\x20\x20\x74\x6f\x20\x61\x64\x64\x72\x65\x73\x73\xa");
        BIO_printf(bio_err, "\x2d\x66\x72\x6f\x6d\x20\x61\x64\x20\x20\x20\x20\x20\x20\x20\x66\x72\x6f\x6d\x20\x61\x64\x64\x72\x65\x73\x73\xa");
        BIO_printf(bio_err, "\x2d\x73\x75\x62\x6a\x65\x63\x74\x20\x73\x20\x20\x20\x20\x20\x73\x75\x62\x6a\x65\x63\x74\xa");
        BIO_printf(bio_err,
                   "\x2d\x74\x65\x78\x74\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x69\x6e\x63\x6c\x75\x64\x65\x20\x6f\x72\x20\x64\x65\x6c\x65\x74\x65\x20\x74\x65\x78\x74\x20\x4d\x49\x4d\x45\x20\x68\x65\x61\x64\x65\x72\x73\xa");
        BIO_printf(bio_err,
                   "\x2d\x43\x41\x70\x61\x74\x68\x20\x64\x69\x72\x20\x20\x20\x20\x74\x72\x75\x73\x74\x65\x64\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73\x20\x64\x69\x72\x65\x63\x74\x6f\x72\x79\xa");
        BIO_printf(bio_err, "\x2d\x43\x41\x66\x69\x6c\x65\x20\x66\x69\x6c\x65\x20\x20\x20\x74\x72\x75\x73\x74\x65\x64\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73\x20\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err,
                   "\x2d\x6e\x6f\x5f\x61\x6c\x74\x5f\x63\x68\x61\x69\x6e\x73\x20\x6f\x6e\x6c\x79\x20\x65\x76\x65\x72\x20\x75\x73\x65\x20\x74\x68\x65\x20\x66\x69\x72\x73\x74\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x63\x68\x61\x69\x6e\x20\x66\x6f\x75\x6e\x64\xa");
        BIO_printf(bio_err,
                   "\x2d\x63\x72\x6c\x5f\x63\x68\x65\x63\x6b\x20\x20\x20\x20\x20\x63\x68\x65\x63\x6b\x20\x72\x65\x76\x6f\x63\x61\x74\x69\x6f\x6e\x20\x73\x74\x61\x74\x75\x73\x20\x6f\x66\x20\x73\x69\x67\x6e\x65\x72\x27\x73\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x75\x73\x69\x6e\x67\x20\x43\x52\x4c\x73\xa");
        BIO_printf(bio_err,
                   "\x2d\x63\x72\x6c\x5f\x63\x68\x65\x63\x6b\x5f\x61\x6c\x6c\x20\x63\x68\x65\x63\x6b\x20\x72\x65\x76\x6f\x63\x61\x74\x69\x6f\x6e\x20\x73\x74\x61\x74\x75\x73\x20\x6f\x66\x20\x73\x69\x67\x6e\x65\x72\x27\x73\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x63\x68\x61\x69\x6e\x20\x75\x73\x69\x6e\x67\x20\x43\x52\x4c\x73\xa");
#ifndef OPENSSL_NO_ENGINE
        BIO_printf(bio_err,
                   "\x2d\x65\x6e\x67\x69\x6e\x65\x20\x65\x20\x20\x20\x20\x20\x20\x75\x73\x65\x20\x65\x6e\x67\x69\x6e\x65\x20\x65\x2c\x20\x70\x6f\x73\x73\x69\x62\x6c\x79\x20\x61\x20\x68\x61\x72\x64\x77\x61\x72\x65\x20\x64\x65\x76\x69\x63\x65\x2e\xa");
#endif
        BIO_printf(bio_err, "\x2d\x70\x61\x73\x73\x69\x6e\x20\x61\x72\x67\x20\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x66\x69\x6c\x65\x20\x70\x61\x73\x73\x20\x70\x68\x72\x61\x73\x65\x20\x73\x6f\x75\x72\x63\x65\xa");
        BIO_printf(bio_err, "\x2d\x72\x61\x6e\x64\x20\x66\x69\x6c\x65\x25\x63\x66\x69\x6c\x65\x25\x63\x2e\x2e\x2e\xa", LIST_SEPARATOR_CHAR,
                   LIST_SEPARATOR_CHAR);
        BIO_printf(bio_err,
                   "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x6c\x6f\x61\x64\x20\x74\x68\x65\x20\x66\x69\x6c\x65\x20\x28\x6f\x72\x20\x74\x68\x65\x20\x66\x69\x6c\x65\x73\x20\x69\x6e\x20\x74\x68\x65\x20\x64\x69\x72\x65\x63\x74\x6f\x72\x79\x29\x20\x69\x6e\x74\x6f\xa");
        BIO_printf(bio_err, "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x74\x68\x65\x20\x72\x61\x6e\x64\x6f\x6d\x20\x6e\x75\x6d\x62\x65\x72\x20\x67\x65\x6e\x65\x72\x61\x74\x6f\x72\xa");
        BIO_printf(bio_err,
                   "\x63\x65\x72\x74\x2e\x70\x65\x6d\x20\x20\x20\x20\x20\x20\x20\x72\x65\x63\x69\x70\x69\x65\x6e\x74\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x28\x73\x29\x20\x66\x6f\x72\x20\x65\x6e\x63\x72\x79\x70\x74\x69\x6f\x6e\xa");
        goto end;
    }
    e = setup_engine(bio_err, engine, 0);

    if (!app_passwd(bio_err, passargin, NULL, &passin, NULL)) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x67\x65\x74\x74\x69\x6e\x67\x20\x70\x61\x73\x73\x77\x6f\x72\x64\xa");
        goto end;
    }

    if (need_rand) {
        app_RAND_load_file(NULL, bio_err, (inrand != NULL));
        if (inrand != NULL)
            BIO_printf(bio_err, "\x25\x6c\x64\x20\x73\x65\x6d\x69\x2d\x72\x61\x6e\x64\x6f\x6d\x20\x62\x79\x74\x65\x73\x20\x6c\x6f\x61\x64\x65\x64\xa",
                       app_RAND_load_files(inrand));
    }

    ret = 2;

    if (!(operation & SMIME_SIGNERS))
        flags &= ~PKCS7_DETACHED;

    if (operation & SMIME_OP) {
        if (outformat == FORMAT_ASN1)
            outmode = "\x77\x62";
    } else {
        if (flags & PKCS7_BINARY)
            outmode = "\x77\x62";
    }

    if (operation & SMIME_IP) {
        if (informat == FORMAT_ASN1)
            inmode = "\x72\x62";
    } else {
        if (flags & PKCS7_BINARY)
            inmode = "\x72\x62";
    }

    if (operation == SMIME_ENCRYPT) {
        if (!cipher) {
#ifndef OPENSSL_NO_DES
            cipher = EVP_des_ede3_cbc();
#else
            BIO_printf(bio_err, "\x4e\x6f\x20\x63\x69\x70\x68\x65\x72\x20\x73\x65\x6c\x65\x63\x74\x65\x64\xa");
            goto end;
#endif
        }
        encerts = sk_X509_new_null();
        while (*args) {
            if (!(cert = load_cert(bio_err, *args, FORMAT_PEM,
                                   NULL, e, "\x72\x65\x63\x69\x70\x69\x65\x6e\x74\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x66\x69\x6c\x65"))) {
#if 0                           /* An appropriate message is already printed */
                BIO_printf(bio_err,
                           "\x43\x61\x6e\x27\x74\x20\x72\x65\x61\x64\x20\x72\x65\x63\x69\x70\x69\x65\x6e\x74\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x66\x69\x6c\x65\x20\x25\x73\xa",
                           *args);
#endif
                goto end;
            }
            sk_X509_push(encerts, cert);
            cert = NULL;
            args++;
        }
    }

    if (certfile) {
        if (!(other = load_certs(bio_err, certfile, FORMAT_PEM, NULL,
                                 e, "\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x66\x69\x6c\x65"))) {
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (recipfile && (operation == SMIME_DECRYPT)) {
        if (!(recip = load_cert(bio_err, recipfile, FORMAT_PEM, NULL,
                                e, "\x72\x65\x63\x69\x70\x69\x65\x6e\x74\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x66\x69\x6c\x65"))) {
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (operation == SMIME_DECRYPT) {
        if (!keyfile)
            keyfile = recipfile;
    } else if (operation == SMIME_SIGN) {
        if (!keyfile)
            keyfile = signerfile;
    } else
        keyfile = NULL;

    if (keyfile) {
        key = load_key(bio_err, keyfile, keyform, 0, passin, e,
                       "\x73\x69\x67\x6e\x69\x6e\x67\x20\x6b\x65\x79\x20\x66\x69\x6c\x65");
        if (!key)
            goto end;
    }

    if (infile) {
        if (!(in = BIO_new_file(infile, inmode))) {
            BIO_printf(bio_err, "\x43\x61\x6e\x27\x74\x20\x6f\x70\x65\x6e\x20\x69\x6e\x70\x75\x74\x20\x66\x69\x6c\x65\x20\x25\x73\xa", infile);
            goto end;
        }
    } else
        in = BIO_new_fp(stdin, BIO_NOCLOSE);

    if (operation & SMIME_IP) {
        if (informat == FORMAT_SMIME)
            p7 = SMIME_read_PKCS7(in, &indata);
        else if (informat == FORMAT_PEM)
            p7 = PEM_read_bio_PKCS7(in, NULL, NULL, NULL);
        else if (informat == FORMAT_ASN1)
            p7 = d2i_PKCS7_bio(in, NULL);
        else {
            BIO_printf(bio_err, "\x42\x61\x64\x20\x69\x6e\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x66\x6f\x72\x20\x50\x4b\x43\x53\x23\x37\x20\x66\x69\x6c\x65\xa");
            goto end;
        }

        if (!p7) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x72\x65\x61\x64\x69\x6e\x67\x20\x53\x2f\x4d\x49\x4d\x45\x20\x6d\x65\x73\x73\x61\x67\x65\xa");
            goto end;
        }
        if (contfile) {
            BIO_free(indata);
            if (!(indata = BIO_new_file(contfile, "\x72\x62"))) {
                BIO_printf(bio_err, "\x43\x61\x6e\x27\x74\x20\x72\x65\x61\x64\x20\x63\x6f\x6e\x74\x65\x6e\x74\x20\x66\x69\x6c\x65\x20\x25\x73\xa", contfile);
                goto end;
            }
        }
    }

    if (outfile) {
        if (!(out = BIO_new_file(outfile, outmode))) {
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

    if (operation == SMIME_VERIFY) {
        if (!(store = setup_verify(bio_err, CAfile, CApath)))
            goto end;
        X509_STORE_set_verify_cb(store, smime_cb);
        if (vpm)
            X509_STORE_set1_param(store, vpm);
    }

    ret = 3;

    if (operation == SMIME_ENCRYPT) {
        if (indef)
            flags |= PKCS7_STREAM;
        p7 = PKCS7_encrypt(encerts, in, cipher, flags);
    } else if (operation & SMIME_SIGNERS) {
        int i;
        /*
         * If detached data content we only enable streaming if S/MIME output
         * format.
         */
        if (operation == SMIME_SIGN) {
            if (flags & PKCS7_DETACHED) {
                if (outformat == FORMAT_SMIME)
                    flags |= PKCS7_STREAM;
            } else if (indef)
                flags |= PKCS7_STREAM;
            flags |= PKCS7_PARTIAL;
            p7 = PKCS7_sign(NULL, NULL, other, in, flags);
            if (!p7)
                goto end;
            if (flags & PKCS7_NOCERTS) {
                for (i = 0; i < sk_X509_num(other); i++) {
                    X509 *x = sk_X509_value(other, i);
                    PKCS7_add_certificate(p7, x);
                }
            }
        } else
            flags |= PKCS7_REUSE_DIGEST;
        for (i = 0; i < sk_OPENSSL_STRING_num(sksigners); i++) {
            signerfile = sk_OPENSSL_STRING_value(sksigners, i);
            keyfile = sk_OPENSSL_STRING_value(skkeys, i);
            signer = load_cert(bio_err, signerfile, FORMAT_PEM, NULL,
                               e, "\x73\x69\x67\x6e\x65\x72\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65");
            if (!signer)
                goto end;
            key = load_key(bio_err, keyfile, keyform, 0, passin, e,
                           "\x73\x69\x67\x6e\x69\x6e\x67\x20\x6b\x65\x79\x20\x66\x69\x6c\x65");
            if (!key)
                goto end;
            if (!PKCS7_sign_add_signer(p7, signer, key, sign_md, flags))
                goto end;
            X509_free(signer);
            signer = NULL;
            EVP_PKEY_free(key);
            key = NULL;
        }
        /* If not streaming or resigning finalize structure */
        if ((operation == SMIME_SIGN) && !(flags & PKCS7_STREAM)) {
            if (!PKCS7_final(p7, in, flags))
                goto end;
        }
    }

    if (!p7) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x63\x72\x65\x61\x74\x69\x6e\x67\x20\x50\x4b\x43\x53\x23\x37\x20\x73\x74\x72\x75\x63\x74\x75\x72\x65\xa");
        goto end;
    }

    ret = 4;
    if (operation == SMIME_DECRYPT) {
        if (!PKCS7_decrypt(p7, key, recip, out, flags)) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x64\x65\x63\x72\x79\x70\x74\x69\x6e\x67\x20\x50\x4b\x43\x53\x23\x37\x20\x73\x74\x72\x75\x63\x74\x75\x72\x65\xa");
            goto end;
        }
    } else if (operation == SMIME_VERIFY) {
        STACK_OF(X509) *signers;
        if (PKCS7_verify(p7, other, store, indata, out, flags))
            BIO_printf(bio_err, "\x56\x65\x72\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x20\x73\x75\x63\x63\x65\x73\x73\x66\x75\x6c\xa");
        else {
            BIO_printf(bio_err, "\x56\x65\x72\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x20\x66\x61\x69\x6c\x75\x72\x65\xa");
            goto end;
        }
        signers = PKCS7_get0_signers(p7, other, flags);
        if (!save_certs(signerfile, signers)) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x77\x72\x69\x74\x69\x6e\x67\x20\x73\x69\x67\x6e\x65\x72\x73\x20\x74\x6f\x20\x25\x73\xa", signerfile);
            ret = 5;
            goto end;
        }
        sk_X509_free(signers);
    } else if (operation == SMIME_PK7OUT)
        PEM_write_bio_PKCS7(out, p7);
    else {
        if (to)
            BIO_printf(out, "\x54\x6f\x3a\x20\x25\x73\xa", to);
        if (from)
            BIO_printf(out, "\x46\x72\x6f\x6d\x3a\x20\x25\x73\xa", from);
        if (subject)
            BIO_printf(out, "\x53\x75\x62\x6a\x65\x63\x74\x3a\x20\x25\x73\xa", subject);
        if (outformat == FORMAT_SMIME) {
            if (operation == SMIME_RESIGN)
                SMIME_write_PKCS7(out, p7, indata, flags);
            else
                SMIME_write_PKCS7(out, p7, in, flags);
        } else if (outformat == FORMAT_PEM)
            PEM_write_bio_PKCS7_stream(out, p7, in, flags);
        else if (outformat == FORMAT_ASN1)
            i2d_PKCS7_bio_stream(out, p7, in, flags);
        else {
            BIO_printf(bio_err, "\x42\x61\x64\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x66\x6f\x72\x20\x50\x4b\x43\x53\x23\x37\x20\x66\x69\x6c\x65\xa");
            goto end;
        }
    }
    ret = 0;
 end:
    if (need_rand)
        app_RAND_write_file(NULL, bio_err);
    if (ret)
        ERR_print_errors(bio_err);
    sk_X509_pop_free(encerts, X509_free);
    sk_X509_pop_free(other, X509_free);
    if (vpm)
        X509_VERIFY_PARAM_free(vpm);
    if (sksigners)
        sk_OPENSSL_STRING_free(sksigners);
    if (skkeys)
        sk_OPENSSL_STRING_free(skkeys);
    X509_STORE_free(store);
    X509_free(cert);
    X509_free(recip);
    X509_free(signer);
    EVP_PKEY_free(key);
    PKCS7_free(p7);
    release_engine(e);
    BIO_free(in);
    BIO_free(indata);
    BIO_free_all(out);
    if (passin)
        OPENSSL_free(passin);
    return (ret);
}

static int save_certs(char *signerfile, STACK_OF(X509) *signers)
{
    int i;
    BIO *tmp;
    if (!signerfile)
        return 1;
    tmp = BIO_new_file(signerfile, "\x77");
    if (!tmp)
        return 0;
    for (i = 0; i < sk_X509_num(signers); i++)
        PEM_write_bio_X509(tmp, sk_X509_value(signers, i));
    BIO_free(tmp);
    return 1;
}

/* Minimal callback just to output policy info (if any) */

static int smime_cb(int ok, X509_STORE_CTX *ctx)
{
    int error;

    error = X509_STORE_CTX_get_error(ctx);

    if ((error != X509_V_ERR_NO_EXPLICIT_POLICY)
        && ((error != X509_V_OK) || (ok != 2)))
        return ok;

    policies_print(NULL, ctx);

    return ok;

}
