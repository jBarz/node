/* apps/s_cb.c - callback functions used by s_client, s_server, and s_time */
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
 * Copyright (c) 1998-2006 The OpenSSL Project.  All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* for memcpy() and strcmp() */
#define USE_SOCKETS
#define NON_MAIN
#include "apps.h"
#undef NON_MAIN
#undef USE_SOCKETS
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include "s_apps.h"

#define COOKIE_SECRET_LENGTH    16

int verify_depth = 0;
int verify_quiet = 0;
int verify_error = X509_V_OK;
int verify_return_error = 0;
unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
int cookie_initialized = 0;

int MS_CALLBACK verify_callback(int ok, X509_STORE_CTX *ctx)
{
    X509 *err_cert;
    int err, depth;

    err_cert = X509_STORE_CTX_get_current_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);

    if (!verify_quiet || !ok) {
        BIO_printf(bio_err, "\x64\x65\x70\x74\x68\x3d\x25\x64\x20", depth);
        if (err_cert) {
            X509_NAME_print_ex(bio_err,
                               X509_get_subject_name(err_cert),
                               0, XN_FLAG_ONELINE);
            BIO_puts(bio_err, "\xa");
        } else
            BIO_puts(bio_err, "\x3c\x6e\x6f\x20\x63\x65\x72\x74\x3e\xa");
    }
    if (!ok) {
        BIO_printf(bio_err, "\x76\x65\x72\x69\x66\x79\x20\x65\x72\x72\x6f\x72\x3a\x6e\x75\x6d\x3d\x25\x64\x3a\x25\x73\xa", err,
                   X509_verify_cert_error_string(err));
        if (verify_depth >= depth) {
            if (!verify_return_error)
                ok = 1;
            verify_error = X509_V_OK;
        } else {
            ok = 0;
            verify_error = X509_V_ERR_CERT_CHAIN_TOO_LONG;
        }
    }
    switch (err) {
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
        BIO_puts(bio_err, "\x69\x73\x73\x75\x65\x72\x3d\x20");
        X509_NAME_print_ex(bio_err, X509_get_issuer_name(err_cert),
                           0, XN_FLAG_ONELINE);
        BIO_puts(bio_err, "\xa");
        break;
    case X509_V_ERR_CERT_NOT_YET_VALID:
    case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
        BIO_printf(bio_err, "\x6e\x6f\x74\x42\x65\x66\x6f\x72\x65\x3d");
        ASN1_TIME_print(bio_err, X509_get_notBefore(err_cert));
        BIO_printf(bio_err, "\xa");
        break;
    case X509_V_ERR_CERT_HAS_EXPIRED:
    case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
        BIO_printf(bio_err, "\x6e\x6f\x74\x41\x66\x74\x65\x72\x3d");
        ASN1_TIME_print(bio_err, X509_get_notAfter(err_cert));
        BIO_printf(bio_err, "\xa");
        break;
    case X509_V_ERR_NO_EXPLICIT_POLICY:
        if (!verify_quiet)
            policies_print(bio_err, ctx);
        break;
    }
    if (err == X509_V_OK && ok == 2 && !verify_quiet)
        policies_print(bio_err, ctx);
    if (ok && !verify_quiet)
        BIO_printf(bio_err, "\x76\x65\x72\x69\x66\x79\x20\x72\x65\x74\x75\x72\x6e\x3a\x25\x64\xa", ok);
    return (ok);
}

int set_cert_stuff(SSL_CTX *ctx, char *cert_file, char *key_file)
{
    if (cert_file != NULL) {
        /*-
        SSL *ssl;
        X509 *x509;
        */

        if (SSL_CTX_use_certificate_file(ctx, cert_file,
                                         SSL_FILETYPE_PEM) <= 0) {
            BIO_printf(bio_err, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x67\x65\x74\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x66\x72\x6f\x6d\x20\x27\x25\x73\x27\xa",
                       cert_file);
            ERR_print_errors(bio_err);
            return (0);
        }
        if (key_file == NULL)
            key_file = cert_file;
        if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
            BIO_printf(bio_err, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x67\x65\x74\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\x20\x66\x72\x6f\x6d\x20\x27\x25\x73\x27\xa",
                       key_file);
            ERR_print_errors(bio_err);
            return (0);
        }

        /*-
        In theory this is no longer needed
        ssl=SSL_new(ctx);
        x509=SSL_get_certificate(ssl);

        if (x509 != NULL) {
                EVP_PKEY *pktmp;
                pktmp = X509_get_pubkey(x509);
                EVP_PKEY_copy_parameters(pktmp,
                                        SSL_get_privatekey(ssl));
                EVP_PKEY_free(pktmp);
        }
        SSL_free(ssl);
        */

        /*
         * If we are using DSA, we can copy the parameters from the private
         * key
         */

        /*
         * Now we know that a key and cert have been set against the SSL
         * context
         */
        if (!SSL_CTX_check_private_key(ctx)) {
            BIO_printf(bio_err,
                       "\x50\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\x20\x64\x6f\x65\x73\x20\x6e\x6f\x74\x20\x6d\x61\x74\x63\x68\x20\x74\x68\x65\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x70\x75\x62\x6c\x69\x63\x20\x6b\x65\x79\xa");
            return (0);
        }
    }
    return (1);
}

int set_cert_key_stuff(SSL_CTX *ctx, X509 *cert, EVP_PKEY *key,
                       STACK_OF(X509) *chain, int build_chain)
{
    int chflags = chain ? SSL_BUILD_CHAIN_FLAG_CHECK : 0;
    if (cert == NULL)
        return 1;
    if (SSL_CTX_use_certificate(ctx, cert) <= 0) {
        BIO_printf(bio_err, "\x65\x72\x72\x6f\x72\x20\x73\x65\x74\x74\x69\x6e\x67\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\xa");
        ERR_print_errors(bio_err);
        return 0;
    }

    if (SSL_CTX_use_PrivateKey(ctx, key) <= 0) {
        BIO_printf(bio_err, "\x65\x72\x72\x6f\x72\x20\x73\x65\x74\x74\x69\x6e\x67\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\xa");
        ERR_print_errors(bio_err);
        return 0;
    }

    /*
     * Now we know that a key and cert have been set against the SSL context
     */
    if (!SSL_CTX_check_private_key(ctx)) {
        BIO_printf(bio_err,
                   "\x50\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\x20\x64\x6f\x65\x73\x20\x6e\x6f\x74\x20\x6d\x61\x74\x63\x68\x20\x74\x68\x65\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x70\x75\x62\x6c\x69\x63\x20\x6b\x65\x79\xa");
        return 0;
    }
    if (chain && !SSL_CTX_set1_chain(ctx, chain)) {
        BIO_printf(bio_err, "\x65\x72\x72\x6f\x72\x20\x73\x65\x74\x74\x69\x6e\x67\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x63\x68\x61\x69\x6e\xa");
        ERR_print_errors(bio_err);
        return 0;
    }
    if (build_chain && !SSL_CTX_build_cert_chain(ctx, chflags)) {
        BIO_printf(bio_err, "\x65\x72\x72\x6f\x72\x20\x62\x75\x69\x6c\x64\x69\x6e\x67\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x63\x68\x61\x69\x6e\xa");
        ERR_print_errors(bio_err);
        return 0;
    }
    return 1;
}

static void ssl_print_client_cert_types(BIO *bio, SSL *s)
{
    const unsigned char *p;
    int i;
    int cert_type_num = SSL_get0_certificate_types(s, &p);
    if (!cert_type_num)
        return;
    BIO_puts(bio, "\x43\x6c\x69\x65\x6e\x74\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x54\x79\x70\x65\x73\x3a\x20");
    for (i = 0; i < cert_type_num; i++) {
        unsigned char cert_type = p[i];
        char *cname;
        switch (cert_type) {
        case TLS_CT_RSA_SIGN:
            cname = "\x52\x53\x41\x20\x73\x69\x67\x6e";
            break;

        case TLS_CT_DSS_SIGN:
            cname = "\x44\x53\x41\x20\x73\x69\x67\x6e";
            break;

        case TLS_CT_RSA_FIXED_DH:
            cname = "\x52\x53\x41\x20\x66\x69\x78\x65\x64\x20\x44\x48";
            break;

        case TLS_CT_DSS_FIXED_DH:
            cname = "\x44\x53\x53\x20\x66\x69\x78\x65\x64\x20\x44\x48";
            break;

        case TLS_CT_ECDSA_SIGN:
            cname = "\x45\x43\x44\x53\x41\x20\x73\x69\x67\x6e";
            break;

        case TLS_CT_RSA_FIXED_ECDH:
            cname = "\x52\x53\x41\x20\x66\x69\x78\x65\x64\x20\x45\x43\x44\x48";
            break;

        case TLS_CT_ECDSA_FIXED_ECDH:
            cname = "\x45\x43\x44\x53\x41\x20\x66\x69\x78\x65\x64\x20\x45\x43\x44\x48";
            break;

        case TLS_CT_GOST94_SIGN:
            cname = "\x47\x4f\x53\x54\x39\x34\x20\x53\x69\x67\x6e";
            break;

        case TLS_CT_GOST01_SIGN:
            cname = "\x47\x4f\x53\x54\x30\x31\x20\x53\x69\x67\x6e";
            break;

        default:
            cname = NULL;
        }

        if (i)
            BIO_puts(bio, "\x2c\x20");

        if (cname)
            BIO_puts(bio, cname);
        else
            BIO_printf(bio, "\x55\x4e\x4b\x4e\x4f\x57\x4e\x20\x28\x25\x64\x29\x2c", cert_type);
    }
    BIO_puts(bio, "\xa");
}

static int do_print_sigalgs(BIO *out, SSL *s, int shared)
{
    int i, nsig, client;
    client = SSL_is_server(s) ? 0 : 1;
    if (shared)
        nsig = SSL_get_shared_sigalgs(s, -1, NULL, NULL, NULL, NULL, NULL);
    else
        nsig = SSL_get_sigalgs(s, -1, NULL, NULL, NULL, NULL, NULL);
    if (nsig == 0)
        return 1;

    if (shared)
        BIO_puts(out, "\x53\x68\x61\x72\x65\x64\x20");

    if (client)
        BIO_puts(out, "\x52\x65\x71\x75\x65\x73\x74\x65\x64\x20");
    BIO_puts(out, "\x53\x69\x67\x6e\x61\x74\x75\x72\x65\x20\x41\x6c\x67\x6f\x72\x69\x74\x68\x6d\x73\x3a\x20");
    for (i = 0; i < nsig; i++) {
        int hash_nid, sign_nid;
        unsigned char rhash, rsign;
        const char *sstr = NULL;
        if (shared)
            SSL_get_shared_sigalgs(s, i, &sign_nid, &hash_nid, NULL,
                                   &rsign, &rhash);
        else
            SSL_get_sigalgs(s, i, &sign_nid, &hash_nid, NULL, &rsign, &rhash);
        if (i)
            BIO_puts(out, "\x3a");
        if (sign_nid == EVP_PKEY_RSA)
            sstr = "\x52\x53\x41";
        else if (sign_nid == EVP_PKEY_DSA)
            sstr = "\x44\x53\x41";
        else if (sign_nid == EVP_PKEY_EC)
            sstr = "\x45\x43\x44\x53\x41";
        if (sstr)
            BIO_printf(out, "\x25\x73\x2b", sstr);
        else
            BIO_printf(out, "\x30\x78\x25\x30\x32\x58\x2b", (int)rsign);
        if (hash_nid != NID_undef)
            BIO_printf(out, "\x25\x73", OBJ_nid2sn(hash_nid));
        else
            BIO_printf(out, "\x30\x78\x25\x30\x32\x58", (int)rhash);
    }
    BIO_puts(out, "\xa");
    return 1;
}

int ssl_print_sigalgs(BIO *out, SSL *s)
{
    int mdnid;
    if (!SSL_is_server(s))
        ssl_print_client_cert_types(out, s);
    do_print_sigalgs(out, s, 0);
    do_print_sigalgs(out, s, 1);
    if (SSL_get_peer_signature_nid(s, &mdnid))
        BIO_printf(out, "\x50\x65\x65\x72\x20\x73\x69\x67\x6e\x69\x6e\x67\x20\x64\x69\x67\x65\x73\x74\x3a\x20\x25\x73\xa", OBJ_nid2sn(mdnid));
    return 1;
}

#ifndef OPENSSL_NO_EC
int ssl_print_point_formats(BIO *out, SSL *s)
{
    int i, nformats;
    const char *pformats;
    nformats = SSL_get0_ec_point_formats(s, &pformats);
    if (nformats <= 0)
        return 1;
    BIO_puts(out, "\x53\x75\x70\x70\x6f\x72\x74\x65\x64\x20\x45\x6c\x6c\x69\x70\x74\x69\x63\x20\x43\x75\x72\x76\x65\x20\x50\x6f\x69\x6e\x74\x20\x46\x6f\x72\x6d\x61\x74\x73\x3a\x20");
    for (i = 0; i < nformats; i++, pformats++) {
        if (i)
            BIO_puts(out, "\x3a");
        switch (*pformats) {
        case TLSEXT_ECPOINTFORMAT_uncompressed:
            BIO_puts(out, "\x75\x6e\x63\x6f\x6d\x70\x72\x65\x73\x73\x65\x64");
            break;

        case TLSEXT_ECPOINTFORMAT_ansiX962_compressed_prime:
            BIO_puts(out, "\x61\x6e\x73\x69\x58\x39\x36\x32\x5f\x63\x6f\x6d\x70\x72\x65\x73\x73\x65\x64\x5f\x70\x72\x69\x6d\x65");
            break;

        case TLSEXT_ECPOINTFORMAT_ansiX962_compressed_char2:
            BIO_puts(out, "\x61\x6e\x73\x69\x58\x39\x36\x32\x5f\x63\x6f\x6d\x70\x72\x65\x73\x73\x65\x64\x5f\x63\x68\x61\x72\x32");
            break;

        default:
            BIO_printf(out, "\x75\x6e\x6b\x6e\x6f\x77\x6e\x28\x25\x64\x29", (int)*pformats);
            break;

        }
    }
    if (nformats <= 0)
        BIO_puts(out, "\x4e\x4f\x4e\x45");
    BIO_puts(out, "\xa");
    return 1;
}

int ssl_print_curves(BIO *out, SSL *s, int noshared)
{
    int i, ncurves, *curves, nid;
    const char *cname;
    ncurves = SSL_get1_curves(s, NULL);
    if (ncurves <= 0)
        return 1;
    curves = OPENSSL_malloc(ncurves * sizeof(int));
    if (!curves) {
        BIO_puts(out, "\x4d\x61\x6c\x6c\x6f\x63\x20\x65\x72\x72\x6f\x72\x20\x67\x65\x74\x74\x69\x6e\x67\x20\x73\x75\x70\x70\x6f\x72\x74\x65\x64\x20\x63\x75\x72\x76\x65\x73\xa");
        return 0;
    }
    SSL_get1_curves(s, curves);


    BIO_puts(out, "\x53\x75\x70\x70\x6f\x72\x74\x65\x64\x20\x45\x6c\x6c\x69\x70\x74\x69\x63\x20\x43\x75\x72\x76\x65\x73\x3a\x20");
    for (i = 0; i < ncurves; i++) {
        if (i)
            BIO_puts(out, "\x3a");
        nid = curves[i];
        /* If unrecognised print out hex version */
        if (nid & TLSEXT_nid_unknown)
            BIO_printf(out, "\x30\x78\x25\x30\x34\x58", nid & 0xFFFF);
        else {
            /* Use NIST name for curve if it exists */
            cname = EC_curve_nid2nist(nid);
            if (!cname)
                cname = OBJ_nid2sn(nid);
            BIO_printf(out, "\x25\x73", cname);
        }
    }
    if (ncurves == 0)
        BIO_puts(out, "\x4e\x4f\x4e\x45");
    OPENSSL_free(curves);
    if (noshared) {
        BIO_puts(out, "\xa");
        return 1;
    }
    BIO_puts(out, "\xa\x53\x68\x61\x72\x65\x64\x20\x45\x6c\x6c\x69\x70\x74\x69\x63\x20\x63\x75\x72\x76\x65\x73\x3a\x20");
    ncurves = SSL_get_shared_curve(s, -1);
    for (i = 0; i < ncurves; i++) {
        if (i)
            BIO_puts(out, "\x3a");
        nid = SSL_get_shared_curve(s, i);
        cname = EC_curve_nid2nist(nid);
        if (!cname)
            cname = OBJ_nid2sn(nid);
        BIO_printf(out, "\x25\x73", cname);
    }
    if (ncurves == 0)
        BIO_puts(out, "\x4e\x4f\x4e\x45");
    BIO_puts(out, "\xa");
    return 1;
}
#endif
int ssl_print_tmp_key(BIO *out, SSL *s)
{
    EVP_PKEY *key;
    if (!SSL_get_server_tmp_key(s, &key))
        return 1;
    BIO_puts(out, "\x53\x65\x72\x76\x65\x72\x20\x54\x65\x6d\x70\x20\x4b\x65\x79\x3a\x20");
    switch (EVP_PKEY_id(key)) {
    case EVP_PKEY_RSA:
        BIO_printf(out, "\x52\x53\x41\x2c\x20\x25\x64\x20\x62\x69\x74\x73\xa", EVP_PKEY_bits(key));
        break;

    case EVP_PKEY_DH:
        BIO_printf(out, "\x44\x48\x2c\x20\x25\x64\x20\x62\x69\x74\x73\xa", EVP_PKEY_bits(key));
        break;
#ifndef OPENSSL_NO_ECDH
    case EVP_PKEY_EC:
        {
            EC_KEY *ec = EVP_PKEY_get1_EC_KEY(key);
            int nid;
            const char *cname;
            nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec));
            EC_KEY_free(ec);
            cname = EC_curve_nid2nist(nid);
            if (!cname)
                cname = OBJ_nid2sn(nid);
            BIO_printf(out, "\x45\x43\x44\x48\x2c\x20\x25\x73\x2c\x20\x25\x64\x20\x62\x69\x74\x73\xa", cname, EVP_PKEY_bits(key));
        }
#endif
    }
    EVP_PKEY_free(key);
    return 1;
}

long MS_CALLBACK bio_dump_callback(BIO *bio, int cmd, const char *argp,
                                   int argi, long argl, long ret)
{
    BIO *out;

    out = (BIO *)BIO_get_callback_arg(bio);
    if (out == NULL)
        return (ret);

    if (cmd == (BIO_CB_READ | BIO_CB_RETURN)) {
        BIO_printf(out, "\x72\x65\x61\x64\x20\x66\x72\x6f\x6d\x20\x25\x70\x20\x5b\x25\x70\x5d\x20\x28\x25\x6c\x75\x20\x62\x79\x74\x65\x73\x20\x3d\x3e\x20\x25\x6c\x64\x20\x28\x30\x78\x25\x6c\x58\x29\x29\xa",
                   (void *)bio, (void *)argp, (unsigned long)argi, ret, ret);
        BIO_dump(out, argp, (int)ret);
        return (ret);
    } else if (cmd == (BIO_CB_WRITE | BIO_CB_RETURN)) {
        BIO_printf(out, "\x77\x72\x69\x74\x65\x20\x74\x6f\x20\x25\x70\x20\x5b\x25\x70\x5d\x20\x28\x25\x6c\x75\x20\x62\x79\x74\x65\x73\x20\x3d\x3e\x20\x25\x6c\x64\x20\x28\x30\x78\x25\x6c\x58\x29\x29\xa",
                   (void *)bio, (void *)argp, (unsigned long)argi, ret, ret);
        BIO_dump(out, argp, (int)ret);
    }
    return (ret);
}

void MS_CALLBACK apps_ssl_info_callback(const SSL *s, int where, int ret)
{
    const char *str;
    int w;

    w = where & ~SSL_ST_MASK;

    if (w & SSL_ST_CONNECT)
        str = "\x53\x53\x4c\x5f\x63\x6f\x6e\x6e\x65\x63\x74";
    else if (w & SSL_ST_ACCEPT)
        str = "\x53\x53\x4c\x5f\x61\x63\x63\x65\x70\x74";
    else
        str = "\x75\x6e\x64\x65\x66\x69\x6e\x65\x64";

    if (where & SSL_CB_LOOP) {
        BIO_printf(bio_err, "\x25\x73\x3a\x25\x73\xa", str, SSL_state_string_long(s));
    } else if (where & SSL_CB_ALERT) {
        str = (where & SSL_CB_READ) ? "\x72\x65\x61\x64" : "\x77\x72\x69\x74\x65";
        BIO_printf(bio_err, "\x53\x53\x4c\x33\x20\x61\x6c\x65\x72\x74\x20\x25\x73\x3a\x25\x73\x3a\x25\x73\xa",
                   str,
                   SSL_alert_type_string_long(ret),
                   SSL_alert_desc_string_long(ret));
    } else if (where & SSL_CB_EXIT) {
        if (ret == 0)
            BIO_printf(bio_err, "\x25\x73\x3a\x66\x61\x69\x6c\x65\x64\x20\x69\x6e\x20\x25\x73\xa",
                       str, SSL_state_string_long(s));
        else if (ret < 0) {
            BIO_printf(bio_err, "\x25\x73\x3a\x65\x72\x72\x6f\x72\x20\x69\x6e\x20\x25\x73\xa",
                       str, SSL_state_string_long(s));
        }
    }
}

void MS_CALLBACK msg_cb(int write_p, int version, int content_type,
                        const void *buf, size_t len, SSL *ssl, void *arg)
{
    BIO *bio = arg;
    const char *str_write_p, *str_version, *str_content_type =
        "", *str_details1 = "", *str_details2 = "";

    str_write_p = write_p ? "\x3e\x3e\x3e" : "\x3c\x3c\x3c";

    switch (version) {
    case SSL2_VERSION:
        str_version = "\x53\x53\x4c\x20\x32\x2e\x30";
        break;
    case SSL3_VERSION:
        str_version = "\x53\x53\x4c\x20\x33\x2e\x30\x20";
        break;
    case TLS1_VERSION:
        str_version = "\x54\x4c\x53\x20\x31\x2e\x30\x20";
        break;
    case TLS1_1_VERSION:
        str_version = "\x54\x4c\x53\x20\x31\x2e\x31\x20";
        break;
    case TLS1_2_VERSION:
        str_version = "\x54\x4c\x53\x20\x31\x2e\x32\x20";
        break;
    case DTLS1_VERSION:
        str_version = "\x44\x54\x4c\x53\x20\x31\x2e\x30\x20";
        break;
    case DTLS1_BAD_VER:
        str_version = "\x44\x54\x4c\x53\x20\x31\x2e\x30\x20\x28\x62\x61\x64\x29\x20";
        break;
    default:
        str_version = "\x3f\x3f\x3f";
    }

    if (version == SSL2_VERSION) {
        str_details1 = "\x3f\x3f\x3f";

        if (len > 0) {
            switch (((const unsigned char *)buf)[0]) {
            case 0:
                str_details1 = "\x2c\x20\x45\x52\x52\x4f\x52\x3a";
                str_details2 = "\x20\x3f\x3f\x3f";
                if (len >= 3) {
                    unsigned err =
                        (((const unsigned char *)buf)[1] << 8) +
                        ((const unsigned char *)buf)[2];

                    switch (err) {
                    case 0x0001:
                        str_details2 = "\x20\x4e\x4f\x2d\x43\x49\x50\x48\x45\x52\x2d\x45\x52\x52\x4f\x52";
                        break;
                    case 0x0002:
                        str_details2 = "\x20\x4e\x4f\x2d\x43\x45\x52\x54\x49\x46\x49\x43\x41\x54\x45\x2d\x45\x52\x52\x4f\x52";
                        break;
                    case 0x0004:
                        str_details2 = "\x20\x42\x41\x44\x2d\x43\x45\x52\x54\x49\x46\x49\x43\x41\x54\x45\x2d\x45\x52\x52\x4f\x52";
                        break;
                    case 0x0006:
                        str_details2 = "\x20\x55\x4e\x53\x55\x50\x50\x4f\x52\x54\x45\x44\x2d\x43\x45\x52\x54\x49\x46\x49\x43\x41\x54\x45\x2d\x54\x59\x50\x45\x2d\x45\x52\x52\x4f\x52";
                        break;
                    }
                }

                break;
            case 1:
                str_details1 = "\x2c\x20\x43\x4c\x49\x45\x4e\x54\x2d\x48\x45\x4c\x4c\x4f";
                break;
            case 2:
                str_details1 = "\x2c\x20\x43\x4c\x49\x45\x4e\x54\x2d\x4d\x41\x53\x54\x45\x52\x2d\x4b\x45\x59";
                break;
            case 3:
                str_details1 = "\x2c\x20\x43\x4c\x49\x45\x4e\x54\x2d\x46\x49\x4e\x49\x53\x48\x45\x44";
                break;
            case 4:
                str_details1 = "\x2c\x20\x53\x45\x52\x56\x45\x52\x2d\x48\x45\x4c\x4c\x4f";
                break;
            case 5:
                str_details1 = "\x2c\x20\x53\x45\x52\x56\x45\x52\x2d\x56\x45\x52\x49\x46\x59";
                break;
            case 6:
                str_details1 = "\x2c\x20\x53\x45\x52\x56\x45\x52\x2d\x46\x49\x4e\x49\x53\x48\x45\x44";
                break;
            case 7:
                str_details1 = "\x2c\x20\x52\x45\x51\x55\x45\x53\x54\x2d\x43\x45\x52\x54\x49\x46\x49\x43\x41\x54\x45";
                break;
            case 8:
                str_details1 = "\x2c\x20\x43\x4c\x49\x45\x4e\x54\x2d\x43\x45\x52\x54\x49\x46\x49\x43\x41\x54\x45";
                break;
            }
        }
    }

    if (version == SSL3_VERSION ||
        version == TLS1_VERSION ||
        version == TLS1_1_VERSION ||
        version == TLS1_2_VERSION ||
        version == DTLS1_VERSION || version == DTLS1_BAD_VER) {
        switch (content_type) {
        case 20:
            str_content_type = "\x43\x68\x61\x6e\x67\x65\x43\x69\x70\x68\x65\x72\x53\x70\x65\x63";
            break;
        case 21:
            str_content_type = "\x41\x6c\x65\x72\x74";
            break;
        case 22:
            str_content_type = "\x48\x61\x6e\x64\x73\x68\x61\x6b\x65";
            break;
        }

        if (content_type == 21) { /* Alert */
            str_details1 = "\x2c\x20\x3f\x3f\x3f";

            if (len == 2) {
                switch (((const unsigned char *)buf)[0]) {
                case 1:
                    str_details1 = "\x2c\x20\x77\x61\x72\x6e\x69\x6e\x67";
                    break;
                case 2:
                    str_details1 = "\x2c\x20\x66\x61\x74\x61\x6c";
                    break;
                }

                str_details2 = "\x20\x3f\x3f\x3f";
                switch (((const unsigned char *)buf)[1]) {
                case 0:
                    str_details2 = "\x20\x63\x6c\x6f\x73\x65\x5f\x6e\x6f\x74\x69\x66\x79";
                    break;
                case 10:
                    str_details2 = "\x20\x75\x6e\x65\x78\x70\x65\x63\x74\x65\x64\x5f\x6d\x65\x73\x73\x61\x67\x65";
                    break;
                case 20:
                    str_details2 = "\x20\x62\x61\x64\x5f\x72\x65\x63\x6f\x72\x64\x5f\x6d\x61\x63";
                    break;
                case 21:
                    str_details2 = "\x20\x64\x65\x63\x72\x79\x70\x74\x69\x6f\x6e\x5f\x66\x61\x69\x6c\x65\x64";
                    break;
                case 22:
                    str_details2 = "\x20\x72\x65\x63\x6f\x72\x64\x5f\x6f\x76\x65\x72\x66\x6c\x6f\x77";
                    break;
                case 30:
                    str_details2 = "\x20\x64\x65\x63\x6f\x6d\x70\x72\x65\x73\x73\x69\x6f\x6e\x5f\x66\x61\x69\x6c\x75\x72\x65";
                    break;
                case 40:
                    str_details2 = "\x20\x68\x61\x6e\x64\x73\x68\x61\x6b\x65\x5f\x66\x61\x69\x6c\x75\x72\x65";
                    break;
                case 42:
                    str_details2 = "\x20\x62\x61\x64\x5f\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65";
                    break;
                case 43:
                    str_details2 = "\x20\x75\x6e\x73\x75\x70\x70\x6f\x72\x74\x65\x64\x5f\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65";
                    break;
                case 44:
                    str_details2 = "\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x5f\x72\x65\x76\x6f\x6b\x65\x64";
                    break;
                case 45:
                    str_details2 = "\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x5f\x65\x78\x70\x69\x72\x65\x64";
                    break;
                case 46:
                    str_details2 = "\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x5f\x75\x6e\x6b\x6e\x6f\x77\x6e";
                    break;
                case 47:
                    str_details2 = "\x20\x69\x6c\x6c\x65\x67\x61\x6c\x5f\x70\x61\x72\x61\x6d\x65\x74\x65\x72";
                    break;
                case 48:
                    str_details2 = "\x20\x75\x6e\x6b\x6e\x6f\x77\x6e\x5f\x63\x61";
                    break;
                case 49:
                    str_details2 = "\x20\x61\x63\x63\x65\x73\x73\x5f\x64\x65\x6e\x69\x65\x64";
                    break;
                case 50:
                    str_details2 = "\x20\x64\x65\x63\x6f\x64\x65\x5f\x65\x72\x72\x6f\x72";
                    break;
                case 51:
                    str_details2 = "\x20\x64\x65\x63\x72\x79\x70\x74\x5f\x65\x72\x72\x6f\x72";
                    break;
                case 60:
                    str_details2 = "\x20\x65\x78\x70\x6f\x72\x74\x5f\x72\x65\x73\x74\x72\x69\x63\x74\x69\x6f\x6e";
                    break;
                case 70:
                    str_details2 = "\x20\x70\x72\x6f\x74\x6f\x63\x6f\x6c\x5f\x76\x65\x72\x73\x69\x6f\x6e";
                    break;
                case 71:
                    str_details2 = "\x20\x69\x6e\x73\x75\x66\x66\x69\x63\x69\x65\x6e\x74\x5f\x73\x65\x63\x75\x72\x69\x74\x79";
                    break;
                case 80:
                    str_details2 = "\x20\x69\x6e\x74\x65\x72\x6e\x61\x6c\x5f\x65\x72\x72\x6f\x72";
                    break;
                case 90:
                    str_details2 = "\x20\x75\x73\x65\x72\x5f\x63\x61\x6e\x63\x65\x6c\x65\x64";
                    break;
                case 100:
                    str_details2 = "\x20\x6e\x6f\x5f\x72\x65\x6e\x65\x67\x6f\x74\x69\x61\x74\x69\x6f\x6e";
                    break;
                case 110:
                    str_details2 = "\x20\x75\x6e\x73\x75\x70\x70\x6f\x72\x74\x65\x64\x5f\x65\x78\x74\x65\x6e\x73\x69\x6f\x6e";
                    break;
                case 111:
                    str_details2 = "\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x5f\x75\x6e\x6f\x62\x74\x61\x69\x6e\x61\x62\x6c\x65";
                    break;
                case 112:
                    str_details2 = "\x20\x75\x6e\x72\x65\x63\x6f\x67\x6e\x69\x7a\x65\x64\x5f\x6e\x61\x6d\x65";
                    break;
                case 113:
                    str_details2 = "\x20\x62\x61\x64\x5f\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x5f\x73\x74\x61\x74\x75\x73\x5f\x72\x65\x73\x70\x6f\x6e\x73\x65";
                    break;
                case 114:
                    str_details2 = "\x20\x62\x61\x64\x5f\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x5f\x68\x61\x73\x68\x5f\x76\x61\x6c\x75\x65";
                    break;
                case 115:
                    str_details2 = "\x20\x75\x6e\x6b\x6e\x6f\x77\x6e\x5f\x70\x73\x6b\x5f\x69\x64\x65\x6e\x74\x69\x74\x79";
                    break;
                }
            }
        }

        if (content_type == 22) { /* Handshake */
            str_details1 = "\x3f\x3f\x3f";

            if (len > 0) {
                switch (((const unsigned char *)buf)[0]) {
                case 0:
                    str_details1 = "\x2c\x20\x48\x65\x6c\x6c\x6f\x52\x65\x71\x75\x65\x73\x74";
                    break;
                case 1:
                    str_details1 = "\x2c\x20\x43\x6c\x69\x65\x6e\x74\x48\x65\x6c\x6c\x6f";
                    break;
                case 2:
                    str_details1 = "\x2c\x20\x53\x65\x72\x76\x65\x72\x48\x65\x6c\x6c\x6f";
                    break;
                case 3:
                    str_details1 = "\x2c\x20\x48\x65\x6c\x6c\x6f\x56\x65\x72\x69\x66\x79\x52\x65\x71\x75\x65\x73\x74";
                    break;
                case 11:
                    str_details1 = "\x2c\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65";
                    break;
                case 12:
                    str_details1 = "\x2c\x20\x53\x65\x72\x76\x65\x72\x4b\x65\x79\x45\x78\x63\x68\x61\x6e\x67\x65";
                    break;
                case 13:
                    str_details1 = "\x2c\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x52\x65\x71\x75\x65\x73\x74";
                    break;
                case 14:
                    str_details1 = "\x2c\x20\x53\x65\x72\x76\x65\x72\x48\x65\x6c\x6c\x6f\x44\x6f\x6e\x65";
                    break;
                case 15:
                    str_details1 = "\x2c\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x56\x65\x72\x69\x66\x79";
                    break;
                case 16:
                    str_details1 = "\x2c\x20\x43\x6c\x69\x65\x6e\x74\x4b\x65\x79\x45\x78\x63\x68\x61\x6e\x67\x65";
                    break;
                case 20:
                    str_details1 = "\x2c\x20\x46\x69\x6e\x69\x73\x68\x65\x64";
                    break;
                }
            }
        }
#ifndef OPENSSL_NO_HEARTBEATS
        if (content_type == 24) { /* Heartbeat */
            str_details1 = "\x2c\x20\x48\x65\x61\x72\x74\x62\x65\x61\x74";

            if (len > 0) {
                switch (((const unsigned char *)buf)[0]) {
                case 1:
                    str_details1 = "\x2c\x20\x48\x65\x61\x72\x74\x62\x65\x61\x74\x52\x65\x71\x75\x65\x73\x74";
                    break;
                case 2:
                    str_details1 = "\x2c\x20\x48\x65\x61\x72\x74\x62\x65\x61\x74\x52\x65\x73\x70\x6f\x6e\x73\x65";
                    break;
                }
            }
        }
#endif
    }

    BIO_printf(bio, "\x25\x73\x20\x25\x73\x25\x73\x20\x5b\x6c\x65\x6e\x67\x74\x68\x20\x25\x30\x34\x6c\x78\x5d\x25\x73\x25\x73\xa", str_write_p, str_version,
               str_content_type, (unsigned long)len, str_details1,
               str_details2);

    if (len > 0) {
        size_t num, i;

        BIO_printf(bio, "\x20\x20\x20");
        num = len;
#if 0
        if (num > 16)
            num = 16;
#endif
        for (i = 0; i < num; i++) {
            if (i % 16 == 0 && i > 0)
                BIO_printf(bio, "\xa\x20\x20\x20");
            BIO_printf(bio, "\x20\x25\x30\x32\x78", ((const unsigned char *)buf)[i]);
        }
        if (i < len)
            BIO_printf(bio, "\x20\x2e\x2e\x2e");
        BIO_printf(bio, "\xa");
    }
    (void)BIO_flush(bio);
}

void MS_CALLBACK tlsext_cb(SSL *s, int client_server, int type,
                           unsigned char *data, int len, void *arg)
{
    BIO *bio = arg;
    char *extname;

    switch (type) {
    case TLSEXT_TYPE_server_name:
        extname = "\x73\x65\x72\x76\x65\x72\x20\x6e\x61\x6d\x65";
        break;

    case TLSEXT_TYPE_max_fragment_length:
        extname = "\x6d\x61\x78\x20\x66\x72\x61\x67\x6d\x65\x6e\x74\x20\x6c\x65\x6e\x67\x74\x68";
        break;

    case TLSEXT_TYPE_client_certificate_url:
        extname = "\x63\x6c\x69\x65\x6e\x74\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x55\x52\x4c";
        break;

    case TLSEXT_TYPE_trusted_ca_keys:
        extname = "\x74\x72\x75\x73\x74\x65\x64\x20\x43\x41\x20\x6b\x65\x79\x73";
        break;

    case TLSEXT_TYPE_truncated_hmac:
        extname = "\x74\x72\x75\x6e\x63\x61\x74\x65\x64\x20\x48\x4d\x41\x43";
        break;

    case TLSEXT_TYPE_status_request:
        extname = "\x73\x74\x61\x74\x75\x73\x20\x72\x65\x71\x75\x65\x73\x74";
        break;

    case TLSEXT_TYPE_user_mapping:
        extname = "\x75\x73\x65\x72\x20\x6d\x61\x70\x70\x69\x6e\x67";
        break;

    case TLSEXT_TYPE_client_authz:
        extname = "\x63\x6c\x69\x65\x6e\x74\x20\x61\x75\x74\x68\x7a";
        break;

    case TLSEXT_TYPE_server_authz:
        extname = "\x73\x65\x72\x76\x65\x72\x20\x61\x75\x74\x68\x7a";
        break;

    case TLSEXT_TYPE_cert_type:
        extname = "\x63\x65\x72\x74\x20\x74\x79\x70\x65";
        break;

    case TLSEXT_TYPE_elliptic_curves:
        extname = "\x65\x6c\x6c\x69\x70\x74\x69\x63\x20\x63\x75\x72\x76\x65\x73";
        break;

    case TLSEXT_TYPE_ec_point_formats:
        extname = "\x45\x43\x20\x70\x6f\x69\x6e\x74\x20\x66\x6f\x72\x6d\x61\x74\x73";
        break;

    case TLSEXT_TYPE_srp:
        extname = "\x53\x52\x50";
        break;

    case TLSEXT_TYPE_signature_algorithms:
        extname = "\x73\x69\x67\x6e\x61\x74\x75\x72\x65\x20\x61\x6c\x67\x6f\x72\x69\x74\x68\x6d\x73";
        break;

    case TLSEXT_TYPE_use_srtp:
        extname = "\x75\x73\x65\x20\x53\x52\x54\x50";
        break;

    case TLSEXT_TYPE_heartbeat:
        extname = "\x68\x65\x61\x72\x74\x62\x65\x61\x74";
        break;

    case TLSEXT_TYPE_session_ticket:
        extname = "\x73\x65\x73\x73\x69\x6f\x6e\x20\x74\x69\x63\x6b\x65\x74";
        break;

    case TLSEXT_TYPE_renegotiate:
        extname = "\x72\x65\x6e\x65\x67\x6f\x74\x69\x61\x74\x69\x6f\x6e\x20\x69\x6e\x66\x6f";
        break;

#ifdef TLSEXT_TYPE_opaque_prf_input
    case TLSEXT_TYPE_opaque_prf_input:
        extname = "\x6f\x70\x61\x71\x75\x65\x20\x50\x52\x46\x20\x69\x6e\x70\x75\x74";
        break;
#endif
#ifdef TLSEXT_TYPE_next_proto_neg
    case TLSEXT_TYPE_next_proto_neg:
        extname = "\x6e\x65\x78\x74\x20\x70\x72\x6f\x74\x6f\x63\x6f\x6c";
        break;
#endif
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
    case TLSEXT_TYPE_application_layer_protocol_negotiation:
        extname = "\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x20\x6c\x61\x79\x65\x72\x20\x70\x72\x6f\x74\x6f\x63\x6f\x6c\x20\x6e\x65\x67\x6f\x74\x69\x61\x74\x69\x6f\x6e";
        break;
#endif

    case TLSEXT_TYPE_padding:
        extname = "\x54\x4c\x53\x20\x70\x61\x64\x64\x69\x6e\x67";
        break;

    default:
        extname = "\x75\x6e\x6b\x6e\x6f\x77\x6e";
        break;

    }

    BIO_printf(bio, "\x54\x4c\x53\x20\x25\x73\x20\x65\x78\x74\x65\x6e\x73\x69\x6f\x6e\x20\x22\x25\x73\x22\x20\x28\x69\x64\x3d\x25\x64\x29\x2c\x20\x6c\x65\x6e\x3d\x25\x64\xa",
               client_server ? "\x73\x65\x72\x76\x65\x72" : "\x63\x6c\x69\x65\x6e\x74", extname, type, len);
    BIO_dump(bio, (char *)data, len);
    (void)BIO_flush(bio);
}

int MS_CALLBACK generate_cookie_callback(SSL *ssl, unsigned char *cookie,
                                         unsigned int *cookie_len)
{
    unsigned char *buffer, result[EVP_MAX_MD_SIZE];
    unsigned int length, resultlength;
    union {
        struct sockaddr sa;
        struct sockaddr_in s4;
#if OPENSSL_USE_IPV6
        struct sockaddr_in6 s6;
#endif
    } peer;

    /* Initialize a random secret */
    if (!cookie_initialized) {
        if (RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH) <= 0) {
            BIO_printf(bio_err, "\x65\x72\x72\x6f\x72\x20\x73\x65\x74\x74\x69\x6e\x67\x20\x72\x61\x6e\x64\x6f\x6d\x20\x63\x6f\x6f\x6b\x69\x65\x20\x73\x65\x63\x72\x65\x74\xa");
            return 0;
        }
        cookie_initialized = 1;
    }

    /* Read peer information */
    (void)BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

    /* Create buffer with peer's address and port */
    length = 0;
    switch (peer.sa.sa_family) {
    case AF_INET:
        length += sizeof(struct in_addr);
        length += sizeof(peer.s4.sin_port);
        break;
#if OPENSSL_USE_IPV6
    case AF_INET6:
        length += sizeof(struct in6_addr);
        length += sizeof(peer.s6.sin6_port);
        break;
#endif
    default:
        OPENSSL_assert(0);
        break;
    }
    buffer = OPENSSL_malloc(length);

    if (buffer == NULL) {
        BIO_printf(bio_err, "\x6f\x75\x74\x20\x6f\x66\x20\x6d\x65\x6d\x6f\x72\x79\xa");
        return 0;
    }

    switch (peer.sa.sa_family) {
    case AF_INET:
        memcpy(buffer, &peer.s4.sin_port, sizeof(peer.s4.sin_port));
        memcpy(buffer + sizeof(peer.s4.sin_port),
               &peer.s4.sin_addr, sizeof(struct in_addr));
        break;
#if OPENSSL_USE_IPV6
    case AF_INET6:
        memcpy(buffer, &peer.s6.sin6_port, sizeof(peer.s6.sin6_port));
        memcpy(buffer + sizeof(peer.s6.sin6_port),
               &peer.s6.sin6_addr, sizeof(struct in6_addr));
        break;
#endif
    default:
        OPENSSL_assert(0);
        break;
    }

    /* Calculate HMAC of buffer using the secret */
    HMAC(EVP_sha1(), cookie_secret, COOKIE_SECRET_LENGTH,
         buffer, length, result, &resultlength);
    OPENSSL_free(buffer);

    memcpy(cookie, result, resultlength);
    *cookie_len = resultlength;

    return 1;
}

int MS_CALLBACK verify_cookie_callback(SSL *ssl, unsigned char *cookie,
                                       unsigned int cookie_len)
{
    unsigned char *buffer, result[EVP_MAX_MD_SIZE];
    unsigned int length, resultlength;
    union {
        struct sockaddr sa;
        struct sockaddr_in s4;
#if OPENSSL_USE_IPV6
        struct sockaddr_in6 s6;
#endif
    } peer;

    /* If secret isn't initialized yet, the cookie can't be valid */
    if (!cookie_initialized)
        return 0;

    /* Read peer information */
    (void)BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

    /* Create buffer with peer's address and port */
    length = 0;
    switch (peer.sa.sa_family) {
    case AF_INET:
        length += sizeof(struct in_addr);
        length += sizeof(peer.s4.sin_port);
        break;
#if OPENSSL_USE_IPV6
    case AF_INET6:
        length += sizeof(struct in6_addr);
        length += sizeof(peer.s6.sin6_port);
        break;
#endif
    default:
        OPENSSL_assert(0);
        break;
    }
    buffer = OPENSSL_malloc(length);

    if (buffer == NULL) {
        BIO_printf(bio_err, "\x6f\x75\x74\x20\x6f\x66\x20\x6d\x65\x6d\x6f\x72\x79\xa");
        return 0;
    }

    switch (peer.sa.sa_family) {
    case AF_INET:
        memcpy(buffer, &peer.s4.sin_port, sizeof(peer.s4.sin_port));
        memcpy(buffer + sizeof(peer.s4.sin_port),
               &peer.s4.sin_addr, sizeof(struct in_addr));
        break;
#if OPENSSL_USE_IPV6
    case AF_INET6:
        memcpy(buffer, &peer.s6.sin6_port, sizeof(peer.s6.sin6_port));
        memcpy(buffer + sizeof(peer.s6.sin6_port),
               &peer.s6.sin6_addr, sizeof(struct in6_addr));
        break;
#endif
    default:
        OPENSSL_assert(0);
        break;
    }

    /* Calculate HMAC of buffer using the secret */
    HMAC(EVP_sha1(), cookie_secret, COOKIE_SECRET_LENGTH,
         buffer, length, result, &resultlength);
    OPENSSL_free(buffer);

    if (cookie_len == resultlength
        && memcmp(result, cookie, resultlength) == 0)
        return 1;

    return 0;
}

/*
 * Example of extended certificate handling. Where the standard support of
 * one certificate per algorithm is not sufficient an application can decide
 * which certificate(s) to use at runtime based on whatever criteria it deems
 * appropriate.
 */

/* Linked list of certificates, keys and chains */
struct ssl_excert_st {
    int certform;
    const char *certfile;
    int keyform;
    const char *keyfile;
    const char *chainfile;
    X509 *cert;
    EVP_PKEY *key;
    STACK_OF(X509) *chain;
    int build_chain;
    struct ssl_excert_st *next, *prev;
};

struct chain_flags {
    int flag;
    const char *name;
};

struct chain_flags chain_flags_list[] = {
    {CERT_PKEY_VALID, "\x4f\x76\x65\x72\x61\x6c\x6c\x20\x56\x61\x6c\x69\x64\x69\x74\x79"},
    {CERT_PKEY_SIGN, "\x53\x69\x67\x6e\x20\x77\x69\x74\x68\x20\x45\x45\x20\x6b\x65\x79"},
    {CERT_PKEY_EE_SIGNATURE, "\x45\x45\x20\x73\x69\x67\x6e\x61\x74\x75\x72\x65"},
    {CERT_PKEY_CA_SIGNATURE, "\x43\x41\x20\x73\x69\x67\x6e\x61\x74\x75\x72\x65"},
    {CERT_PKEY_EE_PARAM, "\x45\x45\x20\x6b\x65\x79\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73"},
    {CERT_PKEY_CA_PARAM, "\x43\x41\x20\x6b\x65\x79\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73"},
    {CERT_PKEY_EXPLICIT_SIGN, "\x45\x78\x70\x6c\x69\x63\x69\x74\x79\x20\x73\x69\x67\x6e\x20\x77\x69\x74\x68\x20\x45\x45\x20\x6b\x65\x79"},
    {CERT_PKEY_ISSUER_NAME, "\x49\x73\x73\x75\x65\x72\x20\x4e\x61\x6d\x65"},
    {CERT_PKEY_CERT_TYPE, "\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x54\x79\x70\x65"},
    {0, NULL}
};

static void print_chain_flags(BIO *out, SSL *s, int flags)
{
    struct chain_flags *ctmp = chain_flags_list;
    while (ctmp->name) {
        BIO_printf(out, "\x9\x25\x73\x3a\x20\x25\x73\xa", ctmp->name,
                   flags & ctmp->flag ? "\x4f\x4b" : "\x4e\x4f\x54\x20\x4f\x4b");
        ctmp++;
    }
    BIO_printf(out, "\x9\x53\x75\x69\x74\x65\x20\x42\x3a\x20");
    if (SSL_set_cert_flags(s, 0) & SSL_CERT_FLAG_SUITEB_128_LOS)
        BIO_puts(out, flags & CERT_PKEY_SUITEB ? "\x4f\x4b\xa" : "\x4e\x4f\x54\x20\x4f\x4b\xa");
    else
        BIO_printf(out, "\x6e\x6f\x74\x20\x74\x65\x73\x74\x65\x64\xa");
}

/*
 * Very basic selection callback: just use any certificate chain reported as
 * valid. More sophisticated could prioritise according to local policy.
 */
static int set_cert_cb(SSL *ssl, void *arg)
{
    int i, rv;
    SSL_EXCERT *exc = arg;
#ifdef CERT_CB_TEST_RETRY
    static int retry_cnt;
    if (retry_cnt < 5) {
        retry_cnt++;
        fprintf(stderr, "\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x63\x61\x6c\x6c\x62\x61\x63\x6b\x20\x72\x65\x74\x72\x79\x20\x74\x65\x73\x74\x3a\x20\x63\x6f\x75\x6e\x74\x20\x25\x64\xa",
                retry_cnt);
        return -1;
    }
#endif
    SSL_certs_clear(ssl);

    if (!exc)
        return 1;

    /*
     * Go to end of list and traverse backwards since we prepend newer
     * entries this retains the original order.
     */
    while (exc->next)
        exc = exc->next;

    i = 0;

    while (exc) {
        i++;
        rv = SSL_check_chain(ssl, exc->cert, exc->key, exc->chain);
        BIO_printf(bio_err, "\x43\x68\x65\x63\x6b\x69\x6e\x67\x20\x63\x65\x72\x74\x20\x63\x68\x61\x69\x6e\x20\x25\x64\x3a\xa\x53\x75\x62\x6a\x65\x63\x74\x3a\x20", i);
        X509_NAME_print_ex(bio_err, X509_get_subject_name(exc->cert), 0,
                           XN_FLAG_ONELINE);
        BIO_puts(bio_err, "\xa");

        print_chain_flags(bio_err, ssl, rv);
        if (rv & CERT_PKEY_VALID) {
            SSL_use_certificate(ssl, exc->cert);
            SSL_use_PrivateKey(ssl, exc->key);
            /*
             * NB: we wouldn't normally do this as it is not efficient
             * building chains on each connection better to cache the chain
             * in advance.
             */
            if (exc->build_chain) {
                if (!SSL_build_cert_chain(ssl, 0))
                    return 0;
            } else if (exc->chain)
                SSL_set1_chain(ssl, exc->chain);
        }
        exc = exc->prev;
    }
    return 1;
}

void ssl_ctx_set_excert(SSL_CTX *ctx, SSL_EXCERT *exc)
{
    SSL_CTX_set_cert_cb(ctx, set_cert_cb, exc);
}

static int ssl_excert_prepend(SSL_EXCERT **pexc)
{
    SSL_EXCERT *exc;
    exc = OPENSSL_malloc(sizeof(SSL_EXCERT));
    if (!exc)
        return 0;
    exc->certfile = NULL;
    exc->keyfile = NULL;
    exc->chainfile = NULL;
    exc->cert = NULL;
    exc->key = NULL;
    exc->chain = NULL;
    exc->prev = NULL;
    exc->build_chain = 0;

    exc->next = *pexc;
    *pexc = exc;

    if (exc->next) {
        exc->certform = exc->next->certform;
        exc->keyform = exc->next->keyform;
        exc->next->prev = exc;
    } else {
        exc->certform = FORMAT_PEM;
        exc->keyform = FORMAT_PEM;
    }
    return 1;

}

void ssl_excert_free(SSL_EXCERT *exc)
{
    SSL_EXCERT *curr;
    while (exc) {
        if (exc->cert)
            X509_free(exc->cert);
        if (exc->key)
            EVP_PKEY_free(exc->key);
        if (exc->chain)
            sk_X509_pop_free(exc->chain, X509_free);
        curr = exc;
        exc = exc->next;
        OPENSSL_free(curr);
    }
}

int load_excert(SSL_EXCERT **pexc, BIO *err)
{
    SSL_EXCERT *exc = *pexc;
    if (!exc)
        return 1;
    /* If nothing in list, free and set to NULL */
    if (!exc->certfile && !exc->next) {
        ssl_excert_free(exc);
        *pexc = NULL;
        return 1;
    }
    for (; exc; exc = exc->next) {
        if (!exc->certfile) {
            BIO_printf(err, "\x4d\x69\x73\x73\x69\x6e\x67\x20\x66\x69\x6c\x65\x6e\x61\x6d\x65\xa");
            return 0;
        }
        exc->cert = load_cert(err, exc->certfile, exc->certform,
                              NULL, NULL, "\x53\x65\x72\x76\x65\x72\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65");
        if (!exc->cert)
            return 0;
        if (exc->keyfile) {
            exc->key = load_key(err, exc->keyfile, exc->keyform,
                                0, NULL, NULL, "\x53\x65\x72\x76\x65\x72\x20\x4b\x65\x79");
        } else {
            exc->key = load_key(err, exc->certfile, exc->certform,
                                0, NULL, NULL, "\x53\x65\x72\x76\x65\x72\x20\x4b\x65\x79");
        }
        if (!exc->key)
            return 0;
        if (exc->chainfile) {
            exc->chain = load_certs(err,
                                    exc->chainfile, FORMAT_PEM,
                                    NULL, NULL, "\x53\x65\x72\x76\x65\x72\x20\x43\x68\x61\x69\x6e");
            if (!exc->chain)
                return 0;
        }
    }
    return 1;
}

int args_excert(char ***pargs, int *pargc,
                int *badarg, BIO *err, SSL_EXCERT **pexc)
{
    char *arg = **pargs, *argn = (*pargs)[1];
    SSL_EXCERT *exc = *pexc;
    int narg = 2;
    if (!exc) {
        if (ssl_excert_prepend(&exc))
            *pexc = exc;
        else {
            BIO_printf(err, "\x45\x72\x72\x6f\x72\x20\x69\x6e\x69\x74\x69\x61\x6c\x69\x73\x69\x6e\x67\x20\x78\x63\x65\x72\x74\xa");
            *badarg = 1;
            goto err;
        }
    }
    if (strcmp(arg, "\x2d\x78\x63\x65\x72\x74") == 0) {
        if (!argn) {
            *badarg = 1;
            return 1;
        }
        if (exc->certfile && !ssl_excert_prepend(&exc)) {
            BIO_printf(err, "\x45\x72\x72\x6f\x72\x20\x61\x64\x64\x69\x6e\x67\x20\x78\x63\x65\x72\x74\xa");
            *badarg = 1;
            goto err;
        }
        exc->certfile = argn;
    } else if (strcmp(arg, "\x2d\x78\x6b\x65\x79") == 0) {
        if (!argn) {
            *badarg = 1;
            return 1;
        }
        if (exc->keyfile) {
            BIO_printf(err, "\x4b\x65\x79\x20\x61\x6c\x72\x65\x61\x64\x79\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\xa");
            *badarg = 1;
            return 1;
        }
        exc->keyfile = argn;
    } else if (strcmp(arg, "\x2d\x78\x63\x68\x61\x69\x6e") == 0) {
        if (!argn) {
            *badarg = 1;
            return 1;
        }
        if (exc->chainfile) {
            BIO_printf(err, "\x43\x68\x61\x69\x6e\x20\x61\x6c\x72\x65\x61\x64\x79\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\xa");
            *badarg = 1;
            return 1;
        }
        exc->chainfile = argn;
    } else if (strcmp(arg, "\x2d\x78\x63\x68\x61\x69\x6e\x5f\x62\x75\x69\x6c\x64") == 0) {
        narg = 1;
        exc->build_chain = 1;
    } else if (strcmp(arg, "\x2d\x78\x63\x65\x72\x74\x66\x6f\x72\x6d") == 0) {
        if (!argn) {
            *badarg = 1;
            goto err;
        }
        exc->certform = str2fmt(argn);
    } else if (strcmp(arg, "\x2d\x78\x6b\x65\x79\x66\x6f\x72\x6d") == 0) {
        if (!argn) {
            *badarg = 1;
            goto err;
        }
        exc->keyform = str2fmt(argn);
    } else
        return 0;

    (*pargs) += narg;

    if (pargc)
        *pargc -= narg;

    *pexc = exc;

    return 1;

 err:
    ERR_print_errors(err);
    ssl_excert_free(exc);
    *pexc = NULL;
    return 1;
}

static void print_raw_cipherlist(BIO *bio, SSL *s)
{
    const unsigned char *rlist;
    static const unsigned char scsv_id[] = { 0, 0, 0xFF };
    size_t i, rlistlen, num;
    if (!SSL_is_server(s))
        return;
    num = SSL_get0_raw_cipherlist(s, NULL);
    rlistlen = SSL_get0_raw_cipherlist(s, &rlist);
    BIO_puts(bio, "\x43\x6c\x69\x65\x6e\x74\x20\x63\x69\x70\x68\x65\x72\x20\x6c\x69\x73\x74\x3a\x20");
    for (i = 0; i < rlistlen; i += num, rlist += num) {
        const SSL_CIPHER *c = SSL_CIPHER_find(s, rlist);
        if (i)
            BIO_puts(bio, "\x3a");
        if (c)
            BIO_puts(bio, SSL_CIPHER_get_name(c));
        else if (!memcmp(rlist, scsv_id - num + 3, num))
            BIO_puts(bio, "\x53\x43\x53\x56");
        else {
            size_t j;
            BIO_puts(bio, "\x30\x78");
            for (j = 0; j < num; j++)
                BIO_printf(bio, "\x25\x30\x32\x58", rlist[j]);
        }
    }
    BIO_puts(bio, "\xa");
}

void print_ssl_summary(BIO *bio, SSL *s)
{
    const SSL_CIPHER *c;
    X509 *peer;
    /*
     * const char *pnam = SSL_is_server(s) ? "client" : "server";
     */
    BIO_printf(bio, "\x50\x72\x6f\x74\x6f\x63\x6f\x6c\x20\x76\x65\x72\x73\x69\x6f\x6e\x3a\x20\x25\x73\xa", SSL_get_version(s));
    print_raw_cipherlist(bio, s);
    c = SSL_get_current_cipher(s);
    BIO_printf(bio, "\x43\x69\x70\x68\x65\x72\x73\x75\x69\x74\x65\x3a\x20\x25\x73\xa", SSL_CIPHER_get_name(c));
    do_print_sigalgs(bio, s, 0);
    peer = SSL_get_peer_certificate(s);
    if (peer) {
        int nid;
        BIO_puts(bio, "\x50\x65\x65\x72\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x3a\x20");
        X509_NAME_print_ex(bio, X509_get_subject_name(peer),
                           0, XN_FLAG_ONELINE);
        BIO_puts(bio, "\xa");
        if (SSL_get_peer_signature_nid(s, &nid))
            BIO_printf(bio, "\x48\x61\x73\x68\x20\x75\x73\x65\x64\x3a\x20\x25\x73\xa", OBJ_nid2sn(nid));
    } else
        BIO_puts(bio, "\x4e\x6f\x20\x70\x65\x65\x72\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\xa");
    if (peer)
        X509_free(peer);
#ifndef OPENSSL_NO_EC
    ssl_print_point_formats(bio, s);
    if (SSL_is_server(s))
        ssl_print_curves(bio, s, 1);
    else
        ssl_print_tmp_key(bio, s);
#else
    if (!SSL_is_server(s))
        ssl_print_tmp_key(bio, s);
#endif
}

int args_ssl(char ***pargs, int *pargc, SSL_CONF_CTX *cctx,
             int *badarg, BIO *err, STACK_OF(OPENSSL_STRING) **pstr,
             int *no_prot_opt)
{
    char *arg = **pargs, *argn = (*pargs)[1];
    int rv;

    if (strcmp(arg, "\x2d\x6e\x6f\x5f\x73\x73\x6c\x32") == 0 || strcmp(arg, "\x2d\x6e\x6f\x5f\x73\x73\x6c\x33") == 0
        || strcmp(arg, "\x2d\x6e\x6f\x5f\x74\x6c\x73\x31") == 0 || strcmp(arg, "\x2d\x6e\x6f\x5f\x74\x6c\x73\x31\x5f\x31") == 0
        || strcmp(arg, "\x2d\x6e\x6f\x5f\x74\x6c\x73\x31\x5f\x32") == 0) {
        *no_prot_opt = 1;
    }

    /* Attempt to run SSL configuration command */
    rv = SSL_CONF_cmd_argv(cctx, pargc, pargs);
    /* If parameter not recognised just return */
    if (rv == 0)
        return 0;
    /* see if missing argument error */
    if (rv == -3) {
        BIO_printf(err, "\x25\x73\x20\x6e\x65\x65\x64\x73\x20\x61\x6e\x20\x61\x72\x67\x75\x6d\x65\x6e\x74\xa", arg);
        *badarg = 1;
        goto end;
    }
    /* Check for some other error */
    if (rv < 0) {
        BIO_printf(err, "\x45\x72\x72\x6f\x72\x20\x77\x69\x74\x68\x20\x63\x6f\x6d\x6d\x61\x6e\x64\x3a\x20\x22\x25\x73\x20\x25\x73\x22\xa",
                   arg, argn ? argn : "");
        *badarg = 1;
        goto end;
    }
    /* Store command and argument */
    /* If only one argument processed store value as NULL */
    if (rv == 1)
        argn = NULL;
    if (!*pstr)
        *pstr = sk_OPENSSL_STRING_new_null();
    if (!*pstr || !sk_OPENSSL_STRING_push(*pstr, arg) ||
        !sk_OPENSSL_STRING_push(*pstr, argn)) {
        BIO_puts(err, "\x4d\x65\x6d\x6f\x72\x79\x20\x61\x6c\x6c\x6f\x63\x61\x74\x69\x6f\x6e\x20\x66\x61\x69\x6c\x75\x72\x65\xa");
        goto end;
    }

 end:
    if (*badarg)
        ERR_print_errors(err);

    return 1;
}

int args_ssl_call(SSL_CTX *ctx, BIO *err, SSL_CONF_CTX *cctx,
                  STACK_OF(OPENSSL_STRING) *str, int no_ecdhe, int no_jpake)
{
    int i;
    SSL_CONF_CTX_set_ssl_ctx(cctx, ctx);
    for (i = 0; i < sk_OPENSSL_STRING_num(str); i += 2) {
        const char *param = sk_OPENSSL_STRING_value(str, i);
        const char *value = sk_OPENSSL_STRING_value(str, i + 1);
        /*
         * If no_ecdhe or named curve already specified don't need a default.
         */
        if (!no_ecdhe && !strcmp(param, "\x2d\x6e\x61\x6d\x65\x64\x5f\x63\x75\x72\x76\x65"))
            no_ecdhe = 1;
#ifndef OPENSSL_NO_JPAKE
        if (!no_jpake && !strcmp(param, "\x2d\x63\x69\x70\x68\x65\x72")) {
            BIO_puts(err, "\x4a\x50\x41\x4b\x45\x20\x73\x65\x74\x73\x20\x63\x69\x70\x68\x65\x72\x20\x74\x6f\x20\x50\x53\x4b\xa");
            return 0;
        }
#endif
        if (SSL_CONF_cmd(cctx, param, value) <= 0) {
            BIO_printf(err, "\x45\x72\x72\x6f\x72\x20\x77\x69\x74\x68\x20\x63\x6f\x6d\x6d\x61\x6e\x64\x3a\x20\x22\x25\x73\x20\x25\x73\x22\xa",
                       param, value ? value : "");
            ERR_print_errors(err);
            return 0;
        }
    }
    /*
     * This is a special case to keep existing s_server functionality: if we
     * don't have any curve specified *and* we haven't disabled ECDHE then
     * use P-256.
     */
    if (!no_ecdhe) {
        if (SSL_CONF_cmd(cctx, "\x2d\x6e\x61\x6d\x65\x64\x5f\x63\x75\x72\x76\x65", "\x50\x2d\x32\x35\x36") <= 0) {
            BIO_puts(err, "\x45\x72\x72\x6f\x72\x20\x73\x65\x74\x74\x69\x6e\x67\x20\x45\x43\x20\x63\x75\x72\x76\x65\xa");
            ERR_print_errors(err);
            return 0;
        }
    }
#ifndef OPENSSL_NO_JPAKE
    if (!no_jpake) {
        if (SSL_CONF_cmd(cctx, "\x2d\x63\x69\x70\x68\x65\x72", "\x50\x53\x4b") <= 0) {
            BIO_puts(err, "\x45\x72\x72\x6f\x72\x20\x73\x65\x74\x74\x69\x6e\x67\x20\x63\x69\x70\x68\x65\x72\x20\x74\x6f\x20\x50\x53\x4b\xa");
            ERR_print_errors(err);
            return 0;
        }
    }
#endif
    if (!SSL_CONF_CTX_finish(cctx)) {
        BIO_puts(err, "\x45\x72\x72\x6f\x72\x20\x66\x69\x6e\x69\x73\x68\x69\x6e\x67\x20\x63\x6f\x6e\x74\x65\x78\x74\xa");
        ERR_print_errors(err);
        return 0;
    }
    return 1;
}

static int add_crls_store(X509_STORE *st, STACK_OF(X509_CRL) *crls)
{
    X509_CRL *crl;
    int i;
    for (i = 0; i < sk_X509_CRL_num(crls); i++) {
        crl = sk_X509_CRL_value(crls, i);
        X509_STORE_add_crl(st, crl);
    }
    return 1;
}

int ssl_ctx_add_crls(SSL_CTX *ctx, STACK_OF(X509_CRL) *crls, int crl_download)
{
    X509_STORE *st;
    st = SSL_CTX_get_cert_store(ctx);
    add_crls_store(st, crls);
    if (crl_download)
        store_setup_crl_download(st);
    return 1;
}

int ssl_load_stores(SSL_CTX *ctx,
                    const char *vfyCApath, const char *vfyCAfile,
                    const char *chCApath, const char *chCAfile,
                    STACK_OF(X509_CRL) *crls, int crl_download)
{
    X509_STORE *vfy = NULL, *ch = NULL;
    int rv = 0;
    if (vfyCApath || vfyCAfile) {
        vfy = X509_STORE_new();
        if (!X509_STORE_load_locations(vfy, vfyCAfile, vfyCApath))
            goto err;
        add_crls_store(vfy, crls);
        SSL_CTX_set1_verify_cert_store(ctx, vfy);
        if (crl_download)
            store_setup_crl_download(vfy);
    }
    if (chCApath || chCAfile) {
        ch = X509_STORE_new();
        if (!X509_STORE_load_locations(ch, chCAfile, chCApath))
            goto err;
        SSL_CTX_set1_chain_cert_store(ctx, ch);
    }
    rv = 1;
 err:
    if (vfy)
        X509_STORE_free(vfy);
    if (ch)
        X509_STORE_free(ch);
    return rv;
}
