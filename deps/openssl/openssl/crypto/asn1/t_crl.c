/* t_crl.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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
#include "cryptlib.h"
#include <openssl/buffer.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#ifndef OPENSSL_NO_FP_API
int X509_CRL_print_fp(FILE *fp, X509_CRL *x)
{
    BIO *b;
    int ret;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        X509err(X509_F_X509_CRL_PRINT_FP, ERR_R_BUF_LIB);
        return (0);
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = X509_CRL_print(b, x);
    BIO_free(b);
    return (ret);
}
#endif

int X509_CRL_print(BIO *out, X509_CRL *x)
{
    STACK_OF(X509_REVOKED) *rev;
    X509_REVOKED *r;
    long l;
    int i;
    char *p;

    BIO_printf(out, "\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x52\x65\x76\x6f\x63\x61\x74\x69\x6f\x6e\x20\x4c\x69\x73\x74\x20\x28\x43\x52\x4c\x29\x3a\xa");
    l = X509_CRL_get_version(x);
    BIO_printf(out, "\x25\x38\x73\x56\x65\x72\x73\x69\x6f\x6e\x20\x25\x6c\x75\x20\x28\x30\x78\x25\x6c\x78\x29\xa", "", l + 1, l);
    i = OBJ_obj2nid(x->sig_alg->algorithm);
    X509_signature_print(out, x->sig_alg, NULL);
    p = X509_NAME_oneline(X509_CRL_get_issuer(x), NULL, 0);
    BIO_printf(out, "\x25\x38\x73\x49\x73\x73\x75\x65\x72\x3a\x20\x25\x73\xa", "", p);
    OPENSSL_free(p);
    BIO_printf(out, "\x25\x38\x73\x4c\x61\x73\x74\x20\x55\x70\x64\x61\x74\x65\x3a\x20", "");
    ASN1_TIME_print(out, X509_CRL_get_lastUpdate(x));
    BIO_printf(out, "\xa\x25\x38\x73\x4e\x65\x78\x74\x20\x55\x70\x64\x61\x74\x65\x3a\x20", "");
    if (X509_CRL_get_nextUpdate(x))
        ASN1_TIME_print(out, X509_CRL_get_nextUpdate(x));
    else
        BIO_printf(out, "\x4e\x4f\x4e\x45");
    BIO_printf(out, "\xa");

    X509V3_extensions_print(out, "\x43\x52\x4c\x20\x65\x78\x74\x65\x6e\x73\x69\x6f\x6e\x73", x->crl->extensions, 0, 8);

    rev = X509_CRL_get_REVOKED(x);

    if (sk_X509_REVOKED_num(rev) > 0)
        BIO_printf(out, "\x52\x65\x76\x6f\x6b\x65\x64\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73\x3a\xa");
    else
        BIO_printf(out, "\x4e\x6f\x20\x52\x65\x76\x6f\x6b\x65\x64\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73\x2e\xa");

    for (i = 0; i < sk_X509_REVOKED_num(rev); i++) {
        r = sk_X509_REVOKED_value(rev, i);
        BIO_printf(out, "\x20\x20\x20\x20\x53\x65\x72\x69\x61\x6c\x20\x4e\x75\x6d\x62\x65\x72\x3a\x20");
        i2a_ASN1_INTEGER(out, r->serialNumber);
        BIO_printf(out, "\xa\x20\x20\x20\x20\x20\x20\x20\x20\x52\x65\x76\x6f\x63\x61\x74\x69\x6f\x6e\x20\x44\x61\x74\x65\x3a\x20");
        ASN1_TIME_print(out, r->revocationDate);
        BIO_printf(out, "\xa");
        X509V3_extensions_print(out, "\x43\x52\x4c\x20\x65\x6e\x74\x72\x79\x20\x65\x78\x74\x65\x6e\x73\x69\x6f\x6e\x73",
                                r->extensions, 0, 8);
    }
    X509_signature_print(out, x->sig_alg, x->signature);

    return 1;

}
