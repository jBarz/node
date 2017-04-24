/* crypto/asn1/t_req.c */
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
#include "cryptlib.h"
#include <openssl/buffer.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#ifndef OPENSSL_NO_RSA
# include <openssl/rsa.h>
#endif
#ifndef OPENSSL_NO_DSA
# include <openssl/dsa.h>
#endif

#ifndef OPENSSL_NO_FP_API
int X509_REQ_print_fp(FILE *fp, X509_REQ *x)
{
    BIO *b;
    int ret;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        X509err(X509_F_X509_REQ_PRINT_FP, ERR_R_BUF_LIB);
        return (0);
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = X509_REQ_print(b, x);
    BIO_free(b);
    return (ret);
}
#endif

int X509_REQ_print_ex(BIO *bp, X509_REQ *x, unsigned long nmflags,
                      unsigned long cflag)
{
    unsigned long l;
    int i;
    const char *neg;
    X509_REQ_INFO *ri;
    EVP_PKEY *pkey;
    STACK_OF(X509_ATTRIBUTE) *sk;
    STACK_OF(X509_EXTENSION) *exts;
    char mlch = '\x20';
    int nmindent = 0;

    if ((nmflags & XN_FLAG_SEP_MASK) == XN_FLAG_SEP_MULTILINE) {
        mlch = '\xa';
        nmindent = 12;
    }

    if (nmflags == X509_FLAG_COMPAT)
        nmindent = 16;

    ri = x->req_info;
    if (!(cflag & X509_FLAG_NO_HEADER)) {
        if (BIO_write(bp, "\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x52\x65\x71\x75\x65\x73\x74\x3a\xa", 21) <= 0)
            goto err;
        if (BIO_write(bp, "\x20\x20\x20\x20\x44\x61\x74\x61\x3a\xa", 10) <= 0)
            goto err;
    }
    if (!(cflag & X509_FLAG_NO_VERSION)) {
        neg = (ri->version->type == V_ASN1_NEG_INTEGER) ? "\x2d" : "";
        l = 0;
        for (i = 0; i < ri->version->length; i++) {
            l <<= 8;
            l += ri->version->data[i];
        }
        if (BIO_printf(bp, "\x25\x38\x73\x56\x65\x72\x73\x69\x6f\x6e\x3a\x20\x25\x73\x25\x6c\x75\x20\x28\x25\x73\x30\x78\x25\x6c\x78\x29\xa", "", neg, l, neg,
                       l) <= 0)
            goto err;
    }
    if (!(cflag & X509_FLAG_NO_SUBJECT)) {
        if (BIO_printf(bp, "\x20\x20\x20\x20\x20\x20\x20\x20\x53\x75\x62\x6a\x65\x63\x74\x3a\x25\x63", mlch) <= 0)
            goto err;
        if (X509_NAME_print_ex(bp, ri->subject, nmindent, nmflags) < 0)
            goto err;
        if (BIO_write(bp, "\xa", 1) <= 0)
            goto err;
    }
    if (!(cflag & X509_FLAG_NO_PUBKEY)) {
        if (BIO_write(bp, "\x20\x20\x20\x20\x20\x20\x20\x20\x53\x75\x62\x6a\x65\x63\x74\x20\x50\x75\x62\x6c\x69\x63\x20\x4b\x65\x79\x20\x49\x6e\x66\x6f\x3a\xa", 33) <= 0)
            goto err;
        if (BIO_printf(bp, "\x25\x31\x32\x73\x50\x75\x62\x6c\x69\x63\x20\x4b\x65\x79\x20\x41\x6c\x67\x6f\x72\x69\x74\x68\x6d\x3a\x20", "") <= 0)
            goto err;
        if (i2a_ASN1_OBJECT(bp, ri->pubkey->algor->algorithm) <= 0)
            goto err;
        if (BIO_puts(bp, "\xa") <= 0)
            goto err;

        pkey = X509_REQ_get_pubkey(x);
        if (pkey == NULL) {
            BIO_printf(bp, "\x25\x31\x32\x73\x55\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x6c\x6f\x61\x64\x20\x50\x75\x62\x6c\x69\x63\x20\x4b\x65\x79\xa", "");
            ERR_print_errors(bp);
        } else {
            EVP_PKEY_print_public(bp, pkey, 16, NULL);
            EVP_PKEY_free(pkey);
        }
    }

    if (!(cflag & X509_FLAG_NO_ATTRIBUTES)) {
        /* may not be */
        if (BIO_printf(bp, "\x25\x38\x73\x41\x74\x74\x72\x69\x62\x75\x74\x65\x73\x3a\xa", "") <= 0)
            goto err;

        sk = x->req_info->attributes;
        if (sk_X509_ATTRIBUTE_num(sk) == 0) {
            if (BIO_printf(bp, "\x25\x31\x32\x73\x61\x30\x3a\x30\x30\xa", "") <= 0)
                goto err;
        } else {
            for (i = 0; i < sk_X509_ATTRIBUTE_num(sk); i++) {
                ASN1_TYPE *at;
                X509_ATTRIBUTE *a;
                ASN1_BIT_STRING *bs = NULL;
                ASN1_TYPE *t;
                int j, type = 0, count = 1, ii = 0;

                a = sk_X509_ATTRIBUTE_value(sk, i);
                if (X509_REQ_extension_nid(OBJ_obj2nid(a->object)))
                    continue;
                if (BIO_printf(bp, "\x25\x31\x32\x73", "") <= 0)
                    goto err;
                if ((j = i2a_ASN1_OBJECT(bp, a->object)) > 0) {
                    if (a->single) {
                        t = a->value.single;
                        type = t->type;
                        bs = t->value.bit_string;
                    } else {
                        ii = 0;
                        count = sk_ASN1_TYPE_num(a->value.set);
 get_next:
                        at = sk_ASN1_TYPE_value(a->value.set, ii);
                        type = at->type;
                        bs = at->value.asn1_string;
                    }
                }
                for (j = 25 - j; j > 0; j--)
                    if (BIO_write(bp, "\x20", 1) != 1)
                        goto err;
                if (BIO_puts(bp, "\x3a") <= 0)
                    goto err;
                if ((type == V_ASN1_PRINTABLESTRING) ||
                    (type == V_ASN1_UTF8STRING) ||
                    (type == V_ASN1_T61STRING) ||
                    (type == V_ASN1_IA5STRING)) {
                    if (BIO_write(bp, (char *)bs->data, bs->length)
                        != bs->length)
                        goto err;
                    BIO_puts(bp, "\xa");
                } else {
                    BIO_puts(bp, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x70\x72\x69\x6e\x74\x20\x61\x74\x74\x72\x69\x62\x75\x74\x65\xa");
                }
                if (++ii < count)
                    goto get_next;
            }
        }
    }
    if (!(cflag & X509_FLAG_NO_EXTENSIONS)) {
        exts = X509_REQ_get_extensions(x);
        if (exts) {
            BIO_printf(bp, "\x25\x38\x73\x52\x65\x71\x75\x65\x73\x74\x65\x64\x20\x45\x78\x74\x65\x6e\x73\x69\x6f\x6e\x73\x3a\xa", "");
            for (i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
                ASN1_OBJECT *obj;
                X509_EXTENSION *ex;
                int j;
                ex = sk_X509_EXTENSION_value(exts, i);
                if (BIO_printf(bp, "\x25\x31\x32\x73", "") <= 0)
                    goto err;
                obj = X509_EXTENSION_get_object(ex);
                i2a_ASN1_OBJECT(bp, obj);
                j = X509_EXTENSION_get_critical(ex);
                if (BIO_printf(bp, "\x3a\x20\x25\x73\xa", j ? "\x63\x72\x69\x74\x69\x63\x61\x6c" : "") <= 0)
                    goto err;
                if (!X509V3_EXT_print(bp, ex, cflag, 16)) {
                    BIO_printf(bp, "\x25\x31\x36\x73", "");
                    M_ASN1_OCTET_STRING_print(bp, ex->value);
                }
                if (BIO_write(bp, "\xa", 1) <= 0)
                    goto err;
            }
            sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
        }
    }

    if (!(cflag & X509_FLAG_NO_SIGDUMP)) {
        if (!X509_signature_print(bp, x->sig_alg, x->signature))
            goto err;
    }

    return (1);
 err:
    X509err(X509_F_X509_REQ_PRINT_EX, ERR_R_BUF_LIB);
    return (0);
}

int X509_REQ_print(BIO *bp, X509_REQ *x)
{
    return X509_REQ_print_ex(bp, x, XN_FLAG_COMPAT, X509_FLAG_COMPAT);
}
