/* crypto/asn1/t_x509.c */
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
#ifndef OPENSSL_NO_RSA
# include <openssl/rsa.h>
#endif
#ifndef OPENSSL_NO_DSA
# include <openssl/dsa.h>
#endif
#ifndef OPENSSL_NO_EC
# include <openssl/ec.h>
#endif
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "asn1_locl.h"

#ifndef OPENSSL_NO_FP_API
int X509_print_fp(FILE *fp, X509 *x)
{
    return X509_print_ex_fp(fp, x, XN_FLAG_COMPAT, X509_FLAG_COMPAT);
}

int X509_print_ex_fp(FILE *fp, X509 *x, unsigned long nmflag,
                     unsigned long cflag)
{
    BIO *b;
    int ret;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        X509err(X509_F_X509_PRINT_EX_FP, ERR_R_BUF_LIB);
        return (0);
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = X509_print_ex(b, x, nmflag, cflag);
    BIO_free(b);
    return (ret);
}
#endif

int X509_print(BIO *bp, X509 *x)
{
    return X509_print_ex(bp, x, XN_FLAG_COMPAT, X509_FLAG_COMPAT);
}

int X509_print_ex(BIO *bp, X509 *x, unsigned long nmflags,
                  unsigned long cflag)
{
    long l;
    int ret = 0, i;
    char *m = NULL, mlch = '\x20';
    int nmindent = 0;
    X509_CINF *ci;
    ASN1_INTEGER *bs;
    EVP_PKEY *pkey = NULL;
    const char *neg;

    if ((nmflags & XN_FLAG_SEP_MASK) == XN_FLAG_SEP_MULTILINE) {
        mlch = '\xa';
        nmindent = 12;
    }

    if (nmflags == X509_FLAG_COMPAT)
        nmindent = 16;

    ci = x->cert_info;
    if (!(cflag & X509_FLAG_NO_HEADER)) {
        if (BIO_write(bp, "\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x3a\xa", 13) <= 0)
            goto err;
        if (BIO_write(bp, "\x20\x20\x20\x20\x44\x61\x74\x61\x3a\xa", 10) <= 0)
            goto err;
    }
    if (!(cflag & X509_FLAG_NO_VERSION)) {
        l = X509_get_version(x);
        if (BIO_printf(bp, "\x25\x38\x73\x56\x65\x72\x73\x69\x6f\x6e\x3a\x20\x25\x6c\x75\x20\x28\x30\x78\x25\x6c\x78\x29\xa", "", l + 1, l) <= 0)
            goto err;
    }
    if (!(cflag & X509_FLAG_NO_SERIAL)) {

        if (BIO_write(bp, "\x20\x20\x20\x20\x20\x20\x20\x20\x53\x65\x72\x69\x61\x6c\x20\x4e\x75\x6d\x62\x65\x72\x3a", 22) <= 0)
            goto err;

        bs = X509_get_serialNumber(x);
        if (bs->length < (int)sizeof(long)
            || (bs->length == sizeof(long) && (bs->data[0] & 0x80) == 0)) {
            l = ASN1_INTEGER_get(bs);
            if (bs->type == V_ASN1_NEG_INTEGER) {
                l = -l;
                neg = "\x2d";
            } else
                neg = "";
            if (BIO_printf(bp, "\x20\x25\x73\x25\x6c\x75\x20\x28\x25\x73\x30\x78\x25\x6c\x78\x29\xa", neg, l, neg, l) <= 0)
                goto err;
        } else {
            neg = (bs->type == V_ASN1_NEG_INTEGER) ? "\x20\x28\x4e\x65\x67\x61\x74\x69\x76\x65\x29" : "";
            if (BIO_printf(bp, "\xa\x25\x31\x32\x73\x25\x73", "", neg) <= 0)
                goto err;

            for (i = 0; i < bs->length; i++) {
                if (BIO_printf(bp, "\x25\x30\x32\x78\x25\x63", bs->data[i],
                               ((i + 1 == bs->length) ? '\xa' : '\x3a')) <= 0)
                    goto err;
            }
        }

    }

    if (!(cflag & X509_FLAG_NO_SIGNAME)) {
        if (X509_signature_print(bp, ci->signature, NULL) <= 0)
            goto err;
#if 0
        if (BIO_printf(bp, "\x25\x38\x73\x53\x69\x67\x6e\x61\x74\x75\x72\x65\x20\x41\x6c\x67\x6f\x72\x69\x74\x68\x6d\x3a\x20", "") <= 0)
            goto err;
        if (i2a_ASN1_OBJECT(bp, ci->signature->algorithm) <= 0)
            goto err;
        if (BIO_puts(bp, "\xa") <= 0)
            goto err;
#endif
    }

    if (!(cflag & X509_FLAG_NO_ISSUER)) {
        if (BIO_printf(bp, "\x20\x20\x20\x20\x20\x20\x20\x20\x49\x73\x73\x75\x65\x72\x3a\x25\x63", mlch) <= 0)
            goto err;
        if (X509_NAME_print_ex(bp, X509_get_issuer_name(x), nmindent, nmflags)
            < 0)
            goto err;
        if (BIO_write(bp, "\xa", 1) <= 0)
            goto err;
    }
    if (!(cflag & X509_FLAG_NO_VALIDITY)) {
        if (BIO_write(bp, "\x20\x20\x20\x20\x20\x20\x20\x20\x56\x61\x6c\x69\x64\x69\x74\x79\xa", 17) <= 0)
            goto err;
        if (BIO_write(bp, "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x4e\x6f\x74\x20\x42\x65\x66\x6f\x72\x65\x3a\x20", 24) <= 0)
            goto err;
        if (!ASN1_TIME_print(bp, X509_get_notBefore(x)))
            goto err;
        if (BIO_write(bp, "\xa\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x4e\x6f\x74\x20\x41\x66\x74\x65\x72\x20\x3a\x20", 25) <= 0)
            goto err;
        if (!ASN1_TIME_print(bp, X509_get_notAfter(x)))
            goto err;
        if (BIO_write(bp, "\xa", 1) <= 0)
            goto err;
    }
    if (!(cflag & X509_FLAG_NO_SUBJECT)) {
        if (BIO_printf(bp, "\x20\x20\x20\x20\x20\x20\x20\x20\x53\x75\x62\x6a\x65\x63\x74\x3a\x25\x63", mlch) <= 0)
            goto err;
        if (X509_NAME_print_ex
            (bp, X509_get_subject_name(x), nmindent, nmflags) < 0)
            goto err;
        if (BIO_write(bp, "\xa", 1) <= 0)
            goto err;
    }
    if (!(cflag & X509_FLAG_NO_PUBKEY)) {
        if (BIO_write(bp, "\x20\x20\x20\x20\x20\x20\x20\x20\x53\x75\x62\x6a\x65\x63\x74\x20\x50\x75\x62\x6c\x69\x63\x20\x4b\x65\x79\x20\x49\x6e\x66\x6f\x3a\xa", 33) <= 0)
            goto err;
        if (BIO_printf(bp, "\x25\x31\x32\x73\x50\x75\x62\x6c\x69\x63\x20\x4b\x65\x79\x20\x41\x6c\x67\x6f\x72\x69\x74\x68\x6d\x3a\x20", "") <= 0)
            goto err;
        if (i2a_ASN1_OBJECT(bp, ci->key->algor->algorithm) <= 0)
            goto err;
        if (BIO_puts(bp, "\xa") <= 0)
            goto err;

        pkey = X509_get_pubkey(x);
        if (pkey == NULL) {
            BIO_printf(bp, "\x25\x31\x32\x73\x55\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x6c\x6f\x61\x64\x20\x50\x75\x62\x6c\x69\x63\x20\x4b\x65\x79\xa", "");
            ERR_print_errors(bp);
        } else {
            EVP_PKEY_print_public(bp, pkey, 16, NULL);
            EVP_PKEY_free(pkey);
        }
    }

    if (!(cflag & X509_FLAG_NO_IDS)) {
        if (ci->issuerUID) {
            if (BIO_printf(bp, "\x25\x38\x73\x49\x73\x73\x75\x65\x72\x20\x55\x6e\x69\x71\x75\x65\x20\x49\x44\x3a\x20", "") <= 0)
                goto err;
            if (!X509_signature_dump(bp, ci->issuerUID, 12))
                goto err;
        }
        if (ci->subjectUID) {
            if (BIO_printf(bp, "\x25\x38\x73\x53\x75\x62\x6a\x65\x63\x74\x20\x55\x6e\x69\x71\x75\x65\x20\x49\x44\x3a\x20", "") <= 0)
                goto err;
            if (!X509_signature_dump(bp, ci->subjectUID, 12))
                goto err;
        }
    }

    if (!(cflag & X509_FLAG_NO_EXTENSIONS))
        X509V3_extensions_print(bp, "\x58\x35\x30\x39\x76\x33\x20\x65\x78\x74\x65\x6e\x73\x69\x6f\x6e\x73",
                                ci->extensions, cflag, 8);

    if (!(cflag & X509_FLAG_NO_SIGDUMP)) {
        if (X509_signature_print(bp, x->sig_alg, x->signature) <= 0)
            goto err;
    }
    if (!(cflag & X509_FLAG_NO_AUX)) {
        if (!X509_CERT_AUX_print(bp, x->aux, 0))
            goto err;
    }
    ret = 1;
 err:
    if (m != NULL)
        OPENSSL_free(m);
    return (ret);
}

int X509_ocspid_print(BIO *bp, X509 *x)
{
    unsigned char *der = NULL;
    unsigned char *dertmp;
    int derlen;
    int i;
    unsigned char SHA1md[SHA_DIGEST_LENGTH];

    /*
     * display the hash of the subject as it would appear in OCSP requests
     */
    if (BIO_printf(bp, "\x20\x20\x20\x20\x20\x20\x20\x20\x53\x75\x62\x6a\x65\x63\x74\x20\x4f\x43\x53\x50\x20\x68\x61\x73\x68\x3a\x20") <= 0)
        goto err;
    derlen = i2d_X509_NAME(x->cert_info->subject, NULL);
    if ((der = dertmp = (unsigned char *)OPENSSL_malloc(derlen)) == NULL)
        goto err;
    i2d_X509_NAME(x->cert_info->subject, &dertmp);

    if (!EVP_Digest(der, derlen, SHA1md, NULL, EVP_sha1(), NULL))
        goto err;
    for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
        if (BIO_printf(bp, "\x25\x30\x32\x58", SHA1md[i]) <= 0)
            goto err;
    }
    OPENSSL_free(der);
    der = NULL;

    /*
     * display the hash of the public key as it would appear in OCSP requests
     */
    if (BIO_printf(bp, "\xa\x20\x20\x20\x20\x20\x20\x20\x20\x50\x75\x62\x6c\x69\x63\x20\x6b\x65\x79\x20\x4f\x43\x53\x50\x20\x68\x61\x73\x68\x3a\x20") <= 0)
        goto err;

    if (!EVP_Digest(x->cert_info->key->public_key->data,
                    x->cert_info->key->public_key->length,
                    SHA1md, NULL, EVP_sha1(), NULL))
        goto err;
    for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
        if (BIO_printf(bp, "\x25\x30\x32\x58", SHA1md[i]) <= 0)
            goto err;
    }
    BIO_printf(bp, "\xa");

    return (1);
 err:
    if (der != NULL)
        OPENSSL_free(der);
    return (0);
}

int X509_signature_dump(BIO *bp, const ASN1_STRING *sig, int indent)
{
    const unsigned char *s;
    int i, n;

    n = sig->length;
    s = sig->data;
    for (i = 0; i < n; i++) {
        if ((i % 18) == 0) {
            if (BIO_write(bp, "\xa", 1) <= 0)
                return 0;
            if (BIO_indent(bp, indent, indent) <= 0)
                return 0;
        }
        if (BIO_printf(bp, "\x25\x30\x32\x78\x25\x73", s[i], ((i + 1) == n) ? "" : "\x3a") <= 0)
            return 0;
    }
    if (BIO_write(bp, "\xa", 1) != 1)
        return 0;

    return 1;
}

int X509_signature_print(BIO *bp, X509_ALGOR *sigalg, ASN1_STRING *sig)
{
    int sig_nid;
    if (BIO_puts(bp, "\x20\x20\x20\x20\x53\x69\x67\x6e\x61\x74\x75\x72\x65\x20\x41\x6c\x67\x6f\x72\x69\x74\x68\x6d\x3a\x20") <= 0)
        return 0;
    if (i2a_ASN1_OBJECT(bp, sigalg->algorithm) <= 0)
        return 0;

    sig_nid = OBJ_obj2nid(sigalg->algorithm);
    if (sig_nid != NID_undef) {
        int pkey_nid, dig_nid;
        const EVP_PKEY_ASN1_METHOD *ameth;
        if (OBJ_find_sigid_algs(sig_nid, &dig_nid, &pkey_nid)) {
            ameth = EVP_PKEY_asn1_find(NULL, pkey_nid);
            if (ameth && ameth->sig_print)
                return ameth->sig_print(bp, sigalg, sig, 9, 0);
        }
    }
    if (sig)
        return X509_signature_dump(bp, sig, 9);
    else if (BIO_puts(bp, "\xa") <= 0)
        return 0;
    return 1;
}

int ASN1_STRING_print(BIO *bp, const ASN1_STRING *v)
{
    int i, n;
    char buf[80];
    const char *p;

    if (v == NULL)
        return (0);
    n = 0;
    p = (const char *)v->data;
    for (i = 0; i < v->length; i++) {
        if ((p[i] > '\x7e') || ((p[i] < '\x20') &&
                             (p[i] != '\xa') && (p[i] != '\xd')))
            buf[n] = '\x2e';
        else
            buf[n] = p[i];
        n++;
        if (n >= 80) {
            if (BIO_write(bp, buf, n) <= 0)
                return (0);
            n = 0;
        }
    }
    if (n > 0)
        if (BIO_write(bp, buf, n) <= 0)
            return (0);
    return (1);
}

int ASN1_TIME_print(BIO *bp, const ASN1_TIME *tm)
{
    if (tm->type == V_ASN1_UTCTIME)
        return ASN1_UTCTIME_print(bp, tm);
    if (tm->type == V_ASN1_GENERALIZEDTIME)
        return ASN1_GENERALIZEDTIME_print(bp, tm);
    BIO_write(bp, "\x42\x61\x64\x20\x74\x69\x6d\x65\x20\x76\x61\x6c\x75\x65", 14);
    return (0);
}

static const char *mon[12] = {
    "\x4a\x61\x6e", "\x46\x65\x62", "\x4d\x61\x72", "\x41\x70\x72", "\x4d\x61\x79", "\x4a\x75\x6e",
    "\x4a\x75\x6c", "\x41\x75\x67", "\x53\x65\x70", "\x4f\x63\x74", "\x4e\x6f\x76", "\x44\x65\x63"
};

int ASN1_GENERALIZEDTIME_print(BIO *bp, const ASN1_GENERALIZEDTIME *tm)
{
    char *v;
    int gmt = 0;
    int i;
    int y = 0, M = 0, d = 0, h = 0, m = 0, s = 0;
    char *f = NULL;
    int f_len = 0;

    i = tm->length;
    v = (char *)tm->data;

    if (i < 12)
        goto err;
    if (v[i - 1] == '\x5a')
        gmt = 1;
    for (i = 0; i < 12; i++)
        if ((v[i] > '\x39') || (v[i] < '\x30'))
            goto err;
    y = (v[0] - '\x30') * 1000 + (v[1] - '\x30') * 100
        + (v[2] - '\x30') * 10 + (v[3] - '\x30');
    M = (v[4] - '\x30') * 10 + (v[5] - '\x30');
    if ((M > 12) || (M < 1))
        goto err;
    d = (v[6] - '\x30') * 10 + (v[7] - '\x30');
    h = (v[8] - '\x30') * 10 + (v[9] - '\x30');
    m = (v[10] - '\x30') * 10 + (v[11] - '\x30');
    if (tm->length >= 14 &&
        (v[12] >= '\x30') && (v[12] <= '\x39') &&
        (v[13] >= '\x30') && (v[13] <= '\x39')) {
        s = (v[12] - '\x30') * 10 + (v[13] - '\x30');
        /* Check for fractions of seconds. */
        if (tm->length >= 15 && v[14] == '\x2e') {
            int l = tm->length;
            f = &v[14];         /* The decimal point. */
            f_len = 1;
            while (14 + f_len < l && f[f_len] >= '\x30' && f[f_len] <= '\x39')
                ++f_len;
        }
    }

    if (BIO_printf(bp, "\x25\x73\x20\x25\x32\x64\x20\x25\x30\x32\x64\x3a\x25\x30\x32\x64\x3a\x25\x30\x32\x64\x25\x2e\x2a\x73\x20\x25\x64\x25\x73",
                   mon[M - 1], d, h, m, s, f_len, f, y,
                   (gmt) ? "\x20\x47\x4d\x54" : "") <= 0)
        return (0);
    else
        return (1);
 err:
    BIO_write(bp, "\x42\x61\x64\x20\x74\x69\x6d\x65\x20\x76\x61\x6c\x75\x65", 14);
    return (0);
}

int ASN1_UTCTIME_print(BIO *bp, const ASN1_UTCTIME *tm)
{
    const char *v;
    int gmt = 0;
    int i;
    int y = 0, M = 0, d = 0, h = 0, m = 0, s = 0;

    i = tm->length;
    v = (const char *)tm->data;

    if (i < 10)
        goto err;
    if (v[i - 1] == '\x5a')
        gmt = 1;
    for (i = 0; i < 10; i++)
        if ((v[i] > '\x39') || (v[i] < '\x30'))
            goto err;
    y = (v[0] - '\x30') * 10 + (v[1] - '\x30');
    if (y < 50)
        y += 100;
    M = (v[2] - '\x30') * 10 + (v[3] - '\x30');
    if ((M > 12) || (M < 1))
        goto err;
    d = (v[4] - '\x30') * 10 + (v[5] - '\x30');
    h = (v[6] - '\x30') * 10 + (v[7] - '\x30');
    m = (v[8] - '\x30') * 10 + (v[9] - '\x30');
    if (tm->length >= 12 &&
        (v[10] >= '\x30') && (v[10] <= '\x39') && (v[11] >= '\x30') && (v[11] <= '\x39'))
        s = (v[10] - '\x30') * 10 + (v[11] - '\x30');

    if (BIO_printf(bp, "\x25\x73\x20\x25\x32\x64\x20\x25\x30\x32\x64\x3a\x25\x30\x32\x64\x3a\x25\x30\x32\x64\x20\x25\x64\x25\x73",
                   mon[M - 1], d, h, m, s, y + 1900,
                   (gmt) ? "\x20\x47\x4d\x54" : "") <= 0)
        return (0);
    else
        return (1);
 err:
    BIO_write(bp, "\x42\x61\x64\x20\x74\x69\x6d\x65\x20\x76\x61\x6c\x75\x65", 14);
    return (0);
}

int X509_NAME_print(BIO *bp, X509_NAME *name, int obase)
{
    char *s, *c, *b;
    int ret = 0, l, i;

    l = 80 - 2 - obase;

    b = X509_NAME_oneline(name, NULL, 0);
    if (!b)
        return 0;
    if (!*b) {
        OPENSSL_free(b);
        return 1;
    }
    s = b + 1;                  /* skip the first slash */

    c = s;
    for (;;) {
#ifndef CHARSET_EBCDIC
        if (((*s == '\x2f') &&
             ((s[1] >= '\x41') && (s[1] <= '\x5a') && ((s[2] == '\x3d') ||
                                                 ((s[2] >= '\x41')
                                                  && (s[2] <= '\x5a')
                                                  && (s[3] == '\x3d'))
              ))) || (*s == '\x0'))
#else
        if (((*s == '\x2f') &&
             (isupper(s[1]) && ((s[2] == '\x3d') ||
                                (isupper(s[2]) && (s[3] == '\x3d'))
              ))) || (*s == '\x0'))
#endif
        {
            i = s - c;
            if (BIO_write(bp, c, i) != i)
                goto err;
            c = s + 1;          /* skip following slash */
            if (*s != '\x0') {
                if (BIO_write(bp, "\x2c\x20", 2) != 2)
                    goto err;
            }
            l--;
        }
        if (*s == '\x0')
            break;
        s++;
        l--;
    }

    ret = 1;
    if (0) {
 err:
        X509err(X509_F_X509_NAME_PRINT, ERR_R_BUF_LIB);
    }
    OPENSSL_free(b);
    return (ret);
}
