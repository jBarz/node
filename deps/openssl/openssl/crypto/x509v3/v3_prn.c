/* v3_prn.c */
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
/* X509 v3 extension utilities */

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/conf.h>
#include <openssl/x509v3.h>

/* Extension printing routines */

static int unknown_ext_print(BIO *out, X509_EXTENSION *ext,
                             unsigned long flag, int indent, int supported);

/* Print out a name+value stack */

void X509V3_EXT_val_prn(BIO *out, STACK_OF(CONF_VALUE) *val, int indent,
                        int ml)
{
    int i;
    CONF_VALUE *nval;
    if (!val)
        return;
    if (!ml || !sk_CONF_VALUE_num(val)) {
        BIO_printf(out, "\x25\x2a\x73", indent, "");
        if (!sk_CONF_VALUE_num(val))
            BIO_puts(out, "\x3c\x45\x4d\x50\x54\x59\x3e\xa");
    }
    for (i = 0; i < sk_CONF_VALUE_num(val); i++) {
        if (ml)
            BIO_printf(out, "\x25\x2a\x73", indent, "");
        else if (i > 0)
            BIO_printf(out, "\x2c\x20");
        nval = sk_CONF_VALUE_value(val, i);
        if (!nval->name)
            BIO_puts(out, nval->value);
        else if (!nval->value)
            BIO_puts(out, nval->name);
#ifndef CHARSET_EBCDIC
        else
            BIO_printf(out, "\x25\x73\x3a\x25\x73", nval->name, nval->value);
#else
        else {
            int len;
            char *tmp;
            len = strlen(nval->value) + 1;
            tmp = OPENSSL_malloc(len);
            if (tmp) {
                ascii2ebcdic(tmp, nval->value, len);
                BIO_printf(out, "\x25\x73\x3a\x25\x73", nval->name, tmp);
                OPENSSL_free(tmp);
            }
        }
#endif
        if (ml)
            BIO_puts(out, "\xa");
    }
}

/* Main routine: print out a general extension */

int X509V3_EXT_print(BIO *out, X509_EXTENSION *ext, unsigned long flag,
                     int indent)
{
    void *ext_str = NULL;
    char *value = NULL;
    const unsigned char *p;
    const X509V3_EXT_METHOD *method;
    STACK_OF(CONF_VALUE) *nval = NULL;
    int ok = 1;

    if (!(method = X509V3_EXT_get(ext)))
        return unknown_ext_print(out, ext, flag, indent, 0);
    p = ext->value->data;
    if (method->it)
        ext_str =
            ASN1_item_d2i(NULL, &p, ext->value->length,
                          ASN1_ITEM_ptr(method->it));
    else
        ext_str = method->d2i(NULL, &p, ext->value->length);

    if (!ext_str)
        return unknown_ext_print(out, ext, flag, indent, 1);

    if (method->i2s) {
        if (!(value = method->i2s(method, ext_str))) {
            ok = 0;
            goto err;
        }
#ifndef CHARSET_EBCDIC
        BIO_printf(out, "\x25\x2a\x73\x25\x73", indent, "", value);
#else
        {
            int len;
            char *tmp;
            len = strlen(value) + 1;
            tmp = OPENSSL_malloc(len);
            if (tmp) {
                ascii2ebcdic(tmp, value, len);
                BIO_printf(out, "\x25\x2a\x73\x25\x73", indent, "", tmp);
                OPENSSL_free(tmp);
            }
        }
#endif
    } else if (method->i2v) {
        if (!(nval = method->i2v(method, ext_str, NULL))) {
            ok = 0;
            goto err;
        }
        X509V3_EXT_val_prn(out, nval, indent,
                           method->ext_flags & X509V3_EXT_MULTILINE);
    } else if (method->i2r) {
        if (!method->i2r(method, ext_str, out, indent))
            ok = 0;
    } else
        ok = 0;

 err:
    sk_CONF_VALUE_pop_free(nval, X509V3_conf_free);
    if (value)
        OPENSSL_free(value);
    if (method->it)
        ASN1_item_free(ext_str, ASN1_ITEM_ptr(method->it));
    else
        method->ext_free(ext_str);
    return ok;
}

int X509V3_extensions_print(BIO *bp, char *title,
                            STACK_OF(X509_EXTENSION) *exts,
                            unsigned long flag, int indent)
{
    int i, j;

    if (sk_X509_EXTENSION_num(exts) <= 0)
        return 1;

    if (title) {
        BIO_printf(bp, "\x25\x2a\x73\x25\x73\x3a\xa", indent, "", title);
        indent += 4;
    }

    for (i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
        ASN1_OBJECT *obj;
        X509_EXTENSION *ex;
        ex = sk_X509_EXTENSION_value(exts, i);
        if (indent && BIO_printf(bp, "\x25\x2a\x73", indent, "") <= 0)
            return 0;
        obj = X509_EXTENSION_get_object(ex);
        i2a_ASN1_OBJECT(bp, obj);
        j = X509_EXTENSION_get_critical(ex);
        if (BIO_printf(bp, "\x3a\x20\x25\x73\xa", j ? "\x63\x72\x69\x74\x69\x63\x61\x6c" : "") <= 0)
            return 0;
        if (!X509V3_EXT_print(bp, ex, flag, indent + 4)) {
            BIO_printf(bp, "\x25\x2a\x73", indent + 4, "");
            M_ASN1_OCTET_STRING_print(bp, ex->value);
        }
        if (BIO_write(bp, "\xa", 1) <= 0)
            return 0;
    }
    return 1;
}

static int unknown_ext_print(BIO *out, X509_EXTENSION *ext,
                             unsigned long flag, int indent, int supported)
{
    switch (flag & X509V3_EXT_UNKNOWN_MASK) {

    case X509V3_EXT_DEFAULT:
        return 0;

    case X509V3_EXT_ERROR_UNKNOWN:
        if (supported)
            BIO_printf(out, "\x25\x2a\x73\x3c\x50\x61\x72\x73\x65\x20\x45\x72\x72\x6f\x72\x3e", indent, "");
        else
            BIO_printf(out, "\x25\x2a\x73\x3c\x4e\x6f\x74\x20\x53\x75\x70\x70\x6f\x72\x74\x65\x64\x3e", indent, "");
        return 1;

    case X509V3_EXT_PARSE_UNKNOWN:
        return ASN1_parse_dump(out,
                               ext->value->data, ext->value->length, indent,
                               -1);
    case X509V3_EXT_DUMP_UNKNOWN:
        return BIO_dump_indent(out, (char *)ext->value->data,
                               ext->value->length, indent);

    default:
        return 1;
    }
}

#ifndef OPENSSL_NO_FP_API
int X509V3_EXT_print_fp(FILE *fp, X509_EXTENSION *ext, int flag, int indent)
{
    BIO *bio_tmp;
    int ret;
    if (!(bio_tmp = BIO_new_fp(fp, BIO_NOCLOSE)))
        return 0;
    ret = X509V3_EXT_print(bio_tmp, ext, flag, indent);
    BIO_free(bio_tmp);
    return ret;
}
#endif
