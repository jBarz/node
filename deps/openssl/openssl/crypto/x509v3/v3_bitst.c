/* v3_bitst.c */
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
#include <openssl/conf.h>
#include <openssl/x509v3.h>

static BIT_STRING_BITNAME ns_cert_type_table[] = {
    {0, "\x53\x53\x4c\x20\x43\x6c\x69\x65\x6e\x74", "\x63\x6c\x69\x65\x6e\x74"},
    {1, "\x53\x53\x4c\x20\x53\x65\x72\x76\x65\x72", "\x73\x65\x72\x76\x65\x72"},
    {2, "\x53\x2f\x4d\x49\x4d\x45", "\x65\x6d\x61\x69\x6c"},
    {3, "\x4f\x62\x6a\x65\x63\x74\x20\x53\x69\x67\x6e\x69\x6e\x67", "\x6f\x62\x6a\x73\x69\x67\x6e"},
    {4, "\x55\x6e\x75\x73\x65\x64", "\x72\x65\x73\x65\x72\x76\x65\x64"},
    {5, "\x53\x53\x4c\x20\x43\x41", "\x73\x73\x6c\x43\x41"},
    {6, "\x53\x2f\x4d\x49\x4d\x45\x20\x43\x41", "\x65\x6d\x61\x69\x6c\x43\x41"},
    {7, "\x4f\x62\x6a\x65\x63\x74\x20\x53\x69\x67\x6e\x69\x6e\x67\x20\x43\x41", "\x6f\x62\x6a\x43\x41"},
    {-1, NULL, NULL}
};

static BIT_STRING_BITNAME key_usage_type_table[] = {
    {0, "\x44\x69\x67\x69\x74\x61\x6c\x20\x53\x69\x67\x6e\x61\x74\x75\x72\x65", "\x64\x69\x67\x69\x74\x61\x6c\x53\x69\x67\x6e\x61\x74\x75\x72\x65"},
    {1, "\x4e\x6f\x6e\x20\x52\x65\x70\x75\x64\x69\x61\x74\x69\x6f\x6e", "\x6e\x6f\x6e\x52\x65\x70\x75\x64\x69\x61\x74\x69\x6f\x6e"},
    {2, "\x4b\x65\x79\x20\x45\x6e\x63\x69\x70\x68\x65\x72\x6d\x65\x6e\x74", "\x6b\x65\x79\x45\x6e\x63\x69\x70\x68\x65\x72\x6d\x65\x6e\x74"},
    {3, "\x44\x61\x74\x61\x20\x45\x6e\x63\x69\x70\x68\x65\x72\x6d\x65\x6e\x74", "\x64\x61\x74\x61\x45\x6e\x63\x69\x70\x68\x65\x72\x6d\x65\x6e\x74"},
    {4, "\x4b\x65\x79\x20\x41\x67\x72\x65\x65\x6d\x65\x6e\x74", "\x6b\x65\x79\x41\x67\x72\x65\x65\x6d\x65\x6e\x74"},
    {5, "\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x53\x69\x67\x6e", "\x6b\x65\x79\x43\x65\x72\x74\x53\x69\x67\x6e"},
    {6, "\x43\x52\x4c\x20\x53\x69\x67\x6e", "\x63\x52\x4c\x53\x69\x67\x6e"},
    {7, "\x45\x6e\x63\x69\x70\x68\x65\x72\x20\x4f\x6e\x6c\x79", "\x65\x6e\x63\x69\x70\x68\x65\x72\x4f\x6e\x6c\x79"},
    {8, "\x44\x65\x63\x69\x70\x68\x65\x72\x20\x4f\x6e\x6c\x79", "\x64\x65\x63\x69\x70\x68\x65\x72\x4f\x6e\x6c\x79"},
    {-1, NULL, NULL}
};

const X509V3_EXT_METHOD v3_nscert =
EXT_BITSTRING(NID_netscape_cert_type, ns_cert_type_table);
const X509V3_EXT_METHOD v3_key_usage =
EXT_BITSTRING(NID_key_usage, key_usage_type_table);

STACK_OF(CONF_VALUE) *i2v_ASN1_BIT_STRING(X509V3_EXT_METHOD *method,
                                          ASN1_BIT_STRING *bits,
                                          STACK_OF(CONF_VALUE) *ret)
{
    BIT_STRING_BITNAME *bnam;
    for (bnam = method->usr_data; bnam->lname; bnam++) {
        if (ASN1_BIT_STRING_get_bit(bits, bnam->bitnum))
            X509V3_add_value(bnam->lname, NULL, &ret);
    }
    return ret;
}

ASN1_BIT_STRING *v2i_ASN1_BIT_STRING(X509V3_EXT_METHOD *method,
                                     X509V3_CTX *ctx,
                                     STACK_OF(CONF_VALUE) *nval)
{
    CONF_VALUE *val;
    ASN1_BIT_STRING *bs;
    int i;
    BIT_STRING_BITNAME *bnam;
    if (!(bs = M_ASN1_BIT_STRING_new())) {
        X509V3err(X509V3_F_V2I_ASN1_BIT_STRING, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    for (i = 0; i < sk_CONF_VALUE_num(nval); i++) {
        val = sk_CONF_VALUE_value(nval, i);
        for (bnam = method->usr_data; bnam->lname; bnam++) {
            if (!strcmp(bnam->sname, val->name) ||
                !strcmp(bnam->lname, val->name)) {
                if (!ASN1_BIT_STRING_set_bit(bs, bnam->bitnum, 1)) {
                    X509V3err(X509V3_F_V2I_ASN1_BIT_STRING,
                              ERR_R_MALLOC_FAILURE);
                    M_ASN1_BIT_STRING_free(bs);
                    return NULL;
                }
                break;
            }
        }
        if (!bnam->lname) {
            X509V3err(X509V3_F_V2I_ASN1_BIT_STRING,
                      X509V3_R_UNKNOWN_BIT_STRING_ARGUMENT);
            X509V3_conf_err(val);
            M_ASN1_BIT_STRING_free(bs);
            return NULL;
        }
    }
    return bs;
}
