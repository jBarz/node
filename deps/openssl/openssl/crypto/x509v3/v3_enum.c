/* v3_enum.c */
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
#include <openssl/x509v3.h>

static ENUMERATED_NAMES crl_reasons[] = {
    {CRL_REASON_UNSPECIFIED, "\x55\x6e\x73\x70\x65\x63\x69\x66\x69\x65\x64", "\x75\x6e\x73\x70\x65\x63\x69\x66\x69\x65\x64"},
    {CRL_REASON_KEY_COMPROMISE, "\x4b\x65\x79\x20\x43\x6f\x6d\x70\x72\x6f\x6d\x69\x73\x65", "\x6b\x65\x79\x43\x6f\x6d\x70\x72\x6f\x6d\x69\x73\x65"},
    {CRL_REASON_CA_COMPROMISE, "\x43\x41\x20\x43\x6f\x6d\x70\x72\x6f\x6d\x69\x73\x65", "\x43\x41\x43\x6f\x6d\x70\x72\x6f\x6d\x69\x73\x65"},
    {CRL_REASON_AFFILIATION_CHANGED, "\x41\x66\x66\x69\x6c\x69\x61\x74\x69\x6f\x6e\x20\x43\x68\x61\x6e\x67\x65\x64",
     "\x61\x66\x66\x69\x6c\x69\x61\x74\x69\x6f\x6e\x43\x68\x61\x6e\x67\x65\x64"},
    {CRL_REASON_SUPERSEDED, "\x53\x75\x70\x65\x72\x73\x65\x64\x65\x64", "\x73\x75\x70\x65\x72\x73\x65\x64\x65\x64"},
    {CRL_REASON_CESSATION_OF_OPERATION,
     "\x43\x65\x73\x73\x61\x74\x69\x6f\x6e\x20\x4f\x66\x20\x4f\x70\x65\x72\x61\x74\x69\x6f\x6e", "\x63\x65\x73\x73\x61\x74\x69\x6f\x6e\x4f\x66\x4f\x70\x65\x72\x61\x74\x69\x6f\x6e"},
    {CRL_REASON_CERTIFICATE_HOLD, "\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x48\x6f\x6c\x64", "\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x48\x6f\x6c\x64"},
    {CRL_REASON_REMOVE_FROM_CRL, "\x52\x65\x6d\x6f\x76\x65\x20\x46\x72\x6f\x6d\x20\x43\x52\x4c", "\x72\x65\x6d\x6f\x76\x65\x46\x72\x6f\x6d\x43\x52\x4c"},
    {CRL_REASON_PRIVILEGE_WITHDRAWN, "\x50\x72\x69\x76\x69\x6c\x65\x67\x65\x20\x57\x69\x74\x68\x64\x72\x61\x77\x6e",
     "\x70\x72\x69\x76\x69\x6c\x65\x67\x65\x57\x69\x74\x68\x64\x72\x61\x77\x6e"},
    {CRL_REASON_AA_COMPROMISE, "\x41\x41\x20\x43\x6f\x6d\x70\x72\x6f\x6d\x69\x73\x65", "\x41\x41\x43\x6f\x6d\x70\x72\x6f\x6d\x69\x73\x65"},
    {-1, NULL, NULL}
};

const X509V3_EXT_METHOD v3_crl_reason = {
    NID_crl_reason, 0, ASN1_ITEM_ref(ASN1_ENUMERATED),
    0, 0, 0, 0,
    (X509V3_EXT_I2S)i2s_ASN1_ENUMERATED_TABLE,
    0,
    0, 0, 0, 0,
    crl_reasons
};

char *i2s_ASN1_ENUMERATED_TABLE(X509V3_EXT_METHOD *method, ASN1_ENUMERATED *e)
{
    ENUMERATED_NAMES *enam;
    long strval;
    strval = ASN1_ENUMERATED_get(e);
    for (enam = method->usr_data; enam->lname; enam++) {
        if (strval == enam->bitnum)
            return BUF_strdup(enam->lname);
    }
    return i2s_ASN1_ENUMERATED(method, e);
}
