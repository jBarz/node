/* ocsp_prn.c */
/*
 * Written by Tom Titchener <Tom_Titchener@groove.net> for the OpenSSL
 * project.
 */

/*
 * History: This file was originally part of ocsp.c and was transfered to
 * Richard Levitte from CertCo by Kathy Weinhold in mid-spring 2000 to be
 * included in OpenSSL or released as a patch kit.
 */

/* ====================================================================
 * Copyright (c) 1998-2000 The OpenSSL Project.  All rights reserved.
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
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
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

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>

static int ocsp_certid_print(BIO *bp, OCSP_CERTID *a, int indent)
{
    BIO_printf(bp, "\x25\x2a\x73\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x49\x44\x3a\xa", indent, "");
    indent += 2;
    BIO_printf(bp, "\x25\x2a\x73\x48\x61\x73\x68\x20\x41\x6c\x67\x6f\x72\x69\x74\x68\x6d\x3a\x20", indent, "");
    i2a_ASN1_OBJECT(bp, a->hashAlgorithm->algorithm);
    BIO_printf(bp, "\xa\x25\x2a\x73\x49\x73\x73\x75\x65\x72\x20\x4e\x61\x6d\x65\x20\x48\x61\x73\x68\x3a\x20", indent, "");
    i2a_ASN1_STRING(bp, a->issuerNameHash, V_ASN1_OCTET_STRING);
    BIO_printf(bp, "\xa\x25\x2a\x73\x49\x73\x73\x75\x65\x72\x20\x4b\x65\x79\x20\x48\x61\x73\x68\x3a\x20", indent, "");
    i2a_ASN1_STRING(bp, a->issuerKeyHash, V_ASN1_OCTET_STRING);
    BIO_printf(bp, "\xa\x25\x2a\x73\x53\x65\x72\x69\x61\x6c\x20\x4e\x75\x6d\x62\x65\x72\x3a\x20", indent, "");
    i2a_ASN1_INTEGER(bp, a->serialNumber);
    BIO_printf(bp, "\xa");
    return 1;
}

typedef struct {
    long t;
    const char *m;
} OCSP_TBLSTR;

static const char *table2string(long s, const OCSP_TBLSTR *ts, int len)
{
    const OCSP_TBLSTR *p;
    for (p = ts; p < ts + len; p++)
        if (p->t == s)
            return p->m;
    return "\x28\x55\x4e\x4b\x4e\x4f\x57\x4e\x29";
}

const char *OCSP_response_status_str(long s)
{
    static const OCSP_TBLSTR rstat_tbl[] = {
        {OCSP_RESPONSE_STATUS_SUCCESSFUL, "\x73\x75\x63\x63\x65\x73\x73\x66\x75\x6c"},
        {OCSP_RESPONSE_STATUS_MALFORMEDREQUEST, "\x6d\x61\x6c\x66\x6f\x72\x6d\x65\x64\x72\x65\x71\x75\x65\x73\x74"},
        {OCSP_RESPONSE_STATUS_INTERNALERROR, "\x69\x6e\x74\x65\x72\x6e\x61\x6c\x65\x72\x72\x6f\x72"},
        {OCSP_RESPONSE_STATUS_TRYLATER, "\x74\x72\x79\x6c\x61\x74\x65\x72"},
        {OCSP_RESPONSE_STATUS_SIGREQUIRED, "\x73\x69\x67\x72\x65\x71\x75\x69\x72\x65\x64"},
        {OCSP_RESPONSE_STATUS_UNAUTHORIZED, "\x75\x6e\x61\x75\x74\x68\x6f\x72\x69\x7a\x65\x64"}
    };
    return table2string(s, rstat_tbl, 6);
}

const char *OCSP_cert_status_str(long s)
{
    static const OCSP_TBLSTR cstat_tbl[] = {
        {V_OCSP_CERTSTATUS_GOOD, "\x67\x6f\x6f\x64"},
        {V_OCSP_CERTSTATUS_REVOKED, "\x72\x65\x76\x6f\x6b\x65\x64"},
        {V_OCSP_CERTSTATUS_UNKNOWN, "\x75\x6e\x6b\x6e\x6f\x77\x6e"}
    };
    return table2string(s, cstat_tbl, 3);
}

const char *OCSP_crl_reason_str(long s)
{
    static const OCSP_TBLSTR reason_tbl[] = {
        {OCSP_REVOKED_STATUS_UNSPECIFIED, "\x75\x6e\x73\x70\x65\x63\x69\x66\x69\x65\x64"},
        {OCSP_REVOKED_STATUS_KEYCOMPROMISE, "\x6b\x65\x79\x43\x6f\x6d\x70\x72\x6f\x6d\x69\x73\x65"},
        {OCSP_REVOKED_STATUS_CACOMPROMISE, "\x63\x41\x43\x6f\x6d\x70\x72\x6f\x6d\x69\x73\x65"},
        {OCSP_REVOKED_STATUS_AFFILIATIONCHANGED, "\x61\x66\x66\x69\x6c\x69\x61\x74\x69\x6f\x6e\x43\x68\x61\x6e\x67\x65\x64"},
        {OCSP_REVOKED_STATUS_SUPERSEDED, "\x73\x75\x70\x65\x72\x73\x65\x64\x65\x64"},
        {OCSP_REVOKED_STATUS_CESSATIONOFOPERATION, "\x63\x65\x73\x73\x61\x74\x69\x6f\x6e\x4f\x66\x4f\x70\x65\x72\x61\x74\x69\x6f\x6e"},
        {OCSP_REVOKED_STATUS_CERTIFICATEHOLD, "\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x48\x6f\x6c\x64"},
        {OCSP_REVOKED_STATUS_REMOVEFROMCRL, "\x72\x65\x6d\x6f\x76\x65\x46\x72\x6f\x6d\x43\x52\x4c"}
    };
    return table2string(s, reason_tbl, 8);
}

int OCSP_REQUEST_print(BIO *bp, OCSP_REQUEST *o, unsigned long flags)
{
    int i;
    long l;
    OCSP_CERTID *cid = NULL;
    OCSP_ONEREQ *one = NULL;
    OCSP_REQINFO *inf = o->tbsRequest;
    OCSP_SIGNATURE *sig = o->optionalSignature;

    if (BIO_write(bp, "\x4f\x43\x53\x50\x20\x52\x65\x71\x75\x65\x73\x74\x20\x44\x61\x74\x61\x3a\xa", 19) <= 0)
        goto err;
    l = ASN1_INTEGER_get(inf->version);
    if (BIO_printf(bp, "\x20\x20\x20\x20\x56\x65\x72\x73\x69\x6f\x6e\x3a\x20\x25\x6c\x75\x20\x28\x30\x78\x25\x6c\x78\x29", l + 1, l) <= 0)
        goto err;
    if (inf->requestorName != NULL) {
        if (BIO_write(bp, "\xa\x20\x20\x20\x20\x52\x65\x71\x75\x65\x73\x74\x6f\x72\x20\x4e\x61\x6d\x65\x3a\x20", 21) <= 0)
            goto err;
        GENERAL_NAME_print(bp, inf->requestorName);
    }
    if (BIO_write(bp, "\xa\x20\x20\x20\x20\x52\x65\x71\x75\x65\x73\x74\x6f\x72\x20\x4c\x69\x73\x74\x3a\xa", 21) <= 0)
        goto err;
    for (i = 0; i < sk_OCSP_ONEREQ_num(inf->requestList); i++) {
        one = sk_OCSP_ONEREQ_value(inf->requestList, i);
        cid = one->reqCert;
        ocsp_certid_print(bp, cid, 8);
        if (!X509V3_extensions_print(bp,
                                     "\x52\x65\x71\x75\x65\x73\x74\x20\x53\x69\x6e\x67\x6c\x65\x20\x45\x78\x74\x65\x6e\x73\x69\x6f\x6e\x73",
                                     one->singleRequestExtensions, flags, 8))
            goto err;
    }
    if (!X509V3_extensions_print(bp, "\x52\x65\x71\x75\x65\x73\x74\x20\x45\x78\x74\x65\x6e\x73\x69\x6f\x6e\x73",
                                 inf->requestExtensions, flags, 4))
        goto err;
    if (sig) {
        X509_signature_print(bp, sig->signatureAlgorithm, sig->signature);
        for (i = 0; i < sk_X509_num(sig->certs); i++) {
            X509_print(bp, sk_X509_value(sig->certs, i));
            PEM_write_bio_X509(bp, sk_X509_value(sig->certs, i));
        }
    }
    return 1;
 err:
    return 0;
}

int OCSP_RESPONSE_print(BIO *bp, OCSP_RESPONSE *o, unsigned long flags)
{
    int i, ret = 0;
    long l;
    OCSP_CERTID *cid = NULL;
    OCSP_BASICRESP *br = NULL;
    OCSP_RESPID *rid = NULL;
    OCSP_RESPDATA *rd = NULL;
    OCSP_CERTSTATUS *cst = NULL;
    OCSP_REVOKEDINFO *rev = NULL;
    OCSP_SINGLERESP *single = NULL;
    OCSP_RESPBYTES *rb = o->responseBytes;

    if (BIO_puts(bp, "\x4f\x43\x53\x50\x20\x52\x65\x73\x70\x6f\x6e\x73\x65\x20\x44\x61\x74\x61\x3a\xa") <= 0)
        goto err;
    l = ASN1_ENUMERATED_get(o->responseStatus);
    if (BIO_printf(bp, "\x20\x20\x20\x20\x4f\x43\x53\x50\x20\x52\x65\x73\x70\x6f\x6e\x73\x65\x20\x53\x74\x61\x74\x75\x73\x3a\x20\x25\x73\x20\x28\x30\x78\x25\x6c\x78\x29\xa",
                   OCSP_response_status_str(l), l) <= 0)
        goto err;
    if (rb == NULL)
        return 1;
    if (BIO_puts(bp, "\x20\x20\x20\x20\x52\x65\x73\x70\x6f\x6e\x73\x65\x20\x54\x79\x70\x65\x3a\x20") <= 0)
        goto err;
    if (i2a_ASN1_OBJECT(bp, rb->responseType) <= 0)
        goto err;
    if (OBJ_obj2nid(rb->responseType) != NID_id_pkix_OCSP_basic) {
        BIO_puts(bp, "\x20\x28\x75\x6e\x6b\x6e\x6f\x77\x6e\x20\x72\x65\x73\x70\x6f\x6e\x73\x65\x20\x74\x79\x70\x65\x29\xa");
        return 1;
    }

    if ((br = OCSP_response_get1_basic(o)) == NULL)
        goto err;
    rd = br->tbsResponseData;
    l = ASN1_INTEGER_get(rd->version);
    if (BIO_printf(bp, "\xa\x20\x20\x20\x20\x56\x65\x72\x73\x69\x6f\x6e\x3a\x20\x25\x6c\x75\x20\x28\x30\x78\x25\x6c\x78\x29\xa", l + 1, l) <= 0)
        goto err;
    if (BIO_puts(bp, "\x20\x20\x20\x20\x52\x65\x73\x70\x6f\x6e\x64\x65\x72\x20\x49\x64\x3a\x20") <= 0)
        goto err;

    rid = rd->responderId;
    switch (rid->type) {
    case V_OCSP_RESPID_NAME:
        X509_NAME_print_ex(bp, rid->value.byName, 0, XN_FLAG_ONELINE);
        break;
    case V_OCSP_RESPID_KEY:
        i2a_ASN1_STRING(bp, rid->value.byKey, V_ASN1_OCTET_STRING);
        break;
    }

    if (BIO_printf(bp, "\xa\x20\x20\x20\x20\x50\x72\x6f\x64\x75\x63\x65\x64\x20\x41\x74\x3a\x20") <= 0)
        goto err;
    if (!ASN1_GENERALIZEDTIME_print(bp, rd->producedAt))
        goto err;
    if (BIO_printf(bp, "\xa\x20\x20\x20\x20\x52\x65\x73\x70\x6f\x6e\x73\x65\x73\x3a\xa") <= 0)
        goto err;
    for (i = 0; i < sk_OCSP_SINGLERESP_num(rd->responses); i++) {
        if (!sk_OCSP_SINGLERESP_value(rd->responses, i))
            continue;
        single = sk_OCSP_SINGLERESP_value(rd->responses, i);
        cid = single->certId;
        if (ocsp_certid_print(bp, cid, 4) <= 0)
            goto err;
        cst = single->certStatus;
        if (BIO_printf(bp, "\x20\x20\x20\x20\x43\x65\x72\x74\x20\x53\x74\x61\x74\x75\x73\x3a\x20\x25\x73",
                       OCSP_cert_status_str(cst->type)) <= 0)
            goto err;
        if (cst->type == V_OCSP_CERTSTATUS_REVOKED) {
            rev = cst->value.revoked;
            if (BIO_printf(bp, "\xa\x20\x20\x20\x20\x52\x65\x76\x6f\x63\x61\x74\x69\x6f\x6e\x20\x54\x69\x6d\x65\x3a\x20") <= 0)
                goto err;
            if (!ASN1_GENERALIZEDTIME_print(bp, rev->revocationTime))
                goto err;
            if (rev->revocationReason) {
                l = ASN1_ENUMERATED_get(rev->revocationReason);
                if (BIO_printf(bp,
                               "\xa\x20\x20\x20\x20\x52\x65\x76\x6f\x63\x61\x74\x69\x6f\x6e\x20\x52\x65\x61\x73\x6f\x6e\x3a\x20\x25\x73\x20\x28\x30\x78\x25\x6c\x78\x29",
                               OCSP_crl_reason_str(l), l) <= 0)
                    goto err;
            }
        }
        if (BIO_printf(bp, "\xa\x20\x20\x20\x20\x54\x68\x69\x73\x20\x55\x70\x64\x61\x74\x65\x3a\x20") <= 0)
            goto err;
        if (!ASN1_GENERALIZEDTIME_print(bp, single->thisUpdate))
            goto err;
        if (single->nextUpdate) {
            if (BIO_printf(bp, "\xa\x20\x20\x20\x20\x4e\x65\x78\x74\x20\x55\x70\x64\x61\x74\x65\x3a\x20") <= 0)
                goto err;
            if (!ASN1_GENERALIZEDTIME_print(bp, single->nextUpdate))
                goto err;
        }
        if (BIO_write(bp, "\xa", 1) <= 0)
            goto err;
        if (!X509V3_extensions_print(bp,
                                     "\x52\x65\x73\x70\x6f\x6e\x73\x65\x20\x53\x69\x6e\x67\x6c\x65\x20\x45\x78\x74\x65\x6e\x73\x69\x6f\x6e\x73",
                                     single->singleExtensions, flags, 8))
            goto err;
        if (BIO_write(bp, "\xa", 1) <= 0)
            goto err;
    }
    if (!X509V3_extensions_print(bp, "\x52\x65\x73\x70\x6f\x6e\x73\x65\x20\x45\x78\x74\x65\x6e\x73\x69\x6f\x6e\x73",
                                 rd->responseExtensions, flags, 4))
        goto err;
    if (X509_signature_print(bp, br->signatureAlgorithm, br->signature) <= 0)
        goto err;

    for (i = 0; i < sk_X509_num(br->certs); i++) {
        X509_print(bp, sk_X509_value(br->certs, i));
        PEM_write_bio_X509(bp, sk_X509_value(br->certs, i));
    }

    ret = 1;
 err:
    OCSP_BASICRESP_free(br);
    return ret;
}
