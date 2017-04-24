/* crypto/ts/ts_resp_print.c */
/*
 * Written by Zoltan Glozik (zglozik@stones.com) for the OpenSSL project
 * 2002.
 */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
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
#include <openssl/objects.h>
#include <openssl/bn.h>
#include <openssl/x509v3.h>
#include "ts.h"

struct status_map_st {
    int bit;
    const char *text;
};

/* Local function declarations. */

static int TS_status_map_print(BIO *bio, struct status_map_st *a,
                               ASN1_BIT_STRING *v);
static int TS_ACCURACY_print_bio(BIO *bio, const TS_ACCURACY *accuracy);

/* Function definitions. */

int TS_RESP_print_bio(BIO *bio, TS_RESP *a)
{
    TS_TST_INFO *tst_info;

    BIO_printf(bio, "\x53\x74\x61\x74\x75\x73\x20\x69\x6e\x66\x6f\x3a\xa");
    TS_STATUS_INFO_print_bio(bio, TS_RESP_get_status_info(a));

    BIO_printf(bio, "\xa\x54\x53\x54\x20\x69\x6e\x66\x6f\x3a\xa");
    tst_info = TS_RESP_get_tst_info(a);
    if (tst_info != NULL)
        TS_TST_INFO_print_bio(bio, TS_RESP_get_tst_info(a));
    else
        BIO_printf(bio, "\x4e\x6f\x74\x20\x69\x6e\x63\x6c\x75\x64\x65\x64\x2e\xa");

    return 1;
}

int TS_STATUS_INFO_print_bio(BIO *bio, TS_STATUS_INFO *a)
{
    static const char *status_map[] = {
        "\x47\x72\x61\x6e\x74\x65\x64\x2e",
        "\x47\x72\x61\x6e\x74\x65\x64\x20\x77\x69\x74\x68\x20\x6d\x6f\x64\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x73\x2e",
        "\x52\x65\x6a\x65\x63\x74\x65\x64\x2e",
        "\x57\x61\x69\x74\x69\x6e\x67\x2e",
        "\x52\x65\x76\x6f\x63\x61\x74\x69\x6f\x6e\x20\x77\x61\x72\x6e\x69\x6e\x67\x2e",
        "\x52\x65\x76\x6f\x6b\x65\x64\x2e"
    };
    static struct status_map_st failure_map[] = {
        {TS_INFO_BAD_ALG,
         "\x75\x6e\x72\x65\x63\x6f\x67\x6e\x69\x7a\x65\x64\x20\x6f\x72\x20\x75\x6e\x73\x75\x70\x70\x6f\x72\x74\x65\x64\x20\x61\x6c\x67\x6f\x72\x69\x74\x68\x6d\x20\x69\x64\x65\x6e\x74\x69\x66\x69\x65\x72"},
        {TS_INFO_BAD_REQUEST,
         "\x74\x72\x61\x6e\x73\x61\x63\x74\x69\x6f\x6e\x20\x6e\x6f\x74\x20\x70\x65\x72\x6d\x69\x74\x74\x65\x64\x20\x6f\x72\x20\x73\x75\x70\x70\x6f\x72\x74\x65\x64"},
        {TS_INFO_BAD_DATA_FORMAT,
         "\x74\x68\x65\x20\x64\x61\x74\x61\x20\x73\x75\x62\x6d\x69\x74\x74\x65\x64\x20\x68\x61\x73\x20\x74\x68\x65\x20\x77\x72\x6f\x6e\x67\x20\x66\x6f\x72\x6d\x61\x74"},
        {TS_INFO_TIME_NOT_AVAILABLE,
         "\x74\x68\x65\x20\x54\x53\x41\x27\x73\x20\x74\x69\x6d\x65\x20\x73\x6f\x75\x72\x63\x65\x20\x69\x73\x20\x6e\x6f\x74\x20\x61\x76\x61\x69\x6c\x61\x62\x6c\x65"},
        {TS_INFO_UNACCEPTED_POLICY,
         "\x74\x68\x65\x20\x72\x65\x71\x75\x65\x73\x74\x65\x64\x20\x54\x53\x41\x20\x70\x6f\x6c\x69\x63\x79\x20\x69\x73\x20\x6e\x6f\x74\x20\x73\x75\x70\x70\x6f\x72\x74\x65\x64\x20\x62\x79\x20\x74\x68\x65\x20\x54\x53\x41"},
        {TS_INFO_UNACCEPTED_EXTENSION,
         "\x74\x68\x65\x20\x72\x65\x71\x75\x65\x73\x74\x65\x64\x20\x65\x78\x74\x65\x6e\x73\x69\x6f\x6e\x20\x69\x73\x20\x6e\x6f\x74\x20\x73\x75\x70\x70\x6f\x72\x74\x65\x64\x20\x62\x79\x20\x74\x68\x65\x20\x54\x53\x41"},
        {TS_INFO_ADD_INFO_NOT_AVAILABLE,
         "\x74\x68\x65\x20\x61\x64\x64\x69\x74\x69\x6f\x6e\x61\x6c\x20\x69\x6e\x66\x6f\x72\x6d\x61\x74\x69\x6f\x6e\x20\x72\x65\x71\x75\x65\x73\x74\x65\x64\x20\x63\x6f\x75\x6c\x64\x20\x6e\x6f\x74\x20\x62\x65\x20\x75\x6e\x64\x65\x72\x73\x74\x6f\x6f\x64\x20"
         "\x6f\x72\x20\x69\x73\x20\x6e\x6f\x74\x20\x61\x76\x61\x69\x6c\x61\x62\x6c\x65"},
        {TS_INFO_SYSTEM_FAILURE,
         "\x74\x68\x65\x20\x72\x65\x71\x75\x65\x73\x74\x20\x63\x61\x6e\x6e\x6f\x74\x20\x62\x65\x20\x68\x61\x6e\x64\x6c\x65\x64\x20\x64\x75\x65\x20\x74\x6f\x20\x73\x79\x73\x74\x65\x6d\x20\x66\x61\x69\x6c\x75\x72\x65"},
        {-1, NULL}
    };
    long status;
    int i, lines = 0;

    /* Printing status code. */
    BIO_printf(bio, "\x53\x74\x61\x74\x75\x73\x3a\x20");
    status = ASN1_INTEGER_get(a->status);
    if (0 <= status
        && status < (long)(sizeof(status_map) / sizeof(status_map[0])))
        BIO_printf(bio, "\x25\x73\xa", status_map[status]);
    else
        BIO_printf(bio, "\x6f\x75\x74\x20\x6f\x66\x20\x62\x6f\x75\x6e\x64\x73\xa");

    /* Printing status description. */
    BIO_printf(bio, "\x53\x74\x61\x74\x75\x73\x20\x64\x65\x73\x63\x72\x69\x70\x74\x69\x6f\x6e\x3a\x20");
    for (i = 0; i < sk_ASN1_UTF8STRING_num(a->text); ++i) {
        if (i > 0)
            BIO_puts(bio, "\x9");
        ASN1_STRING_print_ex(bio, sk_ASN1_UTF8STRING_value(a->text, i), 0);
        BIO_puts(bio, "\xa");
    }
    if (i == 0)
        BIO_printf(bio, "\x75\x6e\x73\x70\x65\x63\x69\x66\x69\x65\x64\xa");

    /* Printing failure information. */
    BIO_printf(bio, "\x46\x61\x69\x6c\x75\x72\x65\x20\x69\x6e\x66\x6f\x3a\x20");
    if (a->failure_info != NULL)
        lines = TS_status_map_print(bio, failure_map, a->failure_info);
    if (lines == 0)
        BIO_printf(bio, "\x75\x6e\x73\x70\x65\x63\x69\x66\x69\x65\x64");
    BIO_printf(bio, "\xa");

    return 1;
}

static int TS_status_map_print(BIO *bio, struct status_map_st *a,
                               ASN1_BIT_STRING *v)
{
    int lines = 0;

    for (; a->bit >= 0; ++a) {
        if (ASN1_BIT_STRING_get_bit(v, a->bit)) {
            if (++lines > 1)
                BIO_printf(bio, "\x2c\x20");
            BIO_printf(bio, "\x25\x73", a->text);
        }
    }

    return lines;
}

int TS_TST_INFO_print_bio(BIO *bio, TS_TST_INFO *a)
{
    int v;
    ASN1_OBJECT *policy_id;
    const ASN1_INTEGER *serial;
    const ASN1_GENERALIZEDTIME *gtime;
    TS_ACCURACY *accuracy;
    const ASN1_INTEGER *nonce;
    GENERAL_NAME *tsa_name;

    if (a == NULL)
        return 0;

    /* Print version. */
    v = TS_TST_INFO_get_version(a);
    BIO_printf(bio, "\x56\x65\x72\x73\x69\x6f\x6e\x3a\x20\x25\x64\xa", v);

    /* Print policy id. */
    BIO_printf(bio, "\x50\x6f\x6c\x69\x63\x79\x20\x4f\x49\x44\x3a\x20");
    policy_id = TS_TST_INFO_get_policy_id(a);
    TS_OBJ_print_bio(bio, policy_id);

    /* Print message imprint. */
    TS_MSG_IMPRINT_print_bio(bio, TS_TST_INFO_get_msg_imprint(a));

    /* Print serial number. */
    BIO_printf(bio, "\x53\x65\x72\x69\x61\x6c\x20\x6e\x75\x6d\x62\x65\x72\x3a\x20");
    serial = TS_TST_INFO_get_serial(a);
    if (serial == NULL)
        BIO_printf(bio, "\x75\x6e\x73\x70\x65\x63\x69\x66\x69\x65\x64");
    else
        TS_ASN1_INTEGER_print_bio(bio, serial);
    BIO_write(bio, "\xa", 1);

    /* Print time stamp. */
    BIO_printf(bio, "\x54\x69\x6d\x65\x20\x73\x74\x61\x6d\x70\x3a\x20");
    gtime = TS_TST_INFO_get_time(a);
    ASN1_GENERALIZEDTIME_print(bio, gtime);
    BIO_write(bio, "\xa", 1);

    /* Print accuracy. */
    BIO_printf(bio, "\x41\x63\x63\x75\x72\x61\x63\x79\x3a\x20");
    accuracy = TS_TST_INFO_get_accuracy(a);
    if (accuracy == NULL)
        BIO_printf(bio, "\x75\x6e\x73\x70\x65\x63\x69\x66\x69\x65\x64");
    else
        TS_ACCURACY_print_bio(bio, accuracy);
    BIO_write(bio, "\xa", 1);

    /* Print ordering. */
    BIO_printf(bio, "\x4f\x72\x64\x65\x72\x69\x6e\x67\x3a\x20\x25\x73\xa",
               TS_TST_INFO_get_ordering(a) ? "\x79\x65\x73" : "\x6e\x6f");

    /* Print nonce. */
    BIO_printf(bio, "\x4e\x6f\x6e\x63\x65\x3a\x20");
    nonce = TS_TST_INFO_get_nonce(a);
    if (nonce == NULL)
        BIO_printf(bio, "\x75\x6e\x73\x70\x65\x63\x69\x66\x69\x65\x64");
    else
        TS_ASN1_INTEGER_print_bio(bio, nonce);
    BIO_write(bio, "\xa", 1);

    /* Print TSA name. */
    BIO_printf(bio, "\x54\x53\x41\x3a\x20");
    tsa_name = TS_TST_INFO_get_tsa(a);
    if (tsa_name == NULL)
        BIO_printf(bio, "\x75\x6e\x73\x70\x65\x63\x69\x66\x69\x65\x64");
    else {
        STACK_OF(CONF_VALUE) *nval;
        if ((nval = i2v_GENERAL_NAME(NULL, tsa_name, NULL)))
            X509V3_EXT_val_prn(bio, nval, 0, 0);
        sk_CONF_VALUE_pop_free(nval, X509V3_conf_free);
    }
    BIO_write(bio, "\xa", 1);

    /* Print extensions. */
    TS_ext_print_bio(bio, TS_TST_INFO_get_exts(a));

    return 1;
}

static int TS_ACCURACY_print_bio(BIO *bio, const TS_ACCURACY *accuracy)
{
    const ASN1_INTEGER *seconds = TS_ACCURACY_get_seconds(accuracy);
    const ASN1_INTEGER *millis = TS_ACCURACY_get_millis(accuracy);
    const ASN1_INTEGER *micros = TS_ACCURACY_get_micros(accuracy);

    if (seconds != NULL)
        TS_ASN1_INTEGER_print_bio(bio, seconds);
    else
        BIO_printf(bio, "\x75\x6e\x73\x70\x65\x63\x69\x66\x69\x65\x64");
    BIO_printf(bio, "\x20\x73\x65\x63\x6f\x6e\x64\x73\x2c\x20");
    if (millis != NULL)
        TS_ASN1_INTEGER_print_bio(bio, millis);
    else
        BIO_printf(bio, "\x75\x6e\x73\x70\x65\x63\x69\x66\x69\x65\x64");
    BIO_printf(bio, "\x20\x6d\x69\x6c\x6c\x69\x73\x2c\x20");
    if (micros != NULL)
        TS_ASN1_INTEGER_print_bio(bio, micros);
    else
        BIO_printf(bio, "\x75\x6e\x73\x70\x65\x63\x69\x66\x69\x65\x64");
    BIO_printf(bio, "\x20\x6d\x69\x63\x72\x6f\x73");

    return 1;
}
