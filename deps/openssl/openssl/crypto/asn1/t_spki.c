/* t_spki.c */
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
#include <openssl/x509.h>
#include <openssl/asn1.h>
#ifndef OPENSSL_NO_RSA
# include <openssl/rsa.h>
#endif
#ifndef OPENSSL_NO_DSA
# include <openssl/dsa.h>
#endif
#include <openssl/bn.h>

/* Print out an SPKI */

int NETSCAPE_SPKI_print(BIO *out, NETSCAPE_SPKI *spki)
{
    EVP_PKEY *pkey;
    ASN1_IA5STRING *chal;
    int i, n;
    char *s;
    BIO_printf(out, "\x4e\x65\x74\x73\x63\x61\x70\x65\x20\x53\x50\x4b\x49\x3a\xa");
    i = OBJ_obj2nid(spki->spkac->pubkey->algor->algorithm);
    BIO_printf(out, "\x20\x20\x50\x75\x62\x6c\x69\x63\x20\x4b\x65\x79\x20\x41\x6c\x67\x6f\x72\x69\x74\x68\x6d\x3a\x20\x25\x73\xa",
               (i == NID_undef) ? "\x55\x4e\x4b\x4e\x4f\x57\x4e" : OBJ_nid2ln(i));
    pkey = X509_PUBKEY_get(spki->spkac->pubkey);
    if (!pkey)
        BIO_printf(out, "\x20\x20\x55\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x6c\x6f\x61\x64\x20\x70\x75\x62\x6c\x69\x63\x20\x6b\x65\x79\xa");
    else {
        EVP_PKEY_print_public(out, pkey, 4, NULL);
        EVP_PKEY_free(pkey);
    }
    chal = spki->spkac->challenge;
    if (chal->length)
        BIO_printf(out, "\x20\x20\x43\x68\x61\x6c\x6c\x65\x6e\x67\x65\x20\x53\x74\x72\x69\x6e\x67\x3a\x20\x25\x73\xa", chal->data);
    i = OBJ_obj2nid(spki->sig_algor->algorithm);
    BIO_printf(out, "\x20\x20\x53\x69\x67\x6e\x61\x74\x75\x72\x65\x20\x41\x6c\x67\x6f\x72\x69\x74\x68\x6d\x3a\x20\x25\x73",
               (i == NID_undef) ? "\x55\x4e\x4b\x4e\x4f\x57\x4e" : OBJ_nid2ln(i));

    n = spki->signature->length;
    s = (char *)spki->signature->data;
    for (i = 0; i < n; i++) {
        if ((i % 18) == 0)
            BIO_write(out, "\xa\x20\x20\x20\x20\x20\x20", 7);
        BIO_printf(out, "\x25\x30\x32\x78\x25\x73", (unsigned char)s[i],
                   ((i + 1) == n) ? "" : "\x3a");
    }
    BIO_write(out, "\xa", 1);
    return 1;
}
