/* tabtest.c */
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

/*
 * Simple program to check the ext_dat.h is correct and print out problems if
 * it is not.
 */

#include <stdio.h>

#include <openssl/x509v3.h>

#include "ext_dat.h"

main()
{
    int i, prev = -1, bad = 0;
    X509V3_EXT_METHOD **tmp;
    i = sizeof(standard_exts) / sizeof(X509V3_EXT_METHOD *);
    if (i != STANDARD_EXTENSION_COUNT)
        fprintf(stderr, "\x45\x78\x74\x65\x6e\x73\x69\x6f\x6e\x20\x6e\x75\x6d\x62\x65\x72\x20\x69\x6e\x76\x61\x6c\x69\x64\x20\x65\x78\x70\x65\x63\x74\x69\x6e\x67\x20\x25\x64\xa", i);
    tmp = standard_exts;
    for (i = 0; i < STANDARD_EXTENSION_COUNT; i++, tmp++) {
        if ((*tmp)->ext_nid < prev)
            bad = 1;
        prev = (*tmp)->ext_nid;

    }
    if (bad) {
        tmp = standard_exts;
        fprintf(stderr, "\x45\x78\x74\x65\x6e\x73\x69\x6f\x6e\x73\x20\x6f\x75\x74\x20\x6f\x66\x20\x6f\x72\x64\x65\x72\x21\xa");
        for (i = 0; i < STANDARD_EXTENSION_COUNT; i++, tmp++)
            printf("\x25\x64\x20\x3a\x20\x25\x73\xa", (*tmp)->ext_nid, OBJ_nid2sn((*tmp)->ext_nid));
    } else
        fprintf(stderr, "\x4f\x72\x64\x65\x72\x20\x4f\x4b\xa");
}
