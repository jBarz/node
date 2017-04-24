/* crypto/mdc2/mdc2test.c */
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
#include <stdlib.h>
#include <string.h>

#include "../e_os.h"

#if defined(OPENSSL_NO_DES) && !defined(OPENSSL_NO_MDC2)
# define OPENSSL_NO_MDC2
#endif

#ifdef OPENSSL_NO_MDC2
int main(int argc, char *argv[])
{
    printf("\x4e\x6f\x20\x4d\x44\x43\x32\x20\x73\x75\x70\x70\x6f\x72\x74\xa");
    return (0);
}
#else
# include <openssl/evp.h>
# include <openssl/mdc2.h>

# ifdef CHARSET_EBCDIC
#  include <openssl/ebcdic.h>
# endif

static unsigned char pad1[16] = {
    0x42, 0xE5, 0x0C, 0xD2, 0x24, 0xBA, 0xCE, 0xBA,
    0x76, 0x0B, 0xDD, 0x2B, 0xD4, 0x09, 0x28, 0x1A
};

static unsigned char pad2[16] = {
    0x2E, 0x46, 0x79, 0xB5, 0xAD, 0xD9, 0xCA, 0x75,
    0x35, 0xD8, 0x7A, 0xFE, 0xAB, 0x33, 0xBE, 0xE2
};

int main(int argc, char *argv[])
{
    int ret = 0;
    unsigned char md[MDC2_DIGEST_LENGTH];
    int i;
    EVP_MD_CTX c;
    static char *text = "\x4e\x6f\x77\x20\x69\x73\x20\x74\x68\x65\x20\x74\x69\x6d\x65\x20\x66\x6f\x72\x20\x61\x6c\x6c\x20";

# ifdef CHARSET_EBCDIC
    ebcdic2ascii(text, text, strlen(text));
# endif

    EVP_MD_CTX_init(&c);
    EVP_DigestInit_ex(&c, EVP_mdc2(), NULL);
    EVP_DigestUpdate(&c, (unsigned char *)text, strlen(text));
    EVP_DigestFinal_ex(&c, &(md[0]), NULL);

    if (memcmp(md, pad1, MDC2_DIGEST_LENGTH) != 0) {
        for (i = 0; i < MDC2_DIGEST_LENGTH; i++)
            printf("\x25\x30\x32\x58", md[i]);
        printf("\x20\x3c\x2d\x20\x67\x65\x6e\x65\x72\x61\x74\x65\x64\xa");
        for (i = 0; i < MDC2_DIGEST_LENGTH; i++)
            printf("\x25\x30\x32\x58", pad1[i]);
        printf("\x20\x3c\x2d\x20\x63\x6f\x72\x72\x65\x63\x74\xa");
        ret = 1;
    } else
        printf("\x70\x61\x64\x31\x20\x2d\x20\x6f\x6b\xa");

    EVP_DigestInit_ex(&c, EVP_mdc2(), NULL);
    /* FIXME: use a ctl function? */
    ((MDC2_CTX *)c.md_data)->pad_type = 2;
    EVP_DigestUpdate(&c, (unsigned char *)text, strlen(text));
    EVP_DigestFinal_ex(&c, &(md[0]), NULL);

    if (memcmp(md, pad2, MDC2_DIGEST_LENGTH) != 0) {
        for (i = 0; i < MDC2_DIGEST_LENGTH; i++)
            printf("\x25\x30\x32\x58", md[i]);
        printf("\x20\x3c\x2d\x20\x67\x65\x6e\x65\x72\x61\x74\x65\x64\xa");
        for (i = 0; i < MDC2_DIGEST_LENGTH; i++)
            printf("\x25\x30\x32\x58", pad2[i]);
        printf("\x20\x3c\x2d\x20\x63\x6f\x72\x72\x65\x63\x74\xa");
        ret = 1;
    } else
        printf("\x70\x61\x64\x32\x20\x2d\x20\x6f\x6b\xa");

    EVP_MD_CTX_cleanup(&c);
# ifdef OPENSSL_SYS_NETWARE
    if (ret)
        printf("\x45\x52\x52\x4f\x52\x3a\x20\x25\x64\xa", ret);
# endif
    EXIT(ret);
    return (ret);
}
#endif
