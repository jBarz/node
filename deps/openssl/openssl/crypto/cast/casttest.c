/* crypto/cast/casttest.c */
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
#include <string.h>
#include <stdlib.h>
#include <openssl/opensslconf.h> /* To see if OPENSSL_NO_CAST is defined */

#include "../e_os.h"

#ifdef OPENSSL_NO_CAST
int main(int argc, char *argv[])
{
    printf("\x4e\x6f\x20\x43\x41\x53\x54\x20\x73\x75\x70\x70\x6f\x72\x74\xa");
    return (0);
}
#else
# include <openssl/cast.h>

# define FULL_TEST

static unsigned char k[16] = {
    0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78,
    0x23, 0x45, 0x67, 0x89, 0x34, 0x56, 0x78, 0x9A
};

static unsigned char in[8] =
    { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };

static int k_len[3] = { 16, 10, 5 };

static unsigned char c[3][8] = {
    {0x23, 0x8B, 0x4F, 0xE5, 0x84, 0x7E, 0x44, 0xB2},
    {0xEB, 0x6A, 0x71, 0x1A, 0x2C, 0x02, 0x27, 0x1B},
    {0x7A, 0xC8, 0x16, 0xD1, 0x6E, 0x9B, 0x30, 0x2E},
};

static unsigned char out[80];

static unsigned char in_a[16] = {
    0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78,
    0x23, 0x45, 0x67, 0x89, 0x34, 0x56, 0x78, 0x9A
};

static unsigned char in_b[16] = {
    0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78,
    0x23, 0x45, 0x67, 0x89, 0x34, 0x56, 0x78, 0x9A
};

static unsigned char c_a[16] = {
    0xEE, 0xA9, 0xD0, 0xA2, 0x49, 0xFD, 0x3B, 0xA6,
    0xB3, 0x43, 0x6F, 0xB8, 0x9D, 0x6D, 0xCA, 0x92
};

static unsigned char c_b[16] = {
    0xB2, 0xC9, 0x5E, 0xB0, 0x0C, 0x31, 0xAD, 0x71,
    0x80, 0xAC, 0x05, 0xB8, 0xE8, 0x3D, 0x69, 0x6E
};

# if 0
char *text = "\x48\x65\x6c\x6c\x6f\x20\x74\x6f\x20\x61\x6c\x6c\x20\x70\x65\x6f\x70\x6c\x65\x20\x6f\x75\x74\x20\x74\x68\x65\x72\x65";

static unsigned char cfb_key[16] = {
    0xe1, 0xf0, 0xc3, 0xd2, 0xa5, 0xb4, 0x87, 0x96,
    0x69, 0x78, 0x4b, 0x5a, 0x2d, 0x3c, 0x0f, 0x1e,
};
static unsigned char cfb_iv[80] =
    { 0x34, 0x12, 0x78, 0x56, 0xab, 0x90, 0xef, 0xcd };
static unsigned char cfb_buf1[40], cfb_buf2[40], cfb_tmp[8];
#  define CFB_TEST_SIZE 24
static unsigned char plain[CFB_TEST_SIZE] = {
    0x4e, 0x6f, 0x77, 0x20, 0x69, 0x73,
    0x20, 0x74, 0x68, 0x65, 0x20, 0x74,
    0x69, 0x6d, 0x65, 0x20, 0x66, 0x6f,
    0x72, 0x20, 0x61, 0x6c, 0x6c, 0x20
};

static unsigned char cfb_cipher64[CFB_TEST_SIZE] = {
    0x59, 0xD8, 0xE2, 0x65, 0x00, 0x58, 0x6C, 0x3F,
    0x2C, 0x17, 0x25, 0xD0, 0x1A, 0x38, 0xB7, 0x2A,
    0x39, 0x61, 0x37, 0xDC, 0x79, 0xFB, 0x9F, 0x45
/*- 0xF9,0x78,0x32,0xB5,0x42,0x1A,0x6B,0x38,
    0x9A,0x44,0xD6,0x04,0x19,0x43,0xC4,0xD9,
    0x3D,0x1E,0xAE,0x47,0xFC,0xCF,0x29,0x0B,*/
};
# endif

int main(int argc, char *argv[])
{
# ifdef FULL_TEST
    long l;
    CAST_KEY key_b;
# endif
    int i, z, err = 0;
    CAST_KEY key;

    for (z = 0; z < 3; z++) {
        CAST_set_key(&key, k_len[z], k);

        CAST_ecb_encrypt(in, out, &key, CAST_ENCRYPT);
        if (memcmp(out, &(c[z][0]), 8) != 0) {
            printf("\x65\x63\x62\x20\x63\x61\x73\x74\x20\x65\x72\x72\x6f\x72\x20\x65\x6e\x63\x72\x79\x70\x74\x69\x6e\x67\x20\x66\x6f\x72\x20\x6b\x65\x79\x73\x69\x7a\x65\x20\x25\x64\xa",
                   k_len[z] * 8);
            printf("\x67\x6f\x74\x20\x20\x20\x20\x20\x3a");
            for (i = 0; i < 8; i++)
                printf("\x25\x30\x32\x58\x20", out[i]);
            printf("\xa");
            printf("\x65\x78\x70\x65\x63\x74\x65\x64\x3a");
            for (i = 0; i < 8; i++)
                printf("\x25\x30\x32\x58\x20", c[z][i]);
            err = 20;
            printf("\xa");
        }

        CAST_ecb_encrypt(out, out, &key, CAST_DECRYPT);
        if (memcmp(out, in, 8) != 0) {
            printf("\x65\x63\x62\x20\x63\x61\x73\x74\x20\x65\x72\x72\x6f\x72\x20\x64\x65\x63\x72\x79\x70\x74\x69\x6e\x67\x20\x66\x6f\x72\x20\x6b\x65\x79\x73\x69\x7a\x65\x20\x25\x64\xa",
                   k_len[z] * 8);
            printf("\x67\x6f\x74\x20\x20\x20\x20\x20\x3a");
            for (i = 0; i < 8; i++)
                printf("\x25\x30\x32\x58\x20", out[i]);
            printf("\xa");
            printf("\x65\x78\x70\x65\x63\x74\x65\x64\x3a");
            for (i = 0; i < 8; i++)
                printf("\x25\x30\x32\x58\x20", in[i]);
            printf("\xa");
            err = 3;
        }
    }
    if (err == 0)
        printf("\x65\x63\x62\x20\x63\x61\x73\x74\x35\x20\x6f\x6b\xa");

# ifdef FULL_TEST
    {
        unsigned char out_a[16], out_b[16];
        static char *hex = "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46";

        printf("\x54\x68\x69\x73\x20\x74\x65\x73\x74\x20\x77\x69\x6c\x6c\x20\x74\x61\x6b\x65\x20\x73\x6f\x6d\x65\x20\x74\x69\x6d\x65\x2e\x2e\x2e\x2e");
        fflush(stdout);
        memcpy(out_a, in_a, sizeof(in_a));
        memcpy(out_b, in_b, sizeof(in_b));
        i = 1;

        for (l = 0; l < 1000000L; l++) {
            CAST_set_key(&key_b, 16, out_b);
            CAST_ecb_encrypt(&(out_a[0]), &(out_a[0]), &key_b, CAST_ENCRYPT);
            CAST_ecb_encrypt(&(out_a[8]), &(out_a[8]), &key_b, CAST_ENCRYPT);
            CAST_set_key(&key, 16, out_a);
            CAST_ecb_encrypt(&(out_b[0]), &(out_b[0]), &key, CAST_ENCRYPT);
            CAST_ecb_encrypt(&(out_b[8]), &(out_b[8]), &key, CAST_ENCRYPT);
            if ((l & 0xffff) == 0xffff) {
                printf("\x25\x63", hex[i & 0x0f]);
                fflush(stdout);
                i++;
            }
        }

        if ((memcmp(out_a, c_a, sizeof(c_a)) != 0) ||
            (memcmp(out_b, c_b, sizeof(c_b)) != 0)) {
            printf("\xa");
            printf("\x45\x72\x72\x6f\x72\xa");

            printf("\x41\x20\x6f\x75\x74\x20\x3d");
            for (i = 0; i < 16; i++)
                printf("\x25\x30\x32\x58\x20", out_a[i]);
            printf("\xaa\x63\x74\x75\x61\x6c\x3d");
            for (i = 0; i < 16; i++)
                printf("\x25\x30\x32\x58\x20", c_a[i]);
            printf("\xa");

            printf("\x42\x20\x6f\x75\x74\x20\x3d");
            for (i = 0; i < 16; i++)
                printf("\x25\x30\x32\x58\x20", out_b[i]);
            printf("\xaa\x63\x74\x75\x61\x6c\x3d");
            for (i = 0; i < 16; i++)
                printf("\x25\x30\x32\x58\x20", c_b[i]);
            printf("\xa");
        } else
            printf("\x20\x6f\x6b\xa");
    }
# endif

    EXIT(err);
    return (err);
}
#endif
