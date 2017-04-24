/* crypto/rc2/rc2test.c */
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

/*
 * This has been a quickly hacked 'ideatest.c'.  When I add tests for other
 * RC2 modes, more of the code will be uncommented.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../e_os.h"

#ifdef OPENSSL_NO_RC2
int main(int argc, char *argv[])
{
    printf("\x4e\x6f\x20\x52\x43\x32\x20\x73\x75\x70\x70\x6f\x72\x74\xa");
    return (0);
}
#else
# include <openssl/rc2.h>

static unsigned char RC2key[4][16] = {
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
};

static unsigned char RC2plain[4][8] = {
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
};

static unsigned char RC2cipher[4][8] = {
    {0x1C, 0x19, 0x8A, 0x83, 0x8D, 0xF0, 0x28, 0xB7},
    {0x21, 0x82, 0x9C, 0x78, 0xA9, 0xF9, 0xC0, 0x74},
    {0x13, 0xDB, 0x35, 0x17, 0xD3, 0x21, 0x86, 0x9E},
    {0x50, 0xDC, 0x01, 0x62, 0xBD, 0x75, 0x7F, 0x31},
};

/************/
# ifdef undef
unsigned char k[16] = {
    0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04,
    0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08
};

unsigned char in[8] = { 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03 };
unsigned char c[8] = { 0x11, 0xFB, 0xED, 0x2B, 0x01, 0x98, 0x6D, 0xE5 };

unsigned char out[80];

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

/*
 * static int cfb64_test(unsigned char *cfb_cipher);
 */
static char *pt(unsigned char *p);
# endif

int main(int argc, char *argv[])
{
    int i, n, err = 0;
    RC2_KEY key;
    unsigned char buf[8], buf2[8];

    for (n = 0; n < 4; n++) {
        RC2_set_key(&key, 16, &(RC2key[n][0]), 0 /* or 1024 */ );

        RC2_ecb_encrypt(&(RC2plain[n][0]), buf, &key, RC2_ENCRYPT);
        if (memcmp(&(RC2cipher[n][0]), buf, 8) != 0) {
            printf("\x65\x63\x62\x20\x72\x63\x32\x20\x65\x72\x72\x6f\x72\x20\x65\x6e\x63\x72\x79\x70\x74\x69\x6e\x67\xa");
            printf("\x67\x6f\x74\x20\x20\x20\x20\x20\x3a");
            for (i = 0; i < 8; i++)
                printf("\x25\x30\x32\x58\x20", buf[i]);
            printf("\xa");
            printf("\x65\x78\x70\x65\x63\x74\x65\x64\x3a");
            for (i = 0; i < 8; i++)
                printf("\x25\x30\x32\x58\x20", RC2cipher[n][i]);
            err = 20;
            printf("\xa");
        }

        RC2_ecb_encrypt(buf, buf2, &key, RC2_DECRYPT);
        if (memcmp(&(RC2plain[n][0]), buf2, 8) != 0) {
            printf("\x65\x63\x62\x20\x52\x43\x32\x20\x65\x72\x72\x6f\x72\x20\x64\x65\x63\x72\x79\x70\x74\x69\x6e\x67\xa");
            printf("\x67\x6f\x74\x20\x20\x20\x20\x20\x3a");
            for (i = 0; i < 8; i++)
                printf("\x25\x30\x32\x58\x20", buf[i]);
            printf("\xa");
            printf("\x65\x78\x70\x65\x63\x74\x65\x64\x3a");
            for (i = 0; i < 8; i++)
                printf("\x25\x30\x32\x58\x20", RC2plain[n][i]);
            printf("\xa");
            err = 3;
        }
    }

    if (err == 0)
        printf("\x65\x63\x62\x20\x52\x43\x32\x20\x6f\x6b\xa");
# ifdef undef
    memcpy(iv, k, 8);
    idea_cbc_encrypt((unsigned char *)text, out, strlen(text) + 1, &key, iv,
                     1);
    memcpy(iv, k, 8);
    idea_cbc_encrypt(out, out, 8, &dkey, iv, 0);
    idea_cbc_encrypt(&(out[8]), &(out[8]), strlen(text) + 1 - 8, &dkey, iv,
                     0);
    if (memcmp(text, out, strlen(text) + 1) != 0) {
        printf("\x63\x62\x63\x20\x69\x64\x65\x61\x20\x62\x61\x64\xa");
        err = 4;
    } else
        printf("\x63\x62\x63\x20\x69\x64\x65\x61\x20\x6f\x6b\xa");

    printf("\x63\x66\x62\x36\x34\x20\x69\x64\x65\x61\x20");
    if (cfb64_test(cfb_cipher64)) {
        printf("\x62\x61\x64\xa");
        err = 5;
    } else
        printf("\x6f\x6b\xa");
# endif

# ifdef OPENSSL_SYS_NETWARE
    if (err)
        printf("\x45\x52\x52\x4f\x52\x3a\x20\x25\x64\xa", err);
# endif
    EXIT(err);
    return (err);
}

# ifdef undef
static int cfb64_test(unsigned char *cfb_cipher)
{
    IDEA_KEY_SCHEDULE eks, dks;
    int err = 0, i, n;

    idea_set_encrypt_key(cfb_key, &eks);
    idea_set_decrypt_key(&eks, &dks);
    memcpy(cfb_tmp, cfb_iv, 8);
    n = 0;
    idea_cfb64_encrypt(plain, cfb_buf1, (long)12, &eks,
                       cfb_tmp, &n, IDEA_ENCRYPT);
    idea_cfb64_encrypt(&(plain[12]), &(cfb_buf1[12]),
                       (long)CFB_TEST_SIZE - 12, &eks,
                       cfb_tmp, &n, IDEA_ENCRYPT);
    if (memcmp(cfb_cipher, cfb_buf1, CFB_TEST_SIZE) != 0) {
        err = 1;
        printf("\x69\x64\x65\x61\x5f\x63\x66\x62\x36\x34\x5f\x65\x6e\x63\x72\x79\x70\x74\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x65\x72\x72\x6f\x72\xa");
        for (i = 0; i < CFB_TEST_SIZE; i += 8)
            printf("\x25\x73\xa", pt(&(cfb_buf1[i])));
    }
    memcpy(cfb_tmp, cfb_iv, 8);
    n = 0;
    idea_cfb64_encrypt(cfb_buf1, cfb_buf2, (long)17, &eks,
                       cfb_tmp, &n, IDEA_DECRYPT);
    idea_cfb64_encrypt(&(cfb_buf1[17]), &(cfb_buf2[17]),
                       (long)CFB_TEST_SIZE - 17, &dks,
                       cfb_tmp, &n, IDEA_DECRYPT);
    if (memcmp(plain, cfb_buf2, CFB_TEST_SIZE) != 0) {
        err = 1;
        printf("\x69\x64\x65\x61\x5f\x63\x66\x62\x5f\x65\x6e\x63\x72\x79\x70\x74\x20\x64\x65\x63\x72\x79\x70\x74\x20\x65\x72\x72\x6f\x72\xa");
        for (i = 0; i < 24; i += 8)
            printf("\x25\x73\xa", pt(&(cfb_buf2[i])));
    }
    return (err);
}

static char *pt(unsigned char *p)
{
    static char bufs[10][20];
    static int bnum = 0;
    char *ret;
    int i;
    static char *f = "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46";

    ret = &(bufs[bnum++][0]);
    bnum %= 10;
    for (i = 0; i < 8; i++) {
        ret[i * 2] = f[(p[i] >> 4) & 0xf];
        ret[i * 2 + 1] = f[p[i] & 0xf];
    }
    ret[16] = '\x0';
    return (ret);
}

# endif
#endif
