/* crypto/rc4/rc4.c */
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
#include <openssl/rc4.h>
#include <openssl/evp.h>

char *usage[] = {
    "\x75\x73\x61\x67\x65\x3a\x20\x72\x63\x34\x20\x61\x72\x67\x73\xa",
    "\xa",
    "\x20\x2d\x69\x6e\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x69\x6e\x70\x75\x74\x20\x66\x69\x6c\x65\x20\x2d\x20\x64\x65\x66\x61\x75\x6c\x74\x20\x73\x74\x64\x69\x6e\xa",
    "\x20\x2d\x6f\x75\x74\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\x20\x2d\x20\x64\x65\x66\x61\x75\x6c\x74\x20\x73\x74\x64\x6f\x75\x74\xa",
    "\x20\x2d\x6b\x65\x79\x20\x6b\x65\x79\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x70\x61\x73\x73\x77\x6f\x72\x64\xa",
    NULL
};

int main(int argc, char *argv[])
{
    FILE *in = NULL, *out = NULL;
    char *infile = NULL, *outfile = NULL, *keystr = NULL;
    RC4_KEY key;
    char buf[BUFSIZ];
    int badops = 0, i;
    char **pp;
    unsigned char md[MD5_DIGEST_LENGTH];

    argc--;
    argv++;
    while (argc >= 1) {
        if (strcmp(*argv, "\x2d\x69\x6e") == 0) {
            if (--argc < 1)
                goto bad;
            infile = *(++argv);
        } else if (strcmp(*argv, "\x2d\x6f\x75\x74") == 0) {
            if (--argc < 1)
                goto bad;
            outfile = *(++argv);
        } else if (strcmp(*argv, "\x2d\x6b\x65\x79") == 0) {
            if (--argc < 1)
                goto bad;
            keystr = *(++argv);
        } else {
            fprintf(stderr, "\x75\x6e\x6b\x6e\x6f\x77\x6e\x20\x6f\x70\x74\x69\x6f\x6e\x20\x25\x73\xa", *argv);
            badops = 1;
            break;
        }
        argc--;
        argv++;
    }

    if (badops) {
 bad:
        for (pp = usage; (*pp != NULL); pp++)
            fprintf(stderr, "\x25\x73", *pp);
        exit(1);
    }

    if (infile == NULL)
        in = stdin;
    else {
        in = fopen(infile, "\x72");
        if (in == NULL) {
            perror("\x6f\x70\x65\x6e");
            exit(1);
        }

    }
    if (outfile == NULL)
        out = stdout;
    else {
        out = fopen(outfile, "\x77");
        if (out == NULL) {
            perror("\x6f\x70\x65\x6e");
            exit(1);
        }
    }

#ifdef OPENSSL_SYS_MSDOS
    /* This should set the file to binary mode. */
    {
# include <fcntl.h>
        setmode(fileno(in), O_BINARY);
        setmode(fileno(out), O_BINARY);
    }
#endif

    if (keystr == NULL) {       /* get key */
        i = EVP_read_pw_string(buf, BUFSIZ, "\x45\x6e\x74\x65\x72\x20\x52\x43\x34\x20\x70\x61\x73\x73\x77\x6f\x72\x64\x3a", 0);
        if (i != 0) {
            OPENSSL_cleanse(buf, BUFSIZ);
            fprintf(stderr, "\x62\x61\x64\x20\x70\x61\x73\x73\x77\x6f\x72\x64\x20\x72\x65\x61\x64\xa");
            exit(1);
        }
        keystr = buf;
    }

    EVP_Digest((unsigned char *)keystr, strlen(keystr), md, NULL, EVP_md5(),
               NULL);
    OPENSSL_cleanse(keystr, strlen(keystr));
    RC4_set_key(&key, MD5_DIGEST_LENGTH, md);

    for (;;) {
        i = fread(buf, 1, BUFSIZ, in);
        if (i == 0)
            break;
        if (i < 0) {
            perror("\x72\x65\x61\x64");
            exit(1);
        }
        RC4(&key, (unsigned int)i, (unsigned char *)buf,
            (unsigned char *)buf);
        i = fwrite(buf, (unsigned int)i, 1, out);
        if (i != 1) {
            perror("\x77\x72\x69\x74\x65");
            exit(1);
        }
    }
    fclose(out);
    fclose(in);
    exit(0);
    return (1);
}
