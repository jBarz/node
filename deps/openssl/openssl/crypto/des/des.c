/* crypto/des/des.c */
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
#include <openssl/opensslconf.h>
#ifndef OPENSSL_SYS_MSDOS
# ifndef OPENSSL_SYS_VMS
#  include OPENSSL_UNISTD
# else                          /* OPENSSL_SYS_VMS */
#  ifdef __DECC
#   include <unistd.h>
#  else                         /* not __DECC */
#   include <math.h>
#  endif                        /* __DECC */
# endif                         /* OPENSSL_SYS_VMS */
#else                           /* OPENSSL_SYS_MSDOS */
# include <io.h>
#endif

#include <time.h>
#include "des_ver.h"

#ifdef OPENSSL_SYS_VMS
# include <types.h>
# include <stat.h>
#else
# ifndef _IRIX
#  include <sys/types.h>
# endif
# include <sys/stat.h>
#endif
#include <openssl/des.h>
#include <openssl/rand.h>
#include <openssl/ui_compat.h>

void usage(void);
void doencryption(void);
int uufwrite(unsigned char *data, int size, unsigned int num, FILE *fp);
void uufwriteEnd(FILE *fp);
int uufread(unsigned char *out, int size, unsigned int num, FILE *fp);
int uuencode(unsigned char *in, int num, unsigned char *out);
int uudecode(unsigned char *in, int num, unsigned char *out);
void DES_3cbc_encrypt(DES_cblock *input, DES_cblock *output, long length,
                      DES_key_schedule sk1, DES_key_schedule sk2,
                      DES_cblock *ivec1, DES_cblock *ivec2, int enc);
#ifdef OPENSSL_SYS_VMS
# define EXIT(a) exit(a&0x10000000L)
#else
# define EXIT(a) exit(a)
#endif

#define BUFSIZE (8*1024)
#define VERIFY  1
#define KEYSIZ  8
#define KEYSIZB 1024            /* should hit tty line limit first :-) */
char key[KEYSIZB + 1];
int do_encrypt, longk = 0;
FILE *DES_IN, *DES_OUT, *CKSUM_OUT;
char uuname[200];
unsigned char uubuf[50];
int uubufnum = 0;
#define INUUBUFN        (45*100)
#define OUTUUBUF        (65*100)
unsigned char b[OUTUUBUF];
unsigned char bb[300];
DES_cblock cksum = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

char cksumname[200] = "";

int vflag, cflag, eflag, dflag, kflag, bflag, fflag, sflag, uflag, flag3,
    hflag, error;

int main(int argc, char **argv)
{
    int i;
    struct stat ins, outs;
    char *p;
    char *in = NULL, *out = NULL;

    vflag = cflag = eflag = dflag = kflag = hflag = bflag = fflag = sflag =
        uflag = flag3 = 0;
    error = 0;
    memset(key, 0, sizeof(key));

    for (i = 1; i < argc; i++) {
        p = argv[i];
        if ((p[0] == '\x2d') && (p[1] != '\x0')) {
            p++;
            while (*p) {
                switch (*(p++)) {
                case '\x33':
                    flag3 = 1;
                    longk = 1;
                    break;
                case '\x63':
                    cflag = 1;
                    strncpy(cksumname, p, 200);
                    cksumname[sizeof(cksumname) - 1] = '\x0';
                    p += strlen(cksumname);
                    break;
                case '\x43':
                    cflag = 1;
                    longk = 1;
                    strncpy(cksumname, p, 200);
                    cksumname[sizeof(cksumname) - 1] = '\x0';
                    p += strlen(cksumname);
                    break;
                case '\x65':
                    eflag = 1;
                    break;
                case '\x76':
                    vflag = 1;
                    break;
                case '\x45':
                    eflag = 1;
                    longk = 1;
                    break;
                case '\x64':
                    dflag = 1;
                    break;
                case '\x44':
                    dflag = 1;
                    longk = 1;
                    break;
                case '\x62':
                    bflag = 1;
                    break;
                case '\x66':
                    fflag = 1;
                    break;
                case '\x73':
                    sflag = 1;
                    break;
                case '\x75':
                    uflag = 1;
                    strncpy(uuname, p, 200);
                    uuname[sizeof(uuname) - 1] = '\x0';
                    p += strlen(uuname);
                    break;
                case '\x68':
                    hflag = 1;
                    break;
                case '\x6b':
                    kflag = 1;
                    if ((i + 1) == argc) {
                        fputs("\x6d\x75\x73\x74\x20\x68\x61\x76\x65\x20\x61\x20\x6b\x65\x79\x20\x77\x69\x74\x68\x20\x74\x68\x65\x20\x2d\x6b\x20\x6f\x70\x74\x69\x6f\x6e\xa", stderr);
                        error = 1;
                    } else {
                        int j;

                        i++;
                        strncpy(key, argv[i], KEYSIZB);
                        for (j = strlen(argv[i]) - 1; j >= 0; j--)
                            argv[i][j] = '\x0';
                    }
                    break;
                default:
                    fprintf(stderr, "\x27\x25\x63\x27\x20\x75\x6e\x6b\x6e\x6f\x77\x6e\x20\x66\x6c\x61\x67\xa", p[-1]);
                    error = 1;
                    break;
                }
            }
        } else {
            if (in == NULL)
                in = argv[i];
            else if (out == NULL)
                out = argv[i];
            else
                error = 1;
        }
    }
    if (error)
        usage();
    /*-
     * We either
     * do checksum or
     * do encrypt or
     * do decrypt or
     * do decrypt then ckecksum or
     * do checksum then encrypt
     */
    if (((eflag + dflag) == 1) || cflag) {
        if (eflag)
            do_encrypt = DES_ENCRYPT;
        if (dflag)
            do_encrypt = DES_DECRYPT;
    } else {
        if (vflag) {
#ifndef _Windows
            fprintf(stderr, "\x64\x65\x73\x28\x31\x29\x20\x62\x75\x69\x6c\x74\x20\x77\x69\x74\x68\x20\x25\x73\xa", libdes_version);
#endif
            EXIT(1);
        } else
            usage();
    }

#ifndef _Windows
    if (vflag)
        fprintf(stderr, "\x64\x65\x73\x28\x31\x29\x20\x62\x75\x69\x6c\x74\x20\x77\x69\x74\x68\x20\x25\x73\xa", libdes_version);
#endif
    if ((in != NULL) && (out != NULL) &&
#ifndef OPENSSL_SYS_MSDOS
        (stat(in, &ins) != -1) &&
        (stat(out, &outs) != -1) &&
        (ins.st_dev == outs.st_dev) && (ins.st_ino == outs.st_ino))
#else                           /* OPENSSL_SYS_MSDOS */
        (strcmp(in, out) == 0))
#endif
    {
        fputs("\x69\x6e\x70\x75\x74\x20\x61\x6e\x64\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\x20\x61\x72\x65\x20\x74\x68\x65\x20\x73\x61\x6d\x65\xa", stderr);
        EXIT(3);
    }

    if (!kflag)
        if (des_read_pw_string
            (key, KEYSIZB + 1, "\x45\x6e\x74\x65\x72\x20\x6b\x65\x79\x3a", eflag ? VERIFY : 0)) {
            fputs("\x70\x61\x73\x73\x77\x6f\x72\x64\x20\x65\x72\x72\x6f\x72\xa", stderr);
            EXIT(2);
        }

    if (in == NULL)
        DES_IN = stdin;
    else if ((DES_IN = fopen(in, "\x72")) == NULL) {
        perror("\x6f\x70\x65\x6e\x69\x6e\x67\x20\x69\x6e\x70\x75\x74\x20\x66\x69\x6c\x65");
        EXIT(4);
    }

    CKSUM_OUT = stdout;
    if (out == NULL) {
        DES_OUT = stdout;
        CKSUM_OUT = stderr;
    } else if ((DES_OUT = fopen(out, "\x77")) == NULL) {
        perror("\x6f\x70\x65\x6e\x69\x6e\x67\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65");
        EXIT(5);
    }
#ifdef OPENSSL_SYS_MSDOS
    /* This should set the file to binary mode. */
    {
# include <fcntl.h>
        if (!(uflag && dflag))
            setmode(fileno(DES_IN), O_BINARY);
        if (!(uflag && eflag))
            setmode(fileno(DES_OUT), O_BINARY);
    }
#endif

    doencryption();
    fclose(DES_IN);
    fclose(DES_OUT);
    EXIT(0);
}

void usage(void)
{
    char **u;
    static const char *Usage[] = {
        "\x64\x65\x73\x20\x3c\x6f\x70\x74\x69\x6f\x6e\x73\x3e\x20\x5b\x69\x6e\x70\x75\x74\x2d\x66\x69\x6c\x65\x20\x5b\x6f\x75\x74\x70\x75\x74\x2d\x66\x69\x6c\x65\x5d\x5d",
        "\x6f\x70\x74\x69\x6f\x6e\x73\x3a",
        "\x2d\x76\x20\x20\x20\x20\x20\x20\x20\x20\x20\x3a\x20\x64\x65\x73\x28\x31\x29\x20\x76\x65\x72\x73\x69\x6f\x6e\x20\x6e\x75\x6d\x62\x65\x72",
        "\x2d\x65\x20\x20\x20\x20\x20\x20\x20\x20\x20\x3a\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x75\x73\x69\x6e\x67\x20\x53\x75\x6e\x4f\x53\x20\x63\x6f\x6d\x70\x61\x74\x69\x62\x6c\x65\x20\x75\x73\x65\x72\x20\x6b\x65\x79\x20\x74\x6f\x20\x44\x45\x53\x20\x6b\x65\x79\x20\x63\x6f\x6e\x76\x65\x72\x73\x69\x6f\x6e\x2e",
        "\x2d\x45\x20\x20\x20\x20\x20\x20\x20\x20\x20\x3a\x20\x65\x6e\x63\x72\x79\x70\x74\x20",
        "\x2d\x64\x20\x20\x20\x20\x20\x20\x20\x20\x20\x3a\x20\x64\x65\x63\x72\x79\x70\x74\x20\x75\x73\x69\x6e\x67\x20\x53\x75\x6e\x4f\x53\x20\x63\x6f\x6d\x70\x61\x74\x69\x62\x6c\x65\x20\x75\x73\x65\x72\x20\x6b\x65\x79\x20\x74\x6f\x20\x44\x45\x53\x20\x6b\x65\x79\x20\x63\x6f\x6e\x76\x65\x72\x73\x69\x6f\x6e\x2e",
        "\x2d\x44\x20\x20\x20\x20\x20\x20\x20\x20\x20\x3a\x20\x64\x65\x63\x72\x79\x70\x74\x20",
        "\x2d\x63\x5b\x63\x6b\x6e\x61\x6d\x65\x5d\x20\x3a\x20\x67\x65\x6e\x65\x72\x61\x74\x65\x20\x61\x20\x63\x62\x63\x5f\x63\x6b\x73\x75\x6d\x20\x75\x73\x69\x6e\x67\x20\x53\x75\x6e\x4f\x53\x20\x63\x6f\x6d\x70\x61\x74\x69\x62\x6c\x65\x20\x75\x73\x65\x72\x20\x6b\x65\x79\x20\x74\x6f",
        "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x44\x45\x53\x20\x6b\x65\x79\x20\x63\x6f\x6e\x76\x65\x72\x73\x69\x6f\x6e\x20\x61\x6e\x64\x20\x6f\x75\x74\x70\x75\x74\x20\x74\x6f\x20\x63\x6b\x6e\x61\x6d\x65\x20\x28\x73\x74\x64\x6f\x75\x74\x20\x64\x65\x66\x61\x75\x6c\x74\x2c",
        "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x73\x74\x64\x65\x72\x72\x20\x69\x66\x20\x64\x61\x74\x61\x20\x62\x65\x69\x6e\x67\x20\x6f\x75\x74\x70\x75\x74\x20\x6f\x6e\x20\x73\x74\x64\x6f\x75\x74\x29\x2e\x20\x20\x54\x68\x65\x20\x63\x68\x65\x63\x6b\x73\x75\x6d\x20\x69\x73",
        "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x67\x65\x6e\x65\x72\x61\x74\x65\x64\x20\x62\x65\x66\x6f\x72\x65\x20\x65\x6e\x63\x72\x79\x70\x74\x69\x6f\x6e\x20\x61\x6e\x64\x20\x61\x66\x74\x65\x72\x20\x64\x65\x63\x72\x79\x70\x74\x69\x6f\x6e\x20\x69\x66\x20\x75\x73\x65\x64",
        "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x69\x6e\x20\x63\x6f\x6e\x6a\x75\x6e\x63\x74\x69\x6f\x6e\x20\x77\x69\x74\x68\x20\x2d\x5b\x65\x45\x64\x44\x5d\x2e",
        "\x2d\x43\x5b\x63\x6b\x6e\x61\x6d\x65\x5d\x20\x3a\x20\x67\x65\x6e\x65\x72\x61\x74\x65\x20\x61\x20\x63\x62\x63\x5f\x63\x6b\x73\x75\x6d\x20\x61\x73\x20\x66\x6f\x72\x20\x2d\x63\x20\x62\x75\x74\x20\x63\x6f\x6d\x70\x61\x74\x69\x62\x6c\x65\x20\x77\x69\x74\x68\x20\x2d\x5b\x45\x44\x5d\x2e",
        "\x2d\x6b\x20\x6b\x65\x79\x20\x20\x20\x20\x20\x3a\x20\x75\x73\x65\x20\x6b\x65\x79\x20\x27\x6b\x65\x79\x27",
        "\x2d\x68\x20\x20\x20\x20\x20\x20\x20\x20\x20\x3a\x20\x74\x68\x65\x20\x6b\x65\x79\x20\x74\x68\x61\x74\x20\x69\x73\x20\x65\x6e\x74\x65\x72\x65\x64\x20\x77\x69\x6c\x6c\x20\x62\x65\x20\x61\x20\x68\x65\x78\x61\x64\x65\x63\x69\x6d\x61\x6c\x20\x6e\x75\x6d\x62\x65\x72",
        "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x74\x68\x61\x74\x20\x69\x73\x20\x75\x73\x65\x64\x20\x64\x69\x72\x65\x63\x74\x6c\x79\x20\x61\x73\x20\x74\x68\x65\x20\x64\x65\x73\x20\x6b\x65\x79",
        "\x2d\x75\x5b\x75\x75\x6e\x61\x6d\x65\x5d\x20\x3a\x20\x69\x6e\x70\x75\x74\x20\x66\x69\x6c\x65\x20\x69\x73\x20\x75\x75\x64\x65\x63\x6f\x64\x65\x64\x20\x69\x66\x20\x2d\x5b\x64\x44\x5d\x20\x6f\x72\x20\x6f\x75\x74\x70\x75\x74\x20\x75\x75\x65\x6e\x63\x6f\x64\x65\x64\x20\x64\x61\x74\x61\x20\x69\x66\x20\x2d\x5b\x65\x45\x5d",
        "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x28\x75\x75\x6e\x61\x6d\x65\x20\x69\x73\x20\x74\x68\x65\x20\x66\x69\x6c\x65\x6e\x61\x6d\x65\x20\x74\x6f\x20\x70\x75\x74\x20\x69\x6e\x20\x74\x68\x65\x20\x75\x75\x65\x6e\x63\x6f\x64\x65\x20\x68\x65\x61\x64\x65\x72\x29\x2e",
        "\x2d\x62\x20\x20\x20\x20\x20\x20\x20\x20\x20\x3a\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x75\x73\x69\x6e\x67\x20\x44\x45\x53\x20\x69\x6e\x20\x65\x63\x62\x20\x65\x6e\x63\x72\x79\x70\x74\x69\x6f\x6e\x20\x6d\x6f\x64\x65\x2c\x20\x74\x68\x65\x20\x64\x65\x66\x61\x75\x6c\x74\x20\x69\x73\x20\x63\x62\x63\x20\x6d\x6f\x64\x65\x2e",
        "\x2d\x33\x20\x20\x20\x20\x20\x20\x20\x20\x20\x3a\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x75\x73\x69\x6e\x67\x20\x74\x72\x69\x70\x6c\x65\x20\x44\x45\x53\x20\x65\x6e\x63\x72\x79\x70\x74\x69\x6f\x6e\x2e\x20\x20\x54\x68\x69\x73\x20\x75\x73\x65\x73\x20\x32\x20\x6b\x65\x79\x73",
        "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x67\x65\x6e\x65\x72\x61\x74\x65\x64\x20\x66\x72\x6f\x6d\x20\x74\x68\x65\x20\x69\x6e\x70\x75\x74\x20\x6b\x65\x79\x2e\x20\x20\x49\x66\x20\x74\x68\x65\x20\x69\x6e\x70\x75\x74\x20\x6b\x65\x79\x20\x69\x73\x20\x6c\x65\x73\x73",
        "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x74\x68\x61\x6e\x20\x38\x20\x63\x68\x61\x72\x61\x63\x74\x65\x72\x73\x20\x6c\x6f\x6e\x67\x2c\x20\x74\x68\x69\x73\x20\x69\x73\x20\x65\x71\x75\x69\x76\x61\x6c\x65\x6e\x74\x20\x74\x6f\x20\x6e\x6f\x72\x6d\x61\x6c",
        "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x65\x6e\x63\x72\x79\x70\x74\x69\x6f\x6e\x2e\x20\x20\x44\x65\x66\x61\x75\x6c\x74\x20\x69\x73\x20\x74\x72\x69\x70\x6c\x65\x20\x63\x62\x63\x2c\x20\x2d\x62\x20\x6d\x61\x6b\x65\x73\x20\x69\x74\x20\x74\x72\x69\x70\x6c\x65\x20\x65\x63\x62\x2e",
        NULL
    };
    for (u = (char **)Usage; *u; u++) {
        fputs(*u, stderr);
        fputc('\xa', stderr);
    }

    EXIT(1);
}

void doencryption(void)
{
#ifdef _LIBC
    extern unsigned long time();
#endif

    register int i;
    DES_key_schedule ks, ks2;
    DES_cblock iv, iv2;
    char *p;
    int num = 0, j, k, l, rem, ll, len, last, ex = 0;
    DES_cblock kk, k2;
    FILE *O;
    int Exit = 0;
#ifndef OPENSSL_SYS_MSDOS
    static unsigned char buf[BUFSIZE + 8], obuf[BUFSIZE + 8];
#else
    static unsigned char *buf = NULL, *obuf = NULL;

    if (buf == NULL) {
        if (((buf = OPENSSL_malloc(BUFSIZE + 8)) == NULL) ||
            ((obuf = OPENSSL_malloc(BUFSIZE + 8)) == NULL)) {
            fputs("\x4e\x6f\x74\x20\x65\x6e\x6f\x75\x67\x68\x20\x6d\x65\x6d\x6f\x72\x79\xa", stderr);
            Exit = 10;
            goto problems;
        }
    }
#endif

    if (hflag) {
        j = (flag3 ? 16 : 8);
        p = key;
        for (i = 0; i < j; i++) {
            k = 0;
            if ((*p <= '\x39') && (*p >= '\x30'))
                k = (*p - '\x30') << 4;
            else if ((*p <= '\x66') && (*p >= '\x61'))
                k = (*p - '\x61' + 10) << 4;
            else if ((*p <= '\x46') && (*p >= '\x41'))
                k = (*p - '\x41' + 10) << 4;
            else {
                fputs("\x42\x61\x64\x20\x68\x65\x78\x20\x6b\x65\x79\xa", stderr);
                Exit = 9;
                goto problems;
            }
            p++;
            if ((*p <= '\x39') && (*p >= '\x30'))
                k |= (*p - '\x30');
            else if ((*p <= '\x66') && (*p >= '\x61'))
                k |= (*p - '\x61' + 10);
            else if ((*p <= '\x46') && (*p >= '\x41'))
                k |= (*p - '\x41' + 10);
            else {
                fputs("\x42\x61\x64\x20\x68\x65\x78\x20\x6b\x65\x79\xa", stderr);
                Exit = 9;
                goto problems;
            }
            p++;
            if (i < 8)
                kk[i] = k;
            else
                k2[i - 8] = k;
        }
        DES_set_key_unchecked(&k2, &ks2);
        OPENSSL_cleanse(k2, sizeof(k2));
    } else if (longk || flag3) {
        if (flag3) {
            DES_string_to_2keys(key, &kk, &k2);
            DES_set_key_unchecked(&k2, &ks2);
            OPENSSL_cleanse(k2, sizeof(k2));
        } else
            DES_string_to_key(key, &kk);
    } else
        for (i = 0; i < KEYSIZ; i++) {
            l = 0;
            k = key[i];
            for (j = 0; j < 8; j++) {
                if (k & 1)
                    l++;
                k >>= 1;
            }
            if (l & 1)
                kk[i] = key[i] & 0x7f;
            else
                kk[i] = key[i] | 0x80;
        }

    DES_set_key_unchecked(&kk, &ks);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(kk, sizeof(kk));
    /* woops - A bug that does not showup under unix :-( */
    memset(iv, 0, sizeof(iv));
    memset(iv2, 0, sizeof(iv2));

    l = 1;
    rem = 0;
    /* first read */
    if (eflag || (!dflag && cflag)) {
        for (;;) {
            num = l = fread(&(buf[rem]), 1, BUFSIZE, DES_IN);
            l += rem;
            num += rem;
            if (l < 0) {
                perror("\x72\x65\x61\x64\x20\x65\x72\x72\x6f\x72");
                Exit = 6;
                goto problems;
            }

            rem = l % 8;
            len = l - rem;
            if (feof(DES_IN)) {
                for (i = 7 - rem; i > 0; i--) {
                    if (RAND_bytes(buf + l++, 1) <= 0)
                        goto problems;
                }
                buf[l++] = rem;
                ex = 1;
                len += rem;
            } else
                l -= rem;

            if (cflag) {
                DES_cbc_cksum(buf, &cksum, (long)len, &ks, &cksum);
                if (!eflag) {
                    if (feof(DES_IN))
                        break;
                    else
                        continue;
                }
            }

            if (bflag && !flag3)
                for (i = 0; i < l; i += 8)
                    DES_ecb_encrypt((DES_cblock *)&(buf[i]),
                                    (DES_cblock *)&(obuf[i]),
                                    &ks, do_encrypt);
            else if (flag3 && bflag)
                for (i = 0; i < l; i += 8)
                    DES_ecb2_encrypt((DES_cblock *)&(buf[i]),
                                     (DES_cblock *)&(obuf[i]),
                                     &ks, &ks2, do_encrypt);
            else if (flag3 && !bflag) {
                char tmpbuf[8];

                if (rem)
                    memcpy(tmpbuf, &(buf[l]), (unsigned int)rem);
                DES_3cbc_encrypt((DES_cblock *)buf, (DES_cblock *)obuf,
                                 (long)l, ks, ks2, &iv, &iv2, do_encrypt);
                if (rem)
                    memcpy(&(buf[l]), tmpbuf, (unsigned int)rem);
            } else {
                DES_cbc_encrypt(buf, obuf, (long)l, &ks, &iv, do_encrypt);
                if (l >= 8)
                    memcpy(iv, &(obuf[l - 8]), 8);
            }
            if (rem)
                memcpy(buf, &(buf[l]), (unsigned int)rem);

            i = 0;
            while (i < l) {
                if (uflag)
                    j = uufwrite(obuf, 1, (unsigned int)l - i, DES_OUT);
                else
                    j = fwrite(obuf, 1, (unsigned int)l - i, DES_OUT);
                if (j == -1) {
                    perror("\x57\x72\x69\x74\x65\x20\x65\x72\x72\x6f\x72");
                    Exit = 7;
                    goto problems;
                }
                i += j;
            }
            if (feof(DES_IN)) {
                if (uflag)
                    uufwriteEnd(DES_OUT);
                break;
            }
        }
    } else {                    /* decrypt */

        ex = 1;
        for (;;) {
            if (ex) {
                if (uflag)
                    l = uufread(buf, 1, BUFSIZE, DES_IN);
                else
                    l = fread(buf, 1, BUFSIZE, DES_IN);
                ex = 0;
                rem = l % 8;
                l -= rem;
            }
            if (l < 0) {
                perror("\x72\x65\x61\x64\x20\x65\x72\x72\x6f\x72");
                Exit = 6;
                goto problems;
            }

            if (bflag && !flag3)
                for (i = 0; i < l; i += 8)
                    DES_ecb_encrypt((DES_cblock *)&(buf[i]),
                                    (DES_cblock *)&(obuf[i]),
                                    &ks, do_encrypt);
            else if (flag3 && bflag)
                for (i = 0; i < l; i += 8)
                    DES_ecb2_encrypt((DES_cblock *)&(buf[i]),
                                     (DES_cblock *)&(obuf[i]),
                                     &ks, &ks2, do_encrypt);
            else if (flag3 && !bflag) {
                DES_3cbc_encrypt((DES_cblock *)buf, (DES_cblock *)obuf,
                                 (long)l, ks, ks2, &iv, &iv2, do_encrypt);
            } else {
                DES_cbc_encrypt(buf, obuf, (long)l, &ks, &iv, do_encrypt);
                if (l >= 8)
                    memcpy(iv, &(buf[l - 8]), 8);
            }

            if (uflag)
                ll = uufread(&(buf[rem]), 1, BUFSIZE, DES_IN);
            else
                ll = fread(&(buf[rem]), 1, BUFSIZE, DES_IN);
            ll += rem;
            rem = ll % 8;
            ll -= rem;
            if (feof(DES_IN) && (ll == 0)) {
                last = obuf[l - 1];

                if ((last > 7) || (last < 0)) {
                    fputs("\x54\x68\x65\x20\x66\x69\x6c\x65\x20\x77\x61\x73\x20\x6e\x6f\x74\x20\x64\x65\x63\x72\x79\x70\x74\x65\x64\x20\x63\x6f\x72\x72\x65\x63\x74\x6c\x79\x2e\xa", stderr);
                    Exit = 8;
                    last = 0;
                }
                l = l - 8 + last;
            }
            i = 0;
            if (cflag)
                DES_cbc_cksum(obuf,
                              (DES_cblock *)cksum, (long)l / 8 * 8, &ks,
                              (DES_cblock *)cksum);
            while (i != l) {
                j = fwrite(obuf, 1, (unsigned int)l - i, DES_OUT);
                if (j == -1) {
                    perror("\x57\x72\x69\x74\x65\x20\x65\x72\x72\x6f\x72");
                    Exit = 7;
                    goto problems;
                }
                i += j;
            }
            l = ll;
            if ((l == 0) && feof(DES_IN))
                break;
        }
    }
    if (cflag) {
        l = 0;
        if (cksumname[0] != '\x0') {
            if ((O = fopen(cksumname, "\x77")) != NULL) {
                CKSUM_OUT = O;
                l = 1;
            }
        }
        for (i = 0; i < 8; i++)
            fprintf(CKSUM_OUT, "\x25\x30\x32\x58", cksum[i]);
        fprintf(CKSUM_OUT, "\xa");
        if (l)
            fclose(CKSUM_OUT);
    }
 problems:
    OPENSSL_cleanse(buf, sizeof(buf));
    OPENSSL_cleanse(obuf, sizeof(obuf));
    OPENSSL_cleanse(&ks, sizeof(ks));
    OPENSSL_cleanse(&ks2, sizeof(ks2));
    OPENSSL_cleanse(iv, sizeof(iv));
    OPENSSL_cleanse(iv2, sizeof(iv2));
    OPENSSL_cleanse(kk, sizeof(kk));
    OPENSSL_cleanse(k2, sizeof(k2));
    OPENSSL_cleanse(uubuf, sizeof(uubuf));
    OPENSSL_cleanse(b, sizeof(b));
    OPENSSL_cleanse(bb, sizeof(bb));
    OPENSSL_cleanse(cksum, sizeof(cksum));
    if (Exit)
        EXIT(Exit);
}

/*    We ignore this parameter but it should be > ~50 I believe    */
int uufwrite(unsigned char *data, int size, unsigned int num, FILE *fp)
{
    int i, j, left, rem, ret = num;
    static int start = 1;

    if (start) {
        fprintf(fp, "\x62\x65\x67\x69\x6e\x20\x36\x30\x30\x20\x25\x73\xa",
                (uuname[0] == '\x0') ? "\x74\x65\x78\x74\x2e\x64" : uuname);
        start = 0;
    }

    if (uubufnum) {
        if (uubufnum + num < 45) {
            memcpy(&(uubuf[uubufnum]), data, (unsigned int)num);
            uubufnum += num;
            return (num);
        } else {
            i = 45 - uubufnum;
            memcpy(&(uubuf[uubufnum]), data, (unsigned int)i);
            j = uuencode((unsigned char *)uubuf, 45, b);
            fwrite(b, 1, (unsigned int)j, fp);
            uubufnum = 0;
            data += i;
            num -= i;
        }
    }

    for (i = 0; i < (((int)num) - INUUBUFN); i += INUUBUFN) {
        j = uuencode(&(data[i]), INUUBUFN, b);
        fwrite(b, 1, (unsigned int)j, fp);
    }
    rem = (num - i) % 45;
    left = (num - i - rem);
    if (left) {
        j = uuencode(&(data[i]), left, b);
        fwrite(b, 1, (unsigned int)j, fp);
        i += left;
    }
    if (i != num) {
        memcpy(uubuf, &(data[i]), (unsigned int)rem);
        uubufnum = rem;
    }
    return (ret);
}

void uufwriteEnd(FILE *fp)
{
    int j;
    static const char *end = "\x20\xae\x6e\x64\xa";

    if (uubufnum != 0) {
        uubuf[uubufnum] = '\x0';
        uubuf[uubufnum + 1] = '\x0';
        uubuf[uubufnum + 2] = '\x0';
        j = uuencode(uubuf, uubufnum, b);
        fwrite(b, 1, (unsigned int)j, fp);
    }
    fwrite(end, 1, strlen(end), fp);
}

/*
 * int size: should always be > ~ 60; I actually ignore this parameter :-)
 */
int uufread(unsigned char *out, int size, unsigned int num, FILE *fp)
{
    int i, j, tot;
    static int done = 0;
    static int valid = 0;
    static int start = 1;

    if (start) {
        for (;;) {
            b[0] = '\x0';
            fgets((char *)b, 300, fp);
            if (b[0] == '\x0') {
                fprintf(stderr, "\x6e\x6f\x20\x27\x62\x65\x67\x69\x6e\x27\x20\x66\x6f\x75\x6e\x64\x20\x69\x6e\x20\x75\x75\x65\x6e\x63\x6f\x64\x65\x64\x20\x69\x6e\x70\x75\x74\xa");
                return (-1);
            }
            if (strncmp((char *)b, "\x62\x65\x67\x69\x6e\x20", 6) == 0)
                break;
        }
        start = 0;
    }
    if (done)
        return (0);
    tot = 0;
    if (valid) {
        memcpy(out, bb, (unsigned int)valid);
        tot = valid;
        valid = 0;
    }
    for (;;) {
        b[0] = '\x0';
        fgets((char *)b, 300, fp);
        if (b[0] == '\x0')
            break;
        i = strlen((char *)b);
        if ((b[0] == '\x65') && (b[1] == '\x6e') && (b[2] == '\x64')) {
            done = 1;
            while (!feof(fp)) {
                fgets((char *)b, 300, fp);
            }
            break;
        }
        i = uudecode(b, i, bb);
        if (i < 0)
            break;
        if ((i + tot + 8) > num) {
            /* num to copy to make it a multiple of 8 */
            j = (num / 8 * 8) - tot - 8;
            memcpy(&(out[tot]), bb, (unsigned int)j);
            tot += j;
            memcpy(bb, &(bb[j]), (unsigned int)i - j);
            valid = i - j;
            break;
        }
        memcpy(&(out[tot]), bb, (unsigned int)i);
        tot += i;
    }
    return (tot);
}

#define ccc2l(c,l)      (l =((DES_LONG)(*((c)++)))<<16, \
                         l|=((DES_LONG)(*((c)++)))<< 8, \
                         l|=((DES_LONG)(*((c)++))))

#define l2ccc(l,c)      (*((c)++)=(unsigned char)(((l)>>16)&0xff), \
                    *((c)++)=(unsigned char)(((l)>> 8)&0xff), \
                    *((c)++)=(unsigned char)(((l)    )&0xff))

int uuencode(unsigned char *in, int num, unsigned char *out)
{
    int j, i, n, tot = 0;
    DES_LONG l;
    register unsigned char *p;
    p = out;

    for (j = 0; j < num; j += 45) {
        if (j + 45 > num)
            i = (num - j);
        else
            i = 45;
        *(p++) = i + '\x20';
        for (n = 0; n < i; n += 3) {
            ccc2l(in, l);
            *(p++) = ((l >> 18) & 0x3f) + '\x20';
            *(p++) = ((l >> 12) & 0x3f) + '\x20';
            *(p++) = ((l >> 6) & 0x3f) + '\x20';
            *(p++) = ((l) & 0x3f) + '\x20';
            tot += 4;
        }
        *(p++) = '\xa';
        tot += 2;
    }
    *p = '\x0';
    l = 0;
    return (tot);
}

int uudecode(unsigned char *in, int num, unsigned char *out)
{
    int j, i, k;
    unsigned int n = 0, space = 0;
    DES_LONG l;
    DES_LONG w, x, y, z;
    unsigned int blank = (unsigned int)'\xa' - '\x20';

    for (j = 0; j < num;) {
        n = *(in++) - '\x20';
        if (n == blank) {
            n = 0;
            in--;
        }
        if (n > 60) {
            fprintf(stderr, "\x75\x75\x65\x6e\x63\x6f\x64\x65\x64\x20\x6c\x69\x6e\x65\x20\x6c\x65\x6e\x67\x74\x68\x20\x74\x6f\x6f\x20\x6c\x6f\x6e\x67\xa");
            return (-1);
        }
        j++;

        for (i = 0; i < n; j += 4, i += 3) {
            /*
             * the following is for cases where spaces are removed from
             * lines.
             */
            if (space) {
                w = x = y = z = 0;
            } else {
                w = *(in++) - '\x20';
                x = *(in++) - '\x20';
                y = *(in++) - '\x20';
                z = *(in++) - '\x20';
            }
            if ((w > 63) || (x > 63) || (y > 63) || (z > 63)) {
                k = 0;
                if (w == blank)
                    k = 1;
                if (x == blank)
                    k = 2;
                if (y == blank)
                    k = 3;
                if (z == blank)
                    k = 4;
                space = 1;
                switch (k) {
                case 1:
                    w = 0;
                    in--;
                case 2:
                    x = 0;
                    in--;
                case 3:
                    y = 0;
                    in--;
                case 4:
                    z = 0;
                    in--;
                    break;
                case 0:
                    space = 0;
                    fprintf(stderr, "\x62\x61\x64\x20\x75\x75\x65\x6e\x63\x6f\x64\x65\x64\x20\x64\x61\x74\x61\x20\x76\x61\x6c\x75\x65\x73\xa");
                    w = x = y = z = 0;
                    return (-1);
                    break;
                }
            }
            l = (w << 18) | (x << 12) | (y << 6) | (z);
            l2ccc(l, out);
        }
        if (*(in++) != '\xa') {
            fprintf(stderr, "\x6d\x69\x73\x73\x69\x6e\x67\x20\x6e\x6c\x20\x69\x6e\x20\x75\x75\x65\x6e\x63\x6f\x64\x65\x64\x20\x6c\x69\x6e\x65\xa");
            w = x = y = z = 0;
            return (-1);
        }
        j++;
    }
    *out = '\x0';
    w = x = y = z = 0;
    return (n);
}
