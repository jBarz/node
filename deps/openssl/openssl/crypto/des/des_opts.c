/* crypto/des/des_opts.c */
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
 * define PART1, PART2, PART3 or PART4 to build only with a few of the
 * options. This is for machines with 64k code segment size restrictions.
 */

#if !defined(OPENSSL_SYS_MSDOS) && (!defined(OPENSSL_SYS_VMS) || defined(__DECC)) && !defined(OPENSSL_SYS_MACOSX)
# define TIMES
#endif

#include <stdio.h>
#ifndef OPENSSL_SYS_MSDOS
# include <openssl/e_os2.h>
# include OPENSSL_UNISTD
#else
# include <io.h>
extern void exit();
#endif

#ifndef OPENSSL_SYS_NETWARE
# include <signal.h>
#endif

#ifndef _IRIX
# include <time.h>
#endif
#ifdef TIMES
# include <sys/types.h>
# include <sys/times.h>
#endif

/*
 * Depending on the VMS version, the tms structure is perhaps defined. The
 * __TMS macro will show if it was.  If it wasn't defined, we should undefine
 * TIMES, since that tells the rest of the program how things should be
 * handled.  -- Richard Levitte
 */
#if defined(OPENSSL_SYS_VMS_DECC) && !defined(__TMS)
# undef TIMES
#endif

#ifndef TIMES
# include <sys/timeb.h>
#endif

#if defined(sun) || defined(__ultrix)
# define _POSIX_SOURCE
# include <limits.h>
# include <sys/param.h>
#endif

#include <openssl/des.h>
#include "spr.h"

#define DES_DEFAULT_OPTIONS

#if !defined(PART1) && !defined(PART2) && !defined(PART3) && !defined(PART4)
# define PART1
# define PART2
# define PART3
# define PART4
#endif

#ifdef PART1

# undef DES_UNROLL
# undef DES_RISC1
# undef DES_RISC2
# undef DES_PTR
# undef D_ENCRYPT
# define DES_encrypt1 des_encrypt_u4_cisc_idx
# define DES_encrypt2 des_encrypt2_u4_cisc_idx
# define DES_encrypt3 des_encrypt3_u4_cisc_idx
# define DES_decrypt3 des_decrypt3_u4_cisc_idx
# undef HEADER_DES_LOCL_H
# include "des_enc.c"

# define DES_UNROLL
# undef DES_RISC1
# undef DES_RISC2
# undef DES_PTR
# undef D_ENCRYPT
# undef DES_encrypt1
# undef DES_encrypt2
# undef DES_encrypt3
# undef DES_decrypt3
# define DES_encrypt1 des_encrypt_u16_cisc_idx
# define DES_encrypt2 des_encrypt2_u16_cisc_idx
# define DES_encrypt3 des_encrypt3_u16_cisc_idx
# define DES_decrypt3 des_decrypt3_u16_cisc_idx
# undef HEADER_DES_LOCL_H
# include "des_enc.c"

# undef DES_UNROLL
# define DES_RISC1
# undef DES_RISC2
# undef DES_PTR
# undef D_ENCRYPT
# undef DES_encrypt1
# undef DES_encrypt2
# undef DES_encrypt3
# undef DES_decrypt3
# define DES_encrypt1 des_encrypt_u4_risc1_idx
# define DES_encrypt2 des_encrypt2_u4_risc1_idx
# define DES_encrypt3 des_encrypt3_u4_risc1_idx
# define DES_decrypt3 des_decrypt3_u4_risc1_idx
# undef HEADER_DES_LOCL_H
# include "des_enc.c"

#endif

#ifdef PART2

# undef DES_UNROLL
# undef DES_RISC1
# define DES_RISC2
# undef DES_PTR
# undef D_ENCRYPT
# undef DES_encrypt1
# undef DES_encrypt2
# undef DES_encrypt3
# undef DES_decrypt3
# define DES_encrypt1 des_encrypt_u4_risc2_idx
# define DES_encrypt2 des_encrypt2_u4_risc2_idx
# define DES_encrypt3 des_encrypt3_u4_risc2_idx
# define DES_decrypt3 des_decrypt3_u4_risc2_idx
# undef HEADER_DES_LOCL_H
# include "des_enc.c"

# define DES_UNROLL
# define DES_RISC1
# undef DES_RISC2
# undef DES_PTR
# undef D_ENCRYPT
# undef DES_encrypt1
# undef DES_encrypt2
# undef DES_encrypt3
# undef DES_decrypt3
# define DES_encrypt1 des_encrypt_u16_risc1_idx
# define DES_encrypt2 des_encrypt2_u16_risc1_idx
# define DES_encrypt3 des_encrypt3_u16_risc1_idx
# define DES_decrypt3 des_decrypt3_u16_risc1_idx
# undef HEADER_DES_LOCL_H
# include "des_enc.c"

# define DES_UNROLL
# undef DES_RISC1
# define DES_RISC2
# undef DES_PTR
# undef D_ENCRYPT
# undef DES_encrypt1
# undef DES_encrypt2
# undef DES_encrypt3
# undef DES_decrypt3
# define DES_encrypt1 des_encrypt_u16_risc2_idx
# define DES_encrypt2 des_encrypt2_u16_risc2_idx
# define DES_encrypt3 des_encrypt3_u16_risc2_idx
# define DES_decrypt3 des_decrypt3_u16_risc2_idx
# undef HEADER_DES_LOCL_H
# include "des_enc.c"

#endif

#ifdef PART3

# undef DES_UNROLL
# undef DES_RISC1
# undef DES_RISC2
# define DES_PTR
# undef D_ENCRYPT
# undef DES_encrypt1
# undef DES_encrypt2
# undef DES_encrypt3
# undef DES_decrypt3
# define DES_encrypt1 des_encrypt_u4_cisc_ptr
# define DES_encrypt2 des_encrypt2_u4_cisc_ptr
# define DES_encrypt3 des_encrypt3_u4_cisc_ptr
# define DES_decrypt3 des_decrypt3_u4_cisc_ptr
# undef HEADER_DES_LOCL_H
# include "des_enc.c"

# define DES_UNROLL
# undef DES_RISC1
# undef DES_RISC2
# define DES_PTR
# undef D_ENCRYPT
# undef DES_encrypt1
# undef DES_encrypt2
# undef DES_encrypt3
# undef DES_decrypt3
# define DES_encrypt1 des_encrypt_u16_cisc_ptr
# define DES_encrypt2 des_encrypt2_u16_cisc_ptr
# define DES_encrypt3 des_encrypt3_u16_cisc_ptr
# define DES_decrypt3 des_decrypt3_u16_cisc_ptr
# undef HEADER_DES_LOCL_H
# include "des_enc.c"

# undef DES_UNROLL
# define DES_RISC1
# undef DES_RISC2
# define DES_PTR
# undef D_ENCRYPT
# undef DES_encrypt1
# undef DES_encrypt2
# undef DES_encrypt3
# undef DES_decrypt3
# define DES_encrypt1 des_encrypt_u4_risc1_ptr
# define DES_encrypt2 des_encrypt2_u4_risc1_ptr
# define DES_encrypt3 des_encrypt3_u4_risc1_ptr
# define DES_decrypt3 des_decrypt3_u4_risc1_ptr
# undef HEADER_DES_LOCL_H
# include "des_enc.c"

#endif

#ifdef PART4

# undef DES_UNROLL
# undef DES_RISC1
# define DES_RISC2
# define DES_PTR
# undef D_ENCRYPT
# undef DES_encrypt1
# undef DES_encrypt2
# undef DES_encrypt3
# undef DES_decrypt3
# define DES_encrypt1 des_encrypt_u4_risc2_ptr
# define DES_encrypt2 des_encrypt2_u4_risc2_ptr
# define DES_encrypt3 des_encrypt3_u4_risc2_ptr
# define DES_decrypt3 des_decrypt3_u4_risc2_ptr
# undef HEADER_DES_LOCL_H
# include "des_enc.c"

# define DES_UNROLL
# define DES_RISC1
# undef DES_RISC2
# define DES_PTR
# undef D_ENCRYPT
# undef DES_encrypt1
# undef DES_encrypt2
# undef DES_encrypt3
# undef DES_decrypt3
# define DES_encrypt1 des_encrypt_u16_risc1_ptr
# define DES_encrypt2 des_encrypt2_u16_risc1_ptr
# define DES_encrypt3 des_encrypt3_u16_risc1_ptr
# define DES_decrypt3 des_decrypt3_u16_risc1_ptr
# undef HEADER_DES_LOCL_H
# include "des_enc.c"

# define DES_UNROLL
# undef DES_RISC1
# define DES_RISC2
# define DES_PTR
# undef D_ENCRYPT
# undef DES_encrypt1
# undef DES_encrypt2
# undef DES_encrypt3
# undef DES_decrypt3
# define DES_encrypt1 des_encrypt_u16_risc2_ptr
# define DES_encrypt2 des_encrypt2_u16_risc2_ptr
# define DES_encrypt3 des_encrypt3_u16_risc2_ptr
# define DES_decrypt3 des_decrypt3_u16_risc2_ptr
# undef HEADER_DES_LOCL_H
# include "des_enc.c"

#endif

/* The following if from times(3) man page.  It may need to be changed */
#ifndef HZ
# ifndef CLK_TCK
#  ifndef _BSD_CLK_TCK_         /* FreeBSD fix */
#   define HZ   100.0
#  else                         /* _BSD_CLK_TCK_ */
#   define HZ ((double)_BSD_CLK_TCK_)
#  endif
# else                          /* CLK_TCK */
#  define HZ ((double)CLK_TCK)
# endif
#endif

#define BUFSIZE ((long)1024)
long run = 0;

double Time_F(int s);
#ifdef SIGALRM
# if defined(__STDC__) || defined(sgi)
#  define SIGRETTYPE void
# else
#  define SIGRETTYPE int
# endif

SIGRETTYPE sig_done(int sig);
SIGRETTYPE sig_done(int sig)
{
    signal(SIGALRM, sig_done);
    run = 0;
# ifdef LINT
    sig = sig;
# endif
}
#endif

#define START   0
#define STOP    1

double Time_F(int s)
{
    double ret;
#ifdef TIMES
    static struct tms tstart, tend;

    if (s == START) {
        times(&tstart);
        return (0);
    } else {
        times(&tend);
        ret = ((double)(tend.tms_utime - tstart.tms_utime)) / HZ;
        return ((ret == 0.0) ? 1e-6 : ret);
    }
#else                           /* !times() */
    static struct timeb tstart, tend;
    long i;

    if (s == START) {
        ftime(&tstart);
        return (0);
    } else {
        ftime(&tend);
        i = (long)tend.millitm - (long)tstart.millitm;
        ret = ((double)(tend.time - tstart.time)) + ((double)i) / 1000.0;
        return ((ret == 0.0) ? 1e-6 : ret);
    }
#endif
}

#ifdef SIGALRM
# define print_name(name) fprintf(stderr,"\x44\x6f\x69\x6e\x67\x20\x25\x73\x27\x73\x20\x66\x6f\x72\x20\x31\x30\x20\x73\x65\x63\x6f\x6e\x64\x73\xa",name); alarm(10);
#else
# define print_name(name) fprintf(stderr,"\x44\x6f\x69\x6e\x67\x20\x25\x73\x20\x25\x6c\x64\x20\x74\x69\x6d\x65\x73\xa",name,cb);
#endif

#define time_it(func,name,index) \
        print_name(name); \
        Time_F(START); \
        for (count=0,run=1; COND(cb); count++) \
                { \
                unsigned long d[2]; \
                func(d,&sch,DES_ENCRYPT); \
                } \
        tm[index]=Time_F(STOP); \
        fprintf(stderr,"\x25\x6c\x64\x20\x25\x73\x27\x73\x20\x69\x6e\x20\x25\x2e\x32\x66\x20\x73\x65\x63\x6f\x6e\x64\xa",count,name,tm[index]); \
        tm[index]=((double)COUNT(cb))/tm[index];

#define print_it(name,index) \
        fprintf(stderr,"\x25\x73\x20\x62\x79\x74\x65\x73\x20\x70\x65\x72\x20\x73\x65\x63\x20\x3d\x20\x25\x31\x32\x2e\x32\x66\x20\x28\x25\x35\x2e\x31\x66\x75\x53\x29\xa",name, \
                tm[index]*8,1.0e6/tm[index]);

int main(int argc, char **argv)
{
    long count;
    static unsigned char buf[BUFSIZE];
    static DES_cblock key =
        { 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 };
    static DES_cblock key2 =
        { 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12 };
    static DES_cblock key3 =
        { 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34 };
    DES_key_schedule sch, sch2, sch3;
    double d, tm[16], max = 0;
    int rank[16];
    char *str[16];
    int max_idx = 0, i, num = 0, j;
#ifndef SIGALARM
    long ca, cb, cc, cd, ce;
#endif

    for (i = 0; i < 12; i++) {
        tm[i] = 0.0;
        rank[i] = 0;
    }

#ifndef TIMES
    fprintf(stderr, "\x54\x6f\x20\x67\x65\x74\x20\x74\x68\x65\x20\x6d\x6f\x73\x74\x20\x61\x63\x63\x75\x72\x61\x74\x65\x20\x72\x65\x73\x75\x6c\x74\x73\x2c\x20\x74\x72\x79\x20\x74\x6f\x20\x72\x75\x6e\x20\x74\x68\x69\x73\xa");
    fprintf(stderr, "\x70\x72\x6f\x67\x72\x61\x6d\x20\x77\x68\x65\x6e\x20\x74\x68\x69\x73\x20\x63\x6f\x6d\x70\x75\x74\x65\x72\x20\x69\x73\x20\x69\x64\x6c\x65\x2e\xa");
#endif

    DES_set_key_unchecked(&key, &sch);
    DES_set_key_unchecked(&key2, &sch2);
    DES_set_key_unchecked(&key3, &sch3);

#ifndef SIGALRM
    fprintf(stderr, "\x46\x69\x72\x73\x74\x20\x77\x65\x20\x63\x61\x6c\x63\x75\x6c\x61\x74\x65\x20\x74\x68\x65\x20\x61\x70\x70\x72\x6f\x78\x69\x6d\x61\x74\x65\x20\x73\x70\x65\x65\x64\x20\x2e\x2e\x2e\xa");
    DES_set_key_unchecked(&key, sch);
    count = 10;
    do {
        long i;
        unsigned long data[2];

        count *= 2;
        Time_F(START);
        for (i = count; i; i--)
            DES_encrypt1(data, &(sch[0]), DES_ENCRYPT);
        d = Time_F(STOP);
    } while (d < 3.0);
    ca = count;
    cb = count * 3;
    cc = count * 3 * 8 / BUFSIZE + 1;
    cd = count * 8 / BUFSIZE + 1;

    ce = count / 20 + 1;
# define COND(d) (count != (d))
# define COUNT(d) (d)
#else
# define COND(c) (run)
# define COUNT(d) (count)
    signal(SIGALRM, sig_done);
    alarm(10);
#endif

#ifdef PART1
    time_it(des_encrypt_u4_cisc_idx, "\x64\x65\x73\x5f\x65\x6e\x63\x72\x79\x70\x74\x5f\x75\x34\x5f\x63\x69\x73\x63\x5f\x69\x64\x78\x20\x20", 0);
    time_it(des_encrypt_u16_cisc_idx, "\x64\x65\x73\x5f\x65\x6e\x63\x72\x79\x70\x74\x5f\x75\x31\x36\x5f\x63\x69\x73\x63\x5f\x69\x64\x78\x20", 1);
    time_it(des_encrypt_u4_risc1_idx, "\x64\x65\x73\x5f\x65\x6e\x63\x72\x79\x70\x74\x5f\x75\x34\x5f\x72\x69\x73\x63\x31\x5f\x69\x64\x78\x20", 2);
    num += 3;
#endif
#ifdef PART2
    time_it(des_encrypt_u16_risc1_idx, "\x64\x65\x73\x5f\x65\x6e\x63\x72\x79\x70\x74\x5f\x75\x31\x36\x5f\x72\x69\x73\x63\x31\x5f\x69\x64\x78", 3);
    time_it(des_encrypt_u4_risc2_idx, "\x64\x65\x73\x5f\x65\x6e\x63\x72\x79\x70\x74\x5f\x75\x34\x5f\x72\x69\x73\x63\x32\x5f\x69\x64\x78\x20", 4);
    time_it(des_encrypt_u16_risc2_idx, "\x64\x65\x73\x5f\x65\x6e\x63\x72\x79\x70\x74\x5f\x75\x31\x36\x5f\x72\x69\x73\x63\x32\x5f\x69\x64\x78", 5);
    num += 3;
#endif
#ifdef PART3
    time_it(des_encrypt_u4_cisc_ptr, "\x64\x65\x73\x5f\x65\x6e\x63\x72\x79\x70\x74\x5f\x75\x34\x5f\x63\x69\x73\x63\x5f\x70\x74\x72\x20\x20", 6);
    time_it(des_encrypt_u16_cisc_ptr, "\x64\x65\x73\x5f\x65\x6e\x63\x72\x79\x70\x74\x5f\x75\x31\x36\x5f\x63\x69\x73\x63\x5f\x70\x74\x72\x20", 7);
    time_it(des_encrypt_u4_risc1_ptr, "\x64\x65\x73\x5f\x65\x6e\x63\x72\x79\x70\x74\x5f\x75\x34\x5f\x72\x69\x73\x63\x31\x5f\x70\x74\x72\x20", 8);
    num += 3;
#endif
#ifdef PART4
    time_it(des_encrypt_u16_risc1_ptr, "\x64\x65\x73\x5f\x65\x6e\x63\x72\x79\x70\x74\x5f\x75\x31\x36\x5f\x72\x69\x73\x63\x31\x5f\x70\x74\x72", 9);
    time_it(des_encrypt_u4_risc2_ptr, "\x64\x65\x73\x5f\x65\x6e\x63\x72\x79\x70\x74\x5f\x75\x34\x5f\x72\x69\x73\x63\x32\x5f\x70\x74\x72\x20", 10);
    time_it(des_encrypt_u16_risc2_ptr, "\x64\x65\x73\x5f\x65\x6e\x63\x72\x79\x70\x74\x5f\x75\x31\x36\x5f\x72\x69\x73\x63\x32\x5f\x70\x74\x72", 11);
    num += 3;
#endif

#ifdef PART1
    str[0] = "\x20\x34\x20\x20\x63\x20\x69";
    print_it("\x64\x65\x73\x5f\x65\x6e\x63\x72\x79\x70\x74\x5f\x75\x34\x5f\x63\x69\x73\x63\x5f\x69\x64\x78\x20\x20", 0);
    max = tm[0];
    max_idx = 0;
    str[1] = "\x31\x36\x20\x20\x63\x20\x69";
    print_it("\x64\x65\x73\x5f\x65\x6e\x63\x72\x79\x70\x74\x5f\x75\x31\x36\x5f\x63\x69\x73\x63\x5f\x69\x64\x78\x20", 1);
    if (max < tm[1]) {
        max = tm[1];
        max_idx = 1;
    }
    str[2] = "\x20\x34\x20\x72\x31\x20\x69";
    print_it("\x64\x65\x73\x5f\x65\x6e\x63\x72\x79\x70\x74\x5f\x75\x34\x5f\x72\x69\x73\x63\x31\x5f\x69\x64\x78\x20", 2);
    if (max < tm[2]) {
        max = tm[2];
        max_idx = 2;
    }
#endif
#ifdef PART2
    str[3] = "\x31\x36\x20\x72\x31\x20\x69";
    print_it("\x64\x65\x73\x5f\x65\x6e\x63\x72\x79\x70\x74\x5f\x75\x31\x36\x5f\x72\x69\x73\x63\x31\x5f\x69\x64\x78", 3);
    if (max < tm[3]) {
        max = tm[3];
        max_idx = 3;
    }
    str[4] = "\x20\x34\x20\x72\x32\x20\x69";
    print_it("\x64\x65\x73\x5f\x65\x6e\x63\x72\x79\x70\x74\x5f\x75\x34\x5f\x72\x69\x73\x63\x32\x5f\x69\x64\x78\x20", 4);
    if (max < tm[4]) {
        max = tm[4];
        max_idx = 4;
    }
    str[5] = "\x31\x36\x20\x72\x32\x20\x69";
    print_it("\x64\x65\x73\x5f\x65\x6e\x63\x72\x79\x70\x74\x5f\x75\x31\x36\x5f\x72\x69\x73\x63\x32\x5f\x69\x64\x78", 5);
    if (max < tm[5]) {
        max = tm[5];
        max_idx = 5;
    }
#endif
#ifdef PART3
    str[6] = "\x20\x34\x20\x20\x63\x20\x70";
    print_it("\x64\x65\x73\x5f\x65\x6e\x63\x72\x79\x70\x74\x5f\x75\x34\x5f\x63\x69\x73\x63\x5f\x70\x74\x72\x20\x20", 6);
    if (max < tm[6]) {
        max = tm[6];
        max_idx = 6;
    }
    str[7] = "\x31\x36\x20\x20\x63\x20\x70";
    print_it("\x64\x65\x73\x5f\x65\x6e\x63\x72\x79\x70\x74\x5f\x75\x31\x36\x5f\x63\x69\x73\x63\x5f\x70\x74\x72\x20", 7);
    if (max < tm[7]) {
        max = tm[7];
        max_idx = 7;
    }
    str[8] = "\x20\x34\x20\x72\x31\x20\x70";
    print_it("\x64\x65\x73\x5f\x65\x6e\x63\x72\x79\x70\x74\x5f\x75\x34\x5f\x72\x69\x73\x63\x31\x5f\x70\x74\x72\x20", 8);
    if (max < tm[8]) {
        max = tm[8];
        max_idx = 8;
    }
#endif
#ifdef PART4
    str[9] = "\x31\x36\x20\x72\x31\x20\x70";
    print_it("\x64\x65\x73\x5f\x65\x6e\x63\x72\x79\x70\x74\x5f\x75\x31\x36\x5f\x72\x69\x73\x63\x31\x5f\x70\x74\x72", 9);
    if (max < tm[9]) {
        max = tm[9];
        max_idx = 9;
    }
    str[10] = "\x20\x34\x20\x72\x32\x20\x70";
    print_it("\x64\x65\x73\x5f\x65\x6e\x63\x72\x79\x70\x74\x5f\x75\x34\x5f\x72\x69\x73\x63\x32\x5f\x70\x74\x72\x20", 10);
    if (max < tm[10]) {
        max = tm[10];
        max_idx = 10;
    }
    str[11] = "\x31\x36\x20\x72\x32\x20\x70";
    print_it("\x64\x65\x73\x5f\x65\x6e\x63\x72\x79\x70\x74\x5f\x75\x31\x36\x5f\x72\x69\x73\x63\x32\x5f\x70\x74\x72", 11);
    if (max < tm[11]) {
        max = tm[11];
        max_idx = 11;
    }
#endif
    printf("\x6f\x70\x74\x69\x6f\x6e\x73\x20\x20\x20\x20\x64\x65\x73\x20\x65\x63\x62\x2f\x73\xa");
    printf("\x25\x73\x20\x25\x31\x32\x2e\x32\x66\x20\x31\x30\x30\x2e\x30\x25\x25\xa", str[max_idx], tm[max_idx]);
    d = tm[max_idx];
    tm[max_idx] = -2.0;
    max = -1.0;
    for (;;) {
        for (i = 0; i < 12; i++) {
            if (max < tm[i]) {
                max = tm[i];
                j = i;
            }
        }
        if (max < 0.0)
            break;
        printf("\x25\x73\x20\x25\x31\x32\x2e\x32\x66\x20\x20\x25\x34\x2e\x31\x66\x25\x25\xa", str[j], tm[j], tm[j] / d * 100.0);
        tm[j] = -2.0;
        max = -1.0;
    }

    switch (max_idx) {
    case 0:
        printf("\x2d\x44\x44\x45\x53\x5f\x44\x45\x46\x41\x55\x4c\x54\x5f\x4f\x50\x54\x49\x4f\x4e\x53\xa");
        break;
    case 1:
        printf("\x2d\x44\x44\x45\x53\x5f\x55\x4e\x52\x4f\x4c\x4c\xa");
        break;
    case 2:
        printf("\x2d\x44\x44\x45\x53\x5f\x52\x49\x53\x43\x31\xa");
        break;
    case 3:
        printf("\x2d\x44\x44\x45\x53\x5f\x55\x4e\x52\x4f\x4c\x4c\x20\x2d\x44\x44\x45\x53\x5f\x52\x49\x53\x43\x31\xa");
        break;
    case 4:
        printf("\x2d\x44\x44\x45\x53\x5f\x52\x49\x53\x43\x32\xa");
        break;
    case 5:
        printf("\x2d\x44\x44\x45\x53\x5f\x55\x4e\x52\x4f\x4c\x4c\x20\x2d\x44\x44\x45\x53\x5f\x52\x49\x53\x43\x32\xa");
        break;
    case 6:
        printf("\x2d\x44\x44\x45\x53\x5f\x50\x54\x52\xa");
        break;
    case 7:
        printf("\x2d\x44\x44\x45\x53\x5f\x55\x4e\x52\x4f\x4c\x4c\x20\x2d\x44\x44\x45\x53\x5f\x50\x54\x52\xa");
        break;
    case 8:
        printf("\x2d\x44\x44\x45\x53\x5f\x52\x49\x53\x43\x31\x20\x2d\x44\x44\x45\x53\x5f\x50\x54\x52\xa");
        break;
    case 9:
        printf("\x2d\x44\x44\x45\x53\x5f\x55\x4e\x52\x4f\x4c\x4c\x20\x2d\x44\x44\x45\x53\x5f\x52\x49\x53\x43\x31\x20\x2d\x44\x44\x45\x53\x5f\x50\x54\x52\xa");
        break;
    case 10:
        printf("\x2d\x44\x44\x45\x53\x5f\x52\x49\x53\x43\x32\x20\x2d\x44\x44\x45\x53\x5f\x50\x54\x52\xa");
        break;
    case 11:
        printf("\x2d\x44\x44\x45\x53\x5f\x55\x4e\x52\x4f\x4c\x4c\x20\x2d\x44\x44\x45\x53\x5f\x52\x49\x53\x43\x32\x20\x2d\x44\x44\x45\x53\x5f\x50\x54\x52\xa");
        break;
    }
    exit(0);
#if defined(LINT) || defined(OPENSSL_SYS_MSDOS)
    return (0);
#endif
}
