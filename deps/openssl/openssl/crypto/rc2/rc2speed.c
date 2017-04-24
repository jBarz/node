/* crypto/rc2/rc2speed.c */
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

/* 11-Sep-92 Andrew Daviel   Support for Silicon Graphics IRIX added */
/* 06-Apr-92 Luke Brennan    Support for VMS and add extra signal calls */

#if !defined(OPENSSL_SYS_MSDOS) && (!defined(OPENSSL_SYS_VMS) || defined(__DECC)) && !defined(OPENSSL_SYS_MACOSX)
# define TIMES
#endif

#include <stdio.h>

#include <openssl/e_os2.h>
#include OPENSSL_UNISTD_IO
OPENSSL_DECLARE_EXIT
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
     * Depending on the VMS version, the tms structure is perhaps defined.
     * The __TMS macro will show if it was.  If it wasn't defined, we should
     * undefine TIMES, since that tells the rest of the program how things
     * should be handled.  -- Richard Levitte
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
#include <openssl/rc2.h>
/* The following if from times(3) man page.  It may need to be changed */
#ifndef HZ
# ifndef CLK_TCK
#  define HZ      100.0
# else                          /* CLK_TCK */
#  define HZ ((double)CLK_TCK)
# endif                         /* CLK_TCK */
#endif                          /* HZ */
#define BUFSIZE ((long)1024)
long run = 0;

double Time_F(int s);
#ifdef SIGALRM
# if defined(__STDC__) || defined(sgi) || defined(_AIX)
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
        ret = ((double)(tend.time - tstart.time)) + ((double)i) / 1e3;
        return ((ret == 0.0) ? 1e-6 : ret);
    }
#endif
}

int main(int argc, char **argv)
{
    long count;
    static unsigned char buf[BUFSIZE];
    static unsigned char key[] = {
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    RC2_KEY sch;
    double a, b, c, d;
#ifndef SIGALRM
    long ca, cb, cc;
#endif

#ifndef TIMES
    printf("\x54\x6f\x20\x67\x65\x74\x20\x74\x68\x65\x20\x6d\x6f\x73\x74\x20\x61\x63\x63\x75\x72\x61\x74\x65\x20\x72\x65\x73\x75\x6c\x74\x73\x2c\x20\x74\x72\x79\x20\x74\x6f\x20\x72\x75\x6e\x20\x74\x68\x69\x73\xa");
    printf("\x70\x72\x6f\x67\x72\x61\x6d\x20\x77\x68\x65\x6e\x20\x74\x68\x69\x73\x20\x63\x6f\x6d\x70\x75\x74\x65\x72\x20\x69\x73\x20\x69\x64\x6c\x65\x2e\xa");
#endif

#ifndef SIGALRM
    printf("\x46\x69\x72\x73\x74\x20\x77\x65\x20\x63\x61\x6c\x63\x75\x6c\x61\x74\x65\x20\x74\x68\x65\x20\x61\x70\x70\x72\x6f\x78\x69\x6d\x61\x74\x65\x20\x73\x70\x65\x65\x64\x20\x2e\x2e\x2e\xa");
    RC2_set_key(&sch, 16, key, 128);
    count = 10;
    do {
        long i;
        unsigned long data[2];

        count *= 2;
        Time_F(START);
        for (i = count; i; i--)
            RC2_encrypt(data, &sch);
        d = Time_F(STOP);
    } while (d < 3.0);
    ca = count / 512;
    cb = count;
    cc = count * 8 / BUFSIZE + 1;
    printf("\x44\x6f\x69\x6e\x67\x20\x52\x43\x32\x5f\x73\x65\x74\x5f\x6b\x65\x79\x20\x25\x6c\x64\x20\x74\x69\x6d\x65\x73\xa", ca);
# define COND(d) (count != (d))
# define COUNT(d) (d)
#else
# define COND(c) (run)
# define COUNT(d) (count)
    signal(SIGALRM, sig_done);
    printf("\x44\x6f\x69\x6e\x67\x20\x52\x43\x32\x5f\x73\x65\x74\x5f\x6b\x65\x79\x20\x66\x6f\x72\x20\x31\x30\x20\x73\x65\x63\x6f\x6e\x64\x73\xa");
    alarm(10);
#endif

    Time_F(START);
    for (count = 0, run = 1; COND(ca); count += 4) {
        RC2_set_key(&sch, 16, key, 128);
        RC2_set_key(&sch, 16, key, 128);
        RC2_set_key(&sch, 16, key, 128);
        RC2_set_key(&sch, 16, key, 128);
    }
    d = Time_F(STOP);
    printf("\x25\x6c\x64\x20\x52\x43\x32\x5f\x73\x65\x74\x5f\x6b\x65\x79\x27\x73\x20\x69\x6e\x20\x25\x2e\x32\x66\x20\x73\x65\x63\x6f\x6e\x64\x73\xa", count, d);
    a = ((double)COUNT(ca)) / d;

#ifdef SIGALRM
    printf("\x44\x6f\x69\x6e\x67\x20\x52\x43\x32\x5f\x65\x6e\x63\x72\x79\x70\x74\x27\x73\x20\x66\x6f\x72\x20\x31\x30\x20\x73\x65\x63\x6f\x6e\x64\x73\xa");
    alarm(10);
#else
    printf("\x44\x6f\x69\x6e\x67\x20\x52\x43\x32\x5f\x65\x6e\x63\x72\x79\x70\x74\x20\x25\x6c\x64\x20\x74\x69\x6d\x65\x73\xa", cb);
#endif
    Time_F(START);
    for (count = 0, run = 1; COND(cb); count += 4) {
        unsigned long data[2];

        RC2_encrypt(data, &sch);
        RC2_encrypt(data, &sch);
        RC2_encrypt(data, &sch);
        RC2_encrypt(data, &sch);
    }
    d = Time_F(STOP);
    printf("\x25\x6c\x64\x20\x52\x43\x32\x5f\x65\x6e\x63\x72\x79\x70\x74\x27\x73\x20\x69\x6e\x20\x25\x2e\x32\x66\x20\x73\x65\x63\x6f\x6e\x64\xa", count, d);
    b = ((double)COUNT(cb) * 8) / d;

#ifdef SIGALRM
    printf("\x44\x6f\x69\x6e\x67\x20\x52\x43\x32\x5f\x63\x62\x63\x5f\x65\x6e\x63\x72\x79\x70\x74\x20\x6f\x6e\x20\x25\x6c\x64\x20\x62\x79\x74\x65\x20\x62\x6c\x6f\x63\x6b\x73\x20\x66\x6f\x72\x20\x31\x30\x20\x73\x65\x63\x6f\x6e\x64\x73\xa",
           BUFSIZE);
    alarm(10);
#else
    printf("\x44\x6f\x69\x6e\x67\x20\x52\x43\x32\x5f\x63\x62\x63\x5f\x65\x6e\x63\x72\x79\x70\x74\x20\x25\x6c\x64\x20\x74\x69\x6d\x65\x73\x20\x6f\x6e\x20\x25\x6c\x64\x20\x62\x79\x74\x65\x20\x62\x6c\x6f\x63\x6b\x73\xa", cc,
           BUFSIZE);
#endif
    Time_F(START);
    for (count = 0, run = 1; COND(cc); count++)
        RC2_cbc_encrypt(buf, buf, BUFSIZE, &sch, &(key[0]), RC2_ENCRYPT);
    d = Time_F(STOP);
    printf("\x25\x6c\x64\x20\x52\x43\x32\x5f\x63\x62\x63\x5f\x65\x6e\x63\x72\x79\x70\x74\x27\x73\x20\x6f\x66\x20\x25\x6c\x64\x20\x62\x79\x74\x65\x20\x62\x6c\x6f\x63\x6b\x73\x20\x69\x6e\x20\x25\x2e\x32\x66\x20\x73\x65\x63\x6f\x6e\x64\xa",
           count, BUFSIZE, d);
    c = ((double)COUNT(cc) * BUFSIZE) / d;

    printf("\x52\x43\x32\x20\x73\x65\x74\x5f\x6b\x65\x79\x20\x20\x20\x20\x20\x20\x20\x70\x65\x72\x20\x73\x65\x63\x20\x3d\x20\x25\x31\x32\x2e\x32\x66\x20\x28\x25\x39\x2e\x33\x66\x75\x53\x29\xa", a, 1.0e6 / a);
    printf("\x52\x43\x32\x20\x72\x61\x77\x20\x65\x63\x62\x20\x62\x79\x74\x65\x73\x20\x70\x65\x72\x20\x73\x65\x63\x20\x3d\x20\x25\x31\x32\x2e\x32\x66\x20\x28\x25\x39\x2e\x33\x66\x75\x53\x29\xa", b, 8.0e6 / b);
    printf("\x52\x43\x32\x20\x63\x62\x63\x20\x20\x20\x20\x20\x62\x79\x74\x65\x73\x20\x70\x65\x72\x20\x73\x65\x63\x20\x3d\x20\x25\x31\x32\x2e\x32\x66\x20\x28\x25\x39\x2e\x33\x66\x75\x53\x29\xa", c, 8.0e6 / c);
    exit(0);
#if defined(LINT) || defined(OPENSSL_SYS_MSDOS)
    return (0);
#endif
}
