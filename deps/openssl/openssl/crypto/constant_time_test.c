/* crypto/constant_time_test.c */
/*-
 * Utilities for constant-time cryptography.
 *
 * Author: Emilia Kasper (emilia@openssl.org)
 * Based on previous work by Bodo Moeller, Emilia Kasper, Adam Langley
 * (Google).
 * ====================================================================
 * Copyright (c) 2014 The OpenSSL Project.  All rights reserved.
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

#include "../crypto/constant_time_locl.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

static const unsigned int CONSTTIME_TRUE = (unsigned)(~0);
static const unsigned int CONSTTIME_FALSE = 0;
static const unsigned char CONSTTIME_TRUE_8 = 0xff;
static const unsigned char CONSTTIME_FALSE_8 = 0;

static int test_binary_op(unsigned int (*op) (unsigned int a, unsigned int b),
                          const char *op_name, unsigned int a, unsigned int b,
                          int is_true)
{
    unsigned c = op(a, b);
    if (is_true && c != CONSTTIME_TRUE) {
        fprintf(stderr, "\x54\x65\x73\x74\x20\x66\x61\x69\x6c\x65\x64\x20\x66\x6f\x72\x20\x25\x73\x28\x25\x64\x75\x2c\x20\x25\x64\x75\x29\x3a\x20\x65\x78\x70\x65\x63\x74\x65\x64\x20\x25\x64\x75\x20"
                "\x28\x54\x52\x55\x45\x29\x2c\x20\x67\x6f\x74\x20\x25\x64\x75\xa", op_name, a, b, CONSTTIME_TRUE, c);
        return 1;
    } else if (!is_true && c != CONSTTIME_FALSE) {
        fprintf(stderr, "\x54\x65\x73\x74\x20\x66\x61\x69\x6c\x65\x64\x20\x66\x6f\x72\x20\x20\x25\x73\x28\x25\x64\x75\x2c\x20\x25\x64\x75\x29\x3a\x20\x65\x78\x70\x65\x63\x74\x65\x64\x20\x25\x64\x75\x20"
                "\x28\x46\x41\x4c\x53\x45\x29\x2c\x20\x67\x6f\x74\x20\x25\x64\x75\xa", op_name, a, b, CONSTTIME_FALSE, c);
        return 1;
    }
    return 0;
}

static int test_binary_op_8(unsigned
                            char (*op) (unsigned int a, unsigned int b),
                            const char *op_name, unsigned int a,
                            unsigned int b, int is_true)
{
    unsigned char c = op(a, b);
    if (is_true && c != CONSTTIME_TRUE_8) {
        fprintf(stderr, "\x54\x65\x73\x74\x20\x66\x61\x69\x6c\x65\x64\x20\x66\x6f\x72\x20\x25\x73\x28\x25\x64\x75\x2c\x20\x25\x64\x75\x29\x3a\x20\x65\x78\x70\x65\x63\x74\x65\x64\x20\x25\x75\x20"
                "\x28\x54\x52\x55\x45\x29\x2c\x20\x67\x6f\x74\x20\x25\x75\xa", op_name, a, b, CONSTTIME_TRUE_8, c);
        return 1;
    } else if (!is_true && c != CONSTTIME_FALSE_8) {
        fprintf(stderr, "\x54\x65\x73\x74\x20\x66\x61\x69\x6c\x65\x64\x20\x66\x6f\x72\x20\x20\x25\x73\x28\x25\x64\x75\x2c\x20\x25\x64\x75\x29\x3a\x20\x65\x78\x70\x65\x63\x74\x65\x64\x20\x25\x75\x20"
                "\x28\x46\x41\x4c\x53\x45\x29\x2c\x20\x67\x6f\x74\x20\x25\x75\xa", op_name, a, b, CONSTTIME_FALSE_8, c);
        return 1;
    }
    return 0;
}

static int test_is_zero(unsigned int a)
{
    unsigned int c = constant_time_is_zero(a);
    if (a == 0 && c != CONSTTIME_TRUE) {
        fprintf(stderr, "\x54\x65\x73\x74\x20\x66\x61\x69\x6c\x65\x64\x20\x66\x6f\x72\x20\x63\x6f\x6e\x73\x74\x61\x6e\x74\x5f\x74\x69\x6d\x65\x5f\x69\x73\x5f\x7a\x65\x72\x6f\x28\x25\x64\x75\x29\x3a\x20"
                "\x65\x78\x70\x65\x63\x74\x65\x64\x20\x25\x64\x75\x20\x28\x54\x52\x55\x45\x29\x2c\x20\x67\x6f\x74\x20\x25\x64\x75\xa", a, CONSTTIME_TRUE, c);
        return 1;
    } else if (a != 0 && c != CONSTTIME_FALSE) {
        fprintf(stderr, "\x54\x65\x73\x74\x20\x66\x61\x69\x6c\x65\x64\x20\x66\x6f\x72\x20\x63\x6f\x6e\x73\x74\x61\x6e\x74\x5f\x74\x69\x6d\x65\x5f\x69\x73\x5f\x7a\x65\x72\x6f\x28\x25\x64\x75\x29\x3a\x20"
                "\x65\x78\x70\x65\x63\x74\x65\x64\x20\x25\x64\x75\x20\x28\x46\x41\x4c\x53\x45\x29\x2c\x20\x67\x6f\x74\x20\x25\x64\x75\xa", a, CONSTTIME_FALSE, c);
        return 1;
    }
    return 0;
}

static int test_is_zero_8(unsigned int a)
{
    unsigned char c = constant_time_is_zero_8(a);
    if (a == 0 && c != CONSTTIME_TRUE_8) {
        fprintf(stderr, "\x54\x65\x73\x74\x20\x66\x61\x69\x6c\x65\x64\x20\x66\x6f\x72\x20\x63\x6f\x6e\x73\x74\x61\x6e\x74\x5f\x74\x69\x6d\x65\x5f\x69\x73\x5f\x7a\x65\x72\x6f\x28\x25\x64\x75\x29\x3a\x20"
                "\x65\x78\x70\x65\x63\x74\x65\x64\x20\x25\x75\x20\x28\x54\x52\x55\x45\x29\x2c\x20\x67\x6f\x74\x20\x25\x75\xa", a, CONSTTIME_TRUE_8, c);
        return 1;
    } else if (a != 0 && c != CONSTTIME_FALSE) {
        fprintf(stderr, "\x54\x65\x73\x74\x20\x66\x61\x69\x6c\x65\x64\x20\x66\x6f\x72\x20\x63\x6f\x6e\x73\x74\x61\x6e\x74\x5f\x74\x69\x6d\x65\x5f\x69\x73\x5f\x7a\x65\x72\x6f\x28\x25\x64\x75\x29\x3a\x20"
                "\x65\x78\x70\x65\x63\x74\x65\x64\x20\x25\x75\x20\x28\x46\x41\x4c\x53\x45\x29\x2c\x20\x67\x6f\x74\x20\x25\x75\xa", a, CONSTTIME_FALSE_8, c);
        return 1;
    }
    return 0;
}

static int test_select(unsigned int a, unsigned int b)
{
    unsigned int selected = constant_time_select(CONSTTIME_TRUE, a, b);
    if (selected != a) {
        fprintf(stderr, "\x54\x65\x73\x74\x20\x66\x61\x69\x6c\x65\x64\x20\x66\x6f\x72\x20\x63\x6f\x6e\x73\x74\x61\x6e\x74\x5f\x74\x69\x6d\x65\x5f\x73\x65\x6c\x65\x63\x74\x28\x25\x64\x75\x2c\x20\x25\x64\x75\x2c"
                "\x25\x64\x75\x29\x3a\x20\x65\x78\x70\x65\x63\x74\x65\x64\x20\x25\x64\x75\x28\x66\x69\x72\x73\x74\x20\x76\x61\x6c\x75\x65\x29\x2c\x20\x67\x6f\x74\x20\x25\x64\x75\xa",
                CONSTTIME_TRUE, a, b, a, selected);
        return 1;
    }
    selected = constant_time_select(CONSTTIME_FALSE, a, b);
    if (selected != b) {
        fprintf(stderr, "\x54\x65\x73\x74\x20\x66\x61\x69\x6c\x65\x64\x20\x66\x6f\x72\x20\x63\x6f\x6e\x73\x74\x61\x6e\x74\x5f\x74\x69\x6d\x65\x5f\x73\x65\x6c\x65\x63\x74\x28\x25\x64\x75\x2c\x20\x25\x64\x75\x2c"
                "\x25\x64\x75\x29\x3a\x20\x65\x78\x70\x65\x63\x74\x65\x64\x20\x25\x64\x75\x28\x73\x65\x63\x6f\x6e\x64\x20\x76\x61\x6c\x75\x65\x29\x2c\x20\x67\x6f\x74\x20\x25\x64\x75\xa",
                CONSTTIME_FALSE, a, b, b, selected);
        return 1;
    }
    return 0;
}

static int test_select_8(unsigned char a, unsigned char b)
{
    unsigned char selected = constant_time_select_8(CONSTTIME_TRUE_8, a, b);
    if (selected != a) {
        fprintf(stderr, "\x54\x65\x73\x74\x20\x66\x61\x69\x6c\x65\x64\x20\x66\x6f\x72\x20\x63\x6f\x6e\x73\x74\x61\x6e\x74\x5f\x74\x69\x6d\x65\x5f\x73\x65\x6c\x65\x63\x74\x28\x25\x75\x2c\x20\x25\x75\x2c"
                "\x25\x75\x29\x3a\x20\x65\x78\x70\x65\x63\x74\x65\x64\x20\x25\x75\x28\x66\x69\x72\x73\x74\x20\x76\x61\x6c\x75\x65\x29\x2c\x20\x67\x6f\x74\x20\x25\x75\xa",
                CONSTTIME_TRUE, a, b, a, selected);
        return 1;
    }
    selected = constant_time_select_8(CONSTTIME_FALSE_8, a, b);
    if (selected != b) {
        fprintf(stderr, "\x54\x65\x73\x74\x20\x66\x61\x69\x6c\x65\x64\x20\x66\x6f\x72\x20\x63\x6f\x6e\x73\x74\x61\x6e\x74\x5f\x74\x69\x6d\x65\x5f\x73\x65\x6c\x65\x63\x74\x28\x25\x75\x2c\x20\x25\x75\x2c"
                "\x25\x75\x29\x3a\x20\x65\x78\x70\x65\x63\x74\x65\x64\x20\x25\x75\x28\x73\x65\x63\x6f\x6e\x64\x20\x76\x61\x6c\x75\x65\x29\x2c\x20\x67\x6f\x74\x20\x25\x75\xa",
                CONSTTIME_FALSE, a, b, b, selected);
        return 1;
    }
    return 0;
}

static int test_select_int(int a, int b)
{
    int selected = constant_time_select_int(CONSTTIME_TRUE, a, b);
    if (selected != a) {
        fprintf(stderr, "\x54\x65\x73\x74\x20\x66\x61\x69\x6c\x65\x64\x20\x66\x6f\x72\x20\x63\x6f\x6e\x73\x74\x61\x6e\x74\x5f\x74\x69\x6d\x65\x5f\x73\x65\x6c\x65\x63\x74\x28\x25\x64\x75\x2c\x20\x25\x64\x2c"
                "\x25\x64\x29\x3a\x20\x65\x78\x70\x65\x63\x74\x65\x64\x20\x25\x64\x28\x66\x69\x72\x73\x74\x20\x76\x61\x6c\x75\x65\x29\x2c\x20\x67\x6f\x74\x20\x25\x64\xa",
                CONSTTIME_TRUE, a, b, a, selected);
        return 1;
    }
    selected = constant_time_select_int(CONSTTIME_FALSE, a, b);
    if (selected != b) {
        fprintf(stderr, "\x54\x65\x73\x74\x20\x66\x61\x69\x6c\x65\x64\x20\x66\x6f\x72\x20\x63\x6f\x6e\x73\x74\x61\x6e\x74\x5f\x74\x69\x6d\x65\x5f\x73\x65\x6c\x65\x63\x74\x28\x25\x64\x75\x2c\x20\x25\x64\x2c"
                "\x25\x64\x29\x3a\x20\x65\x78\x70\x65\x63\x74\x65\x64\x20\x25\x64\x28\x73\x65\x63\x6f\x6e\x64\x20\x76\x61\x6c\x75\x65\x29\x2c\x20\x67\x6f\x74\x20\x25\x64\xa",
                CONSTTIME_FALSE, a, b, b, selected);
        return 1;
    }
    return 0;
}

static int test_eq_int(int a, int b)
{
    unsigned int equal = constant_time_eq_int(a, b);
    if (a == b && equal != CONSTTIME_TRUE) {
        fprintf(stderr, "\x54\x65\x73\x74\x20\x66\x61\x69\x6c\x65\x64\x20\x66\x6f\x72\x20\x63\x6f\x6e\x73\x74\x61\x6e\x74\x5f\x74\x69\x6d\x65\x5f\x65\x71\x5f\x69\x6e\x74\x28\x25\x64\x2c\x20\x25\x64\x29\x3a\x20"
                "\x65\x78\x70\x65\x63\x74\x65\x64\x20\x25\x64\x75\x28\x54\x52\x55\x45\x29\x2c\x20\x67\x6f\x74\x20\x25\x64\x75\xa", a, b, CONSTTIME_TRUE, equal);
        return 1;
    } else if (a != b && equal != CONSTTIME_FALSE) {
        fprintf(stderr, "\x54\x65\x73\x74\x20\x66\x61\x69\x6c\x65\x64\x20\x66\x6f\x72\x20\x63\x6f\x6e\x73\x74\x61\x6e\x74\x5f\x74\x69\x6d\x65\x5f\x65\x71\x5f\x69\x6e\x74\x28\x25\x64\x2c\x20\x25\x64\x29\x3a\x20"
                "\x65\x78\x70\x65\x63\x74\x65\x64\x20\x25\x64\x75\x28\x46\x41\x4c\x53\x45\x29\x2c\x20\x67\x6f\x74\x20\x25\x64\x75\xa",
                a, b, CONSTTIME_FALSE, equal);
        return 1;
    }
    return 0;
}

static int test_eq_int_8(int a, int b)
{
    unsigned char equal = constant_time_eq_int_8(a, b);
    if (a == b && equal != CONSTTIME_TRUE_8) {
        fprintf(stderr, "\x54\x65\x73\x74\x20\x66\x61\x69\x6c\x65\x64\x20\x66\x6f\x72\x20\x63\x6f\x6e\x73\x74\x61\x6e\x74\x5f\x74\x69\x6d\x65\x5f\x65\x71\x5f\x69\x6e\x74\x5f\x38\x28\x25\x64\x2c\x20\x25\x64\x29\x3a\x20"
                "\x65\x78\x70\x65\x63\x74\x65\x64\x20\x25\x75\x28\x54\x52\x55\x45\x29\x2c\x20\x67\x6f\x74\x20\x25\x75\xa", a, b, CONSTTIME_TRUE_8, equal);
        return 1;
    } else if (a != b && equal != CONSTTIME_FALSE_8) {
        fprintf(stderr, "\x54\x65\x73\x74\x20\x66\x61\x69\x6c\x65\x64\x20\x66\x6f\x72\x20\x63\x6f\x6e\x73\x74\x61\x6e\x74\x5f\x74\x69\x6d\x65\x5f\x65\x71\x5f\x69\x6e\x74\x5f\x38\x28\x25\x64\x2c\x20\x25\x64\x29\x3a\x20"
                "\x65\x78\x70\x65\x63\x74\x65\x64\x20\x25\x75\x28\x46\x41\x4c\x53\x45\x29\x2c\x20\x67\x6f\x74\x20\x25\x75\xa",
                a, b, CONSTTIME_FALSE_8, equal);
        return 1;
    }
    return 0;
}

static unsigned int test_values[] =
    { 0, 1, 1024, 12345, 32000, UINT_MAX / 2 - 1,
    UINT_MAX / 2, UINT_MAX / 2 + 1, UINT_MAX - 1,
    UINT_MAX
};

static unsigned char test_values_8[] =
    { 0, 1, 2, 20, 32, 127, 128, 129, 255 };

static int signed_test_values[] = { 0, 1, -1, 1024, -1024, 12345, -12345,
    32000, -32000, INT_MAX, INT_MIN, INT_MAX - 1,
    INT_MIN + 1
};

int main(int argc, char *argv[])
{
    unsigned int a, b, i, j;
    int c, d;
    unsigned char e, f;
    int num_failed = 0, num_all = 0;
    fprintf(stdout, "\x54\x65\x73\x74\x69\x6e\x67\x20\x63\x6f\x6e\x73\x74\x61\x6e\x74\x20\x74\x69\x6d\x65\x20\x6f\x70\x65\x72\x61\x74\x69\x6f\x6e\x73\x2e\x2e\x2e\xa");

    for (i = 0; i < sizeof(test_values) / sizeof(int); ++i) {
        a = test_values[i];
        num_failed += test_is_zero(a);
        num_failed += test_is_zero_8(a);
        num_all += 2;
        for (j = 0; j < sizeof(test_values) / sizeof(int); ++j) {
            b = test_values[j];
            num_failed += test_binary_op(&constant_time_lt,
                                         "\x63\x6f\x6e\x73\x74\x61\x6e\x74\x5f\x74\x69\x6d\x65\x5f\x6c\x74", a, b, a < b);
            num_failed += test_binary_op_8(&constant_time_lt_8,
                                           "\x63\x6f\x6e\x73\x74\x61\x6e\x74\x5f\x74\x69\x6d\x65\x5f\x6c\x74\x5f\x38", a, b, a < b);
            num_failed += test_binary_op(&constant_time_lt,
                                         "\x63\x6f\x6e\x73\x74\x61\x6e\x74\x5f\x74\x69\x6d\x65\x5f\x6c\x74\x5f\x38", b, a, b < a);
            num_failed += test_binary_op_8(&constant_time_lt_8,
                                           "\x63\x6f\x6e\x73\x74\x61\x6e\x74\x5f\x74\x69\x6d\x65\x5f\x6c\x74\x5f\x38", b, a, b < a);
            num_failed += test_binary_op(&constant_time_ge,
                                         "\x63\x6f\x6e\x73\x74\x61\x6e\x74\x5f\x74\x69\x6d\x65\x5f\x67\x65", a, b, a >= b);
            num_failed += test_binary_op_8(&constant_time_ge_8,
                                           "\x63\x6f\x6e\x73\x74\x61\x6e\x74\x5f\x74\x69\x6d\x65\x5f\x67\x65\x5f\x38", a, b,
                                           a >= b);
            num_failed +=
                test_binary_op(&constant_time_ge, "\x63\x6f\x6e\x73\x74\x61\x6e\x74\x5f\x74\x69\x6d\x65\x5f\x67\x65", b, a,
                               b >= a);
            num_failed +=
                test_binary_op_8(&constant_time_ge_8, "\x63\x6f\x6e\x73\x74\x61\x6e\x74\x5f\x74\x69\x6d\x65\x5f\x67\x65\x5f\x38", b,
                                 a, b >= a);
            num_failed +=
                test_binary_op(&constant_time_eq, "\x63\x6f\x6e\x73\x74\x61\x6e\x74\x5f\x74\x69\x6d\x65\x5f\x65\x71", a, b,
                               a == b);
            num_failed +=
                test_binary_op_8(&constant_time_eq_8, "\x63\x6f\x6e\x73\x74\x61\x6e\x74\x5f\x74\x69\x6d\x65\x5f\x65\x71\x5f\x38", a,
                                 b, a == b);
            num_failed +=
                test_binary_op(&constant_time_eq, "\x63\x6f\x6e\x73\x74\x61\x6e\x74\x5f\x74\x69\x6d\x65\x5f\x65\x71", b, a,
                               b == a);
            num_failed +=
                test_binary_op_8(&constant_time_eq_8, "\x63\x6f\x6e\x73\x74\x61\x6e\x74\x5f\x74\x69\x6d\x65\x5f\x65\x71\x5f\x38", b,
                                 a, b == a);
            num_failed += test_select(a, b);
            num_all += 13;
        }
    }

    for (i = 0; i < sizeof(signed_test_values) / sizeof(int); ++i) {
        c = signed_test_values[i];
        for (j = 0; j < sizeof(signed_test_values) / sizeof(int); ++j) {
            d = signed_test_values[j];
            num_failed += test_select_int(c, d);
            num_failed += test_eq_int(c, d);
            num_failed += test_eq_int_8(c, d);
            num_all += 3;
        }
    }

    for (i = 0; i < sizeof(test_values_8); ++i) {
        e = test_values_8[i];
        for (j = 0; j < sizeof(test_values_8); ++j) {
            f = test_values_8[j];
            num_failed += test_select_8(e, f);
            num_all += 1;
        }
    }

    if (!num_failed) {
        fprintf(stdout, "\x6f\x6b\x20\x28\x72\x61\x6e\x20\x25\x64\x20\x74\x65\x73\x74\x73\x29\xa", num_all);
        return EXIT_SUCCESS;
    } else {
        fprintf(stdout, "\x25\x64\x20\x6f\x66\x20\x25\x64\x20\x74\x65\x73\x74\x73\x20\x66\x61\x69\x6c\x65\x64\x21\xa", num_failed, num_all);
        return EXIT_FAILURE;
    }
}
