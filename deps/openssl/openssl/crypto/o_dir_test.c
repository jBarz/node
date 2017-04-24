/* crypto/o_dir.h */
/*
 * Copied from Richard Levitte's (richard@levitte.org) LP library.  All
 * symbol names have been changed, with permission from the author.
 */

/* $LP: LPlib/test/test_dir.c,v 1.1 2004/06/16 22:59:47 _cvs_levitte Exp $ */
/*
 * Copyright (c) 2004, Richard Levitte <richard@levitte.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include "e_os2.h"
#include "o_dir.h"

#if defined OPENSSL_SYS_UNIX || defined OPENSSL_SYS_WIN32 || defined OPENSSL_SYS_WINCE
# define CURRDIR "\x2e"
#elif defined OPENSSL_SYS_VMS
# define CURRDIR "\x53\x59\x53\x24\x44\x49\x53\x4b\x3a\x5b\x5d"
#else
# error "\x4e\x6f\x20\x73\x75\x70\x70\x6f\x72\x74\x65\x64\x20\x70\x6c\x61\x74\x66\x6f\x72\x6d\x20\x64\x65\x66\x69\x6e\x65\x64\x21"
#endif

int main()
{
    OPENSSL_DIR_CTX *ctx = NULL;
    const char *result;

    while ((result = OPENSSL_DIR_read(&ctx, CURRDIR)) != NULL) {
        printf("\x25\x73\xa", result);
    }

    if (errno) {
        perror("\x74\x65\x73\x74\x5f\x64\x69\x72");
        exit(1);
    }

    if (!OPENSSL_DIR_end(&ctx)) {
        perror("\x74\x65\x73\x74\x5f\x64\x69\x72");
        exit(2);
    }
    exit(0);
}
