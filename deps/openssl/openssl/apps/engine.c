/* apps/engine.c */
/*
 * Written by Richard Levitte <richard@levitte.org> for the OpenSSL project
 * 2000.
 */
/* ====================================================================
 * Copyright (c) 2000 The OpenSSL Project.  All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef OPENSSL_NO_STDIO
# define APPS_WIN16
#endif
#include "apps.h"
#include <openssl/err.h>
#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
# include <openssl/ssl.h>

# undef PROG
# define PROG    engine_main

static const char *engine_usage[] = {
    "\x75\x73\x61\x67\x65\x3a\x20\x65\x6e\x67\x69\x6e\x65\x20\x6f\x70\x74\x73\x20\x5b\x65\x6e\x67\x69\x6e\x65\x20\x2e\x2e\x2e\x5d\xa",
    "\x20\x2d\x76\x5b\x76\x5b\x76\x5b\x76\x5d\x5d\x5d\x20\x2d\x20\x76\x65\x72\x62\x6f\x73\x65\x20\x6d\x6f\x64\x65\x2c\x20\x66\x6f\x72\x20\x65\x61\x63\x68\x20\x65\x6e\x67\x69\x6e\x65\x2c\x20\x6c\x69\x73\x74\x20\x69\x74\x73\x20\x27\x63\x6f\x6e\x74\x72\x6f\x6c\x20\x63\x6f\x6d\x6d\x61\x6e\x64\x73\x27\xa",
    "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x76\x76\x20\x77\x69\x6c\x6c\x20\x61\x64\x64\x69\x74\x69\x6f\x6e\x61\x6c\x6c\x79\x20\x64\x69\x73\x70\x6c\x61\x79\x20\x65\x61\x63\x68\x20\x63\x6f\x6d\x6d\x61\x6e\x64\x27\x73\x20\x64\x65\x73\x63\x72\x69\x70\x74\x69\x6f\x6e\xa",
    "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x76\x76\x76\x20\x77\x69\x6c\x6c\x20\x61\x6c\x73\x6f\x20\x61\x64\x64\x20\x74\x68\x65\x20\x69\x6e\x70\x75\x74\x20\x66\x6c\x61\x67\x73\x20\x66\x6f\x72\x20\x65\x61\x63\x68\x20\x63\x6f\x6d\x6d\x61\x6e\x64\xa",
    "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x76\x76\x76\x76\x20\x77\x69\x6c\x6c\x20\x61\x6c\x73\x6f\x20\x73\x68\x6f\x77\x20\x69\x6e\x74\x65\x72\x6e\x61\x6c\x20\x69\x6e\x70\x75\x74\x20\x66\x6c\x61\x67\x73\xa",
    "\x20\x2d\x63\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x66\x6f\x72\x20\x65\x61\x63\x68\x20\x65\x6e\x67\x69\x6e\x65\x2c\x20\x61\x6c\x73\x6f\x20\x6c\x69\x73\x74\x20\x74\x68\x65\x20\x63\x61\x70\x61\x62\x69\x6c\x69\x74\x69\x65\x73\xa",
    "\x20\x2d\x74\x5b\x74\x5d\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x66\x6f\x72\x20\x65\x61\x63\x68\x20\x65\x6e\x67\x69\x6e\x65\x2c\x20\x63\x68\x65\x63\x6b\x20\x74\x68\x61\x74\x20\x74\x68\x65\x79\x20\x61\x72\x65\x20\x72\x65\x61\x6c\x6c\x79\x20\x61\x76\x61\x69\x6c\x61\x62\x6c\x65\xa",
    "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x74\x74\x20\x77\x69\x6c\x6c\x20\x64\x69\x73\x70\x6c\x61\x79\x20\x65\x72\x72\x6f\x72\x20\x74\x72\x61\x63\x65\x20\x66\x6f\x72\x20\x75\x6e\x61\x76\x61\x69\x6c\x61\x62\x6c\x65\x20\x65\x6e\x67\x69\x6e\x65\x73\xa",
    "\x20\x2d\x70\x72\x65\x20\x3c\x63\x6d\x64\x3e\x20\x20\x2d\x20\x72\x75\x6e\x73\x20\x63\x6f\x6d\x6d\x61\x6e\x64\x20\x27\x63\x6d\x64\x27\x20\x61\x67\x61\x69\x6e\x73\x74\x20\x74\x68\x65\x20\x45\x4e\x47\x49\x4e\x45\x20\x62\x65\x66\x6f\x72\x65\x20\x61\x6e\x79\x20\x61\x74\x74\x65\x6d\x70\x74\x73\xa",
    "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x74\x6f\x20\x6c\x6f\x61\x64\x20\x69\x74\x20\x28\x69\x66\x20\x2d\x74\x20\x69\x73\x20\x75\x73\x65\x64\x29\xa",
    "\x20\x2d\x70\x6f\x73\x74\x20\x3c\x63\x6d\x64\x3e\x20\x2d\x20\x72\x75\x6e\x73\x20\x63\x6f\x6d\x6d\x61\x6e\x64\x20\x27\x63\x6d\x64\x27\x20\x61\x67\x61\x69\x6e\x73\x74\x20\x74\x68\x65\x20\x45\x4e\x47\x49\x4e\x45\x20\x61\x66\x74\x65\x72\x20\x6c\x6f\x61\x64\x69\x6e\x67\x20\x69\x74\xa",
    "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x28\x6f\x6e\x6c\x79\x20\x75\x73\x65\x64\x20\x69\x66\x20\x2d\x74\x20\x69\x73\x20\x61\x6c\x73\x6f\x20\x70\x72\x6f\x76\x69\x64\x65\x64\x29\xa",
    "\x20\x4e\x42\x3a\x20\x2d\x70\x72\x65\x20\x61\x6e\x64\x20\x2d\x70\x6f\x73\x74\x20\x77\x69\x6c\x6c\x20\x62\x65\x20\x61\x70\x70\x6c\x69\x65\x64\x20\x74\x6f\x20\x61\x6c\x6c\x20\x45\x4e\x47\x49\x4e\x45\x73\x20\x73\x75\x70\x70\x6c\x69\x65\x64\x20\x6f\x6e\x20\x74\x68\x65\x20\x63\x6f\x6d\x6d\x61\x6e\x64\xa",
    "\x20\x6c\x69\x6e\x65\x2c\x20\x6f\x72\x20\x61\x6c\x6c\x20\x73\x75\x70\x70\x6f\x72\x74\x65\x64\x20\x45\x4e\x47\x49\x4e\x45\x73\x20\x69\x66\x20\x6e\x6f\x6e\x65\x20\x61\x72\x65\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\x2e\xa",
    "\x20\x45\x67\x2e\x20\x27\x2d\x70\x72\x65\x20\x22\x53\x4f\x5f\x50\x41\x54\x48\x3a\x2f\x6c\x69\x62\x2f\x6c\x69\x62\x64\x72\x69\x76\x65\x72\x2e\x73\x6f\x22\x27\x20\x63\x61\x6c\x6c\x73\x20\x63\x6f\x6d\x6d\x61\x6e\x64\x20\x22\x53\x4f\x5f\x50\x41\x54\x48\x22\x20\x77\x69\x74\x68\xa",
    "\x20\x61\x72\x67\x75\x6d\x65\x6e\x74\x20\x22\x2f\x6c\x69\x62\x2f\x6c\x69\x62\x64\x72\x69\x76\x65\x72\x2e\x73\x6f\x22\x2e\xa",
    NULL
};

static void identity(char *ptr)
{
    return;
}

static int append_buf(char **buf, const char *s, int *size, int step)
{
    if (*buf == NULL) {
        *size = step;
        *buf = OPENSSL_malloc(*size);
        if (*buf == NULL)
            return 0;
        **buf = '\x0';
    }

    if (strlen(*buf) + strlen(s) >= (unsigned int)*size) {
        *size += step;
        *buf = OPENSSL_realloc(*buf, *size);
    }

    if (*buf == NULL)
        return 0;

    if (**buf != '\x0')
        BUF_strlcat(*buf, "\x2c\x20", *size);
    BUF_strlcat(*buf, s, *size);

    return 1;
}

static int util_flags(BIO *bio_out, unsigned int flags, const char *indent)
{
    int started = 0, err = 0;
    /* Indent before displaying input flags */
    BIO_printf(bio_out, "\x25\x73\x25\x73\x28\x69\x6e\x70\x75\x74\x20\x66\x6c\x61\x67\x73\x29\x3a\x20", indent, indent);
    if (flags == 0) {
        BIO_printf(bio_out, "\x3c\x6e\x6f\x20\x66\x6c\x61\x67\x73\x3e\xa");
        return 1;
    }
    /*
     * If the object is internal, mark it in a way that shows instead of
     * having it part of all the other flags, even if it really is.
     */
    if (flags & ENGINE_CMD_FLAG_INTERNAL) {
        BIO_printf(bio_out, "\x5b\x49\x6e\x74\x65\x72\x6e\x61\x6c\x5d\x20");
    }

    if (flags & ENGINE_CMD_FLAG_NUMERIC) {
        BIO_printf(bio_out, "\x4e\x55\x4d\x45\x52\x49\x43");
        started = 1;
    }
    /*
     * Now we check that no combinations of the mutually exclusive NUMERIC,
     * STRING, and NO_INPUT flags have been used. Future flags that can be
     * OR'd together with these would need to added after these to preserve
     * the testing logic.
     */
    if (flags & ENGINE_CMD_FLAG_STRING) {
        if (started) {
            BIO_printf(bio_out, "\x7c");
            err = 1;
        }
        BIO_printf(bio_out, "\x53\x54\x52\x49\x4e\x47");
        started = 1;
    }
    if (flags & ENGINE_CMD_FLAG_NO_INPUT) {
        if (started) {
            BIO_printf(bio_out, "\x7c");
            err = 1;
        }
        BIO_printf(bio_out, "\x4e\x4f\x5f\x49\x4e\x50\x55\x54");
        started = 1;
    }
    /* Check for unknown flags */
    flags = flags & ~ENGINE_CMD_FLAG_NUMERIC &
        ~ENGINE_CMD_FLAG_STRING &
        ~ENGINE_CMD_FLAG_NO_INPUT & ~ENGINE_CMD_FLAG_INTERNAL;
    if (flags) {
        if (started)
            BIO_printf(bio_out, "\x7c");
        BIO_printf(bio_out, "\x3c\x30\x78\x25\x30\x34\x58\x3e", flags);
    }
    if (err)
        BIO_printf(bio_out, "\x20\x20\x3c\x69\x6c\x6c\x65\x67\x61\x6c\x20\x66\x6c\x61\x67\x73\x21\x3e");
    BIO_printf(bio_out, "\xa");
    return 1;
}

static int util_verbose(ENGINE *e, int verbose, BIO *bio_out,
                        const char *indent)
{
    static const int line_wrap = 78;
    int num;
    int ret = 0;
    char *name = NULL;
    char *desc = NULL;
    int flags;
    int xpos = 0;
    STACK_OF(OPENSSL_STRING) *cmds = NULL;
    if (!ENGINE_ctrl(e, ENGINE_CTRL_HAS_CTRL_FUNCTION, 0, NULL, NULL) ||
        ((num = ENGINE_ctrl(e, ENGINE_CTRL_GET_FIRST_CMD_TYPE,
                            0, NULL, NULL)) <= 0)) {
# if 0
        BIO_printf(bio_out, "\x25\x73\x3c\x6e\x6f\x20\x63\x6f\x6e\x74\x72\x6f\x6c\x20\x63\x6f\x6d\x6d\x61\x6e\x64\x73\x3e\xa", indent);
# endif
        return 1;
    }

    cmds = sk_OPENSSL_STRING_new_null();

    if (!cmds)
        goto err;
    do {
        int len;
        /* Get the command input flags */
        if ((flags = ENGINE_ctrl(e, ENGINE_CTRL_GET_CMD_FLAGS, num,
                                 NULL, NULL)) < 0)
            goto err;
        if (!(flags & ENGINE_CMD_FLAG_INTERNAL) || verbose >= 4) {
            /* Get the command name */
            if ((len = ENGINE_ctrl(e, ENGINE_CTRL_GET_NAME_LEN_FROM_CMD, num,
                                   NULL, NULL)) <= 0)
                goto err;
            if ((name = OPENSSL_malloc(len + 1)) == NULL)
                goto err;
            if (ENGINE_ctrl(e, ENGINE_CTRL_GET_NAME_FROM_CMD, num, name,
                            NULL) <= 0)
                goto err;
            /* Get the command description */
            if ((len = ENGINE_ctrl(e, ENGINE_CTRL_GET_DESC_LEN_FROM_CMD, num,
                                   NULL, NULL)) < 0)
                goto err;
            if (len > 0) {
                if ((desc = OPENSSL_malloc(len + 1)) == NULL)
                    goto err;
                if (ENGINE_ctrl(e, ENGINE_CTRL_GET_DESC_FROM_CMD, num, desc,
                                NULL) <= 0)
                    goto err;
            }
            /* Now decide on the output */
            if (xpos == 0)
                /* Do an indent */
                xpos = BIO_puts(bio_out, indent);
            else
                /* Otherwise prepend a ", " */
                xpos += BIO_printf(bio_out, "\x2c\x20");
            if (verbose == 1) {
                /*
                 * We're just listing names, comma-delimited
                 */
                if ((xpos > (int)strlen(indent)) &&
                    (xpos + (int)strlen(name) > line_wrap)) {
                    BIO_printf(bio_out, "\xa");
                    xpos = BIO_puts(bio_out, indent);
                }
                xpos += BIO_printf(bio_out, "\x25\x73", name);
            } else {
                /* We're listing names plus descriptions */
                BIO_printf(bio_out, "\x25\x73\x3a\x20\x25\x73\xa", name,
                           (desc == NULL) ? "\x3c\x6e\x6f\x20\x64\x65\x73\x63\x72\x69\x70\x74\x69\x6f\x6e\x3e" : desc);
                /* ... and sometimes input flags */
                if ((verbose >= 3) && !util_flags(bio_out, flags, indent))
                    goto err;
                xpos = 0;
            }
        }
        OPENSSL_free(name);
        name = NULL;
        if (desc) {
            OPENSSL_free(desc);
            desc = NULL;
        }
        /* Move to the next command */
        num = ENGINE_ctrl(e, ENGINE_CTRL_GET_NEXT_CMD_TYPE, num, NULL, NULL);
    } while (num > 0);
    if (xpos > 0)
        BIO_printf(bio_out, "\xa");
    ret = 1;
 err:
    if (cmds)
        sk_OPENSSL_STRING_pop_free(cmds, identity);
    if (name)
        OPENSSL_free(name);
    if (desc)
        OPENSSL_free(desc);
    return ret;
}

static void util_do_cmds(ENGINE *e, STACK_OF(OPENSSL_STRING) *cmds,
                         BIO *bio_out, const char *indent)
{
    int loop, res, num = sk_OPENSSL_STRING_num(cmds);

    if (num < 0) {
        BIO_printf(bio_out, "\x5b\x45\x72\x72\x6f\x72\x5d\x3a\x20\x69\x6e\x74\x65\x72\x6e\x61\x6c\x20\x73\x74\x61\x63\x6b\x20\x65\x72\x72\x6f\x72\xa");
        return;
    }
    for (loop = 0; loop < num; loop++) {
        char buf[256];
        const char *cmd, *arg;
        cmd = sk_OPENSSL_STRING_value(cmds, loop);
        res = 1;                /* assume success */
        /* Check if this command has no "\x3a\x61\x72\x67" */
        if ((arg = strstr(cmd, "\x3a")) == NULL) {
            if (!ENGINE_ctrl_cmd_string(e, cmd, NULL, 0))
                res = 0;
        } else {
            if ((int)(arg - cmd) > 254) {
                BIO_printf(bio_out, "\x5b\x45\x72\x72\x6f\x72\x5d\x3a\x20\x63\x6f\x6d\x6d\x61\x6e\x64\x20\x6e\x61\x6d\x65\x20\x74\x6f\x6f\x20\x6c\x6f\x6e\x67\xa");
                return;
            }
            memcpy(buf, cmd, (int)(arg - cmd));
            buf[arg - cmd] = '\x0';
            arg++;              /* Move past the "\x3a" */
            /* Call the command with the argument */
            if (!ENGINE_ctrl_cmd_string(e, buf, arg, 0))
                res = 0;
        }
        if (res)
            BIO_printf(bio_out, "\x5b\x53\x75\x63\x63\x65\x73\x73\x5d\x3a\x20\x25\x73\xa", cmd);
        else {
            BIO_printf(bio_out, "\x5b\x46\x61\x69\x6c\x75\x72\x65\x5d\x3a\x20\x25\x73\xa", cmd);
            ERR_print_errors(bio_out);
        }
    }
}

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    int ret = 1, i;
    const char **pp;
    int verbose = 0, list_cap = 0, test_avail = 0, test_avail_noise = 0;
    ENGINE *e;
    STACK_OF(OPENSSL_STRING) *engines = sk_OPENSSL_STRING_new_null();
    STACK_OF(OPENSSL_STRING) *pre_cmds = sk_OPENSSL_STRING_new_null();
    STACK_OF(OPENSSL_STRING) *post_cmds = sk_OPENSSL_STRING_new_null();
    int badops = 1;
    BIO *bio_out = NULL;
    const char *indent = "\x20\x20\x20\x20\x20";

    apps_startup();
    SSL_load_error_strings();

    if (bio_err == NULL)
        bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

    if (!load_config(bio_err, NULL))
        goto end;
    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
# ifdef OPENSSL_SYS_VMS
    {
        BIO *tmpbio = BIO_new(BIO_f_linebuffer());
        bio_out = BIO_push(tmpbio, bio_out);
    }
# endif

    argc--;
    argv++;
    while (argc >= 1) {
        if (strncmp(*argv, "\x2d\x76", 2) == 0) {
            if (strspn(*argv + 1, "\x76") < strlen(*argv + 1))
                goto skip_arg_loop;
            if ((verbose = strlen(*argv + 1)) > 4)
                goto skip_arg_loop;
        } else if (strcmp(*argv, "\x2d\x63") == 0)
            list_cap = 1;
        else if (strncmp(*argv, "\x2d\x74", 2) == 0) {
            test_avail = 1;
            if (strspn(*argv + 1, "\x74") < strlen(*argv + 1))
                goto skip_arg_loop;
            if ((test_avail_noise = strlen(*argv + 1) - 1) > 1)
                goto skip_arg_loop;
        } else if (strcmp(*argv, "\x2d\x70\x72\x65") == 0) {
            argc--;
            argv++;
            if (argc == 0)
                goto skip_arg_loop;
            sk_OPENSSL_STRING_push(pre_cmds, *argv);
        } else if (strcmp(*argv, "\x2d\x70\x6f\x73\x74") == 0) {
            argc--;
            argv++;
            if (argc == 0)
                goto skip_arg_loop;
            sk_OPENSSL_STRING_push(post_cmds, *argv);
        } else if ((strncmp(*argv, "\x2d\x68", 2) == 0) ||
                   (strcmp(*argv, "\x2d\x3f") == 0))
            goto skip_arg_loop;
        else
            sk_OPENSSL_STRING_push(engines, *argv);
        argc--;
        argv++;
    }
    /* Looks like everything went OK */
    badops = 0;
 skip_arg_loop:

    if (badops) {
        for (pp = engine_usage; (*pp != NULL); pp++)
            BIO_printf(bio_err, "\x25\x73", *pp);
        goto end;
    }

    if (sk_OPENSSL_STRING_num(engines) == 0) {
        for (e = ENGINE_get_first(); e != NULL; e = ENGINE_get_next(e)) {
            sk_OPENSSL_STRING_push(engines, (char *)ENGINE_get_id(e));
        }
    }

    for (i = 0; i < sk_OPENSSL_STRING_num(engines); i++) {
        const char *id = sk_OPENSSL_STRING_value(engines, i);
        if ((e = ENGINE_by_id(id)) != NULL) {
            const char *name = ENGINE_get_name(e);
            /*
             * Do "id" first, then "name". Easier to auto-parse.
             */
            BIO_printf(bio_out, "\x28\x25\x73\x29\x20\x25\x73\xa", id, name);
            util_do_cmds(e, pre_cmds, bio_out, indent);
            if (strcmp(ENGINE_get_id(e), id) != 0) {
                BIO_printf(bio_out, "\x4c\x6f\x61\x64\x65\x64\x3a\x20\x28\x25\x73\x29\x20\x25\x73\xa",
                           ENGINE_get_id(e), ENGINE_get_name(e));
            }
            if (list_cap) {
                int cap_size = 256;
                char *cap_buf = NULL;
                int k, n;
                const int *nids;
                ENGINE_CIPHERS_PTR fn_c;
                ENGINE_DIGESTS_PTR fn_d;
                ENGINE_PKEY_METHS_PTR fn_pk;

                if (ENGINE_get_RSA(e) != NULL
                    && !append_buf(&cap_buf, "\x52\x53\x41", &cap_size, 256))
                    goto end;
                if (ENGINE_get_DSA(e) != NULL
                    && !append_buf(&cap_buf, "\x44\x53\x41", &cap_size, 256))
                    goto end;
                if (ENGINE_get_DH(e) != NULL
                    && !append_buf(&cap_buf, "\x44\x48", &cap_size, 256))
                    goto end;
                if (ENGINE_get_RAND(e) != NULL
                    && !append_buf(&cap_buf, "\x52\x41\x4e\x44", &cap_size, 256))
                    goto end;

                fn_c = ENGINE_get_ciphers(e);
                if (!fn_c)
                    goto skip_ciphers;
                n = fn_c(e, NULL, &nids, 0);
                for (k = 0; k < n; ++k)
                    if (!append_buf(&cap_buf,
                                    OBJ_nid2sn(nids[k]), &cap_size, 256))
                        goto end;

 skip_ciphers:
                fn_d = ENGINE_get_digests(e);
                if (!fn_d)
                    goto skip_digests;
                n = fn_d(e, NULL, &nids, 0);
                for (k = 0; k < n; ++k)
                    if (!append_buf(&cap_buf,
                                    OBJ_nid2sn(nids[k]), &cap_size, 256))
                        goto end;

 skip_digests:
                fn_pk = ENGINE_get_pkey_meths(e);
                if (!fn_pk)
                    goto skip_pmeths;
                n = fn_pk(e, NULL, &nids, 0);
                for (k = 0; k < n; ++k)
                    if (!append_buf(&cap_buf,
                                    OBJ_nid2sn(nids[k]), &cap_size, 256))
                        goto end;
 skip_pmeths:
                if (cap_buf && (*cap_buf != '\x0'))
                    BIO_printf(bio_out, "\x20\x5b\x25\x73\x5d\xa", cap_buf);

                OPENSSL_free(cap_buf);
            }
            if (test_avail) {
                BIO_printf(bio_out, "\x25\x73", indent);
                if (ENGINE_init(e)) {
                    BIO_printf(bio_out, "\x5b\x20\x61\x76\x61\x69\x6c\x61\x62\x6c\x65\x20\x5d\xa");
                    util_do_cmds(e, post_cmds, bio_out, indent);
                    ENGINE_finish(e);
                } else {
                    BIO_printf(bio_out, "\x5b\x20\x75\x6e\x61\x76\x61\x69\x6c\x61\x62\x6c\x65\x20\x5d\xa");
                    if (test_avail_noise)
                        ERR_print_errors_fp(stdout);
                    ERR_clear_error();
                }
            }
            if ((verbose > 0) && !util_verbose(e, verbose, bio_out, indent))
                goto end;
            ENGINE_free(e);
        } else
            ERR_print_errors(bio_err);
    }

    ret = 0;
 end:

    ERR_print_errors(bio_err);
    sk_OPENSSL_STRING_pop_free(engines, identity);
    sk_OPENSSL_STRING_pop_free(pre_cmds, identity);
    sk_OPENSSL_STRING_pop_free(post_cmds, identity);
    if (bio_out != NULL)
        BIO_free_all(bio_out);
    apps_shutdown();
    OPENSSL_EXIT(ret);
}
#else

# if PEDANTIC
static void *dummy = &dummy;
# endif

#endif
