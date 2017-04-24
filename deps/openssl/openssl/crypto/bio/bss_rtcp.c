/* crypto/bio/bss_rtcp.c */
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

/*-
 * Written by David L. Jones <jonesd@kcgl1.eng.ohio-state.edu>
 * Date:   22-JUL-1996
 * Revised: 25-SEP-1997         Update for 0.8.1, BIO_CTRL_SET -> BIO_C_SET_FD
 */
/* VMS */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "cryptlib.h"
#include <openssl/bio.h>

#include <iodef.h>              /* VMS IO$_ definitions */
#include <starlet.h>

typedef unsigned short io_channel;
/*************************************************************************/
struct io_status {
    short status, count;
    long flags;
};

/* Should have member alignment inhibited */
struct rpc_msg {
    /* 'A'-app data. 'R'-remote client 'G'-global */
    char channel;
    /* 'G'-get, 'P'-put, 'C'-confirm, 'X'-close */
    char function;
    /* Amount of data returned or max to return */
    unsigned short int length;
    /* variable data */
    char data[4092];
};
#define RPC_HDR_SIZE (sizeof(struct rpc_msg) - 4092)

struct rpc_ctx {
    int filled, pos;
    struct rpc_msg msg;
};

static int rtcp_write(BIO *h, const char *buf, int num);
static int rtcp_read(BIO *h, char *buf, int size);
static int rtcp_puts(BIO *h, const char *str);
static int rtcp_gets(BIO *h, char *str, int size);
static long rtcp_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int rtcp_new(BIO *h);
static int rtcp_free(BIO *data);

static BIO_METHOD rtcp_method = {
    BIO_TYPE_FD,
    "\x52\x54\x43\x50",
    rtcp_write,
    rtcp_read,
    rtcp_puts,
    rtcp_gets,
    rtcp_ctrl,
    rtcp_new,
    rtcp_free,
    NULL,
};

BIO_METHOD *BIO_s_rtcp(void)
{
    return (&rtcp_method);
}

/*****************************************************************************/
/*
 * Decnet I/O routines.
 */

#ifdef __DECC
# pragma message save
# pragma message disable DOLLARID
#endif

static int get(io_channel chan, char *buffer, int maxlen, int *length)
{
    int status;
    struct io_status iosb;
    status = sys$qiow(0, chan, IO$_READVBLK, &iosb, 0, 0,
                      buffer, maxlen, 0, 0, 0, 0);
    if ((status & 1) == 1)
        status = iosb.status;
    if ((status & 1) == 1)
        *length = iosb.count;
    return status;
}

static int put(io_channel chan, char *buffer, int length)
{
    int status;
    struct io_status iosb;
    status = sys$qiow(0, chan, IO$_WRITEVBLK, &iosb, 0, 0,
                      buffer, length, 0, 0, 0, 0);
    if ((status & 1) == 1)
        status = iosb.status;
    return status;
}

#ifdef __DECC
# pragma message restore
#endif

/***************************************************************************/

static int rtcp_new(BIO *bi)
{
    struct rpc_ctx *ctx;
    bi->init = 1;
    bi->num = 0;
    bi->flags = 0;
    bi->ptr = OPENSSL_malloc(sizeof(struct rpc_ctx));
    if (bi->ptr == NULL)
        return (0);
    ctx = (struct rpc_ctx *)bi->ptr;
    ctx->filled = 0;
    ctx->pos = 0;
    return (1);
}

static int rtcp_free(BIO *a)
{
    if (a == NULL)
        return (0);
    if (a->ptr)
        OPENSSL_free(a->ptr);
    a->ptr = NULL;
    return (1);
}

static int rtcp_read(BIO *b, char *out, int outl)
{
    int status, length;
    struct rpc_ctx *ctx;
    /*
     * read data, return existing.
     */
    ctx = (struct rpc_ctx *)b->ptr;
    if (ctx->pos < ctx->filled) {
        length = ctx->filled - ctx->pos;
        if (length > outl)
            length = outl;
        memmove(out, &ctx->msg.data[ctx->pos], length);
        ctx->pos += length;
        return length;
    }
    /*
     * Requst more data from R channel.
     */
    ctx->msg.channel = '\x52';
    ctx->msg.function = '\x47';
    ctx->msg.length = sizeof(ctx->msg.data);
    status = put(b->num, (char *)&ctx->msg, RPC_HDR_SIZE);
    if ((status & 1) == 0) {
        return -1;
    }
    /*
     * Read.
     */
    ctx->pos = ctx->filled = 0;
    status = get(b->num, (char *)&ctx->msg, sizeof(ctx->msg), &length);
    if ((status & 1) == 0)
        length = -1;
    if (ctx->msg.channel != '\x52' || ctx->msg.function != '\x43') {
        length = -1;
    }
    ctx->filled = length - RPC_HDR_SIZE;

    if (ctx->pos < ctx->filled) {
        length = ctx->filled - ctx->pos;
        if (length > outl)
            length = outl;
        memmove(out, ctx->msg.data, length);
        ctx->pos += length;
        return length;
    }

    return length;
}

static int rtcp_write(BIO *b, const char *in, int inl)
{
    int status, i, segment, length;
    struct rpc_ctx *ctx;
    /*
     * Output data, send in chunks no larger that sizeof(ctx->msg.data).
     */
    ctx = (struct rpc_ctx *)b->ptr;
    for (i = 0; i < inl; i += segment) {
        segment = inl - i;
        if (segment > sizeof(ctx->msg.data))
            segment = sizeof(ctx->msg.data);
        ctx->msg.channel = '\x52';
        ctx->msg.function = '\x50';
        ctx->msg.length = segment;
        memmove(ctx->msg.data, &in[i], segment);
        status = put(b->num, (char *)&ctx->msg, segment + RPC_HDR_SIZE);
        if ((status & 1) == 0) {
            i = -1;
            break;
        }

        status = get(b->num, (char *)&ctx->msg, sizeof(ctx->msg), &length);
        if (((status & 1) == 0) || (length < RPC_HDR_SIZE)) {
            i = -1;
            break;
        }
        if ((ctx->msg.channel != '\x52') || (ctx->msg.function != '\x43')) {
            printf("\x75\x6e\x65\x78\x70\x65\x63\x74\x65\x64\x20\x72\x65\x73\x70\x6f\x6e\x73\x65\x20\x77\x68\x65\x6e\x20\x63\x6f\x6e\x66\x69\x72\x6d\x69\x6e\x67\x20\x70\x75\x74\x20\x25\x63\x20\x25\x63\xa",
                   ctx->msg.channel, ctx->msg.function);

        }
    }
    return (i);
}

static long rtcp_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    long ret = 1;

    switch (cmd) {
    case BIO_CTRL_RESET:
    case BIO_CTRL_EOF:
        ret = 1;
        break;
    case BIO_C_SET_FD:
        b->num = num;
        ret = 1;
        break;
    case BIO_CTRL_SET_CLOSE:
    case BIO_CTRL_FLUSH:
    case BIO_CTRL_DUP:
        ret = 1;
        break;
    case BIO_CTRL_GET_CLOSE:
    case BIO_CTRL_INFO:
    case BIO_CTRL_GET:
    case BIO_CTRL_PENDING:
    case BIO_CTRL_WPENDING:
    default:
        ret = 0;
        break;
    }
    return (ret);
}

static int rtcp_gets(BIO *bp, char *buf, int size)
{
    return (0);
}

static int rtcp_puts(BIO *bp, const char *str)
{
    int length;
    if (str == NULL)
        return (0);
    length = strlen(str);
    if (length == 0)
        return (0);
    return rtcp_write(bp, str, length);
}
