/* ssl/ssl_txt.c */
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
/* ====================================================================
 * Copyright 2005 Nokia. All rights reserved.
 *
 * The portions of the attached software ("\x43\x6f\x6e\x74\x72\x69\x62\x75\x74\x69\x6f\x6e") is developed by
 * Nokia Corporation and is licensed pursuant to the OpenSSL open source
 * license.
 *
 * The Contribution, originally written by Mika Kousa and Pasi Eronen of
 * Nokia Corporation, consists of the "\x50\x53\x4b" (Pre-Shared Key) ciphersuites
 * support (see RFC 4279) to OpenSSL.
 *
 * No patent licenses or other rights except those expressly stated in
 * the OpenSSL open source license shall be deemed granted or received
 * expressly, by implication, estoppel, or otherwise.
 *
 * No assurances are provided by Nokia that the Contribution does not
 * infringe the patent or other intellectual property rights of any third
 * party or that the license provides you with all the necessary rights
 * to make use of the Contribution.
 *
 * THE SOFTWARE IS PROVIDED "\x41\x53\x20\x49\x53" WITHOUT WARRANTY OF ANY KIND. IN
 * ADDITION TO THE DISCLAIMERS INCLUDED IN THE LICENSE, NOKIA
 * SPECIFICALLY DISCLAIMS ANY LIABILITY FOR CLAIMS BROUGHT BY YOU OR ANY
 * OTHER ENTITY BASED ON INFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS OR
 * OTHERWISE.
 */

#include <stdio.h>
#include <openssl/buffer.h>
#include "ssl_locl.h"

#ifndef OPENSSL_NO_FP_API
int SSL_SESSION_print_fp(FILE *fp, const SSL_SESSION *x)
{
    BIO *b;
    int ret;

    if ((b = BIO_new(BIO_s_file_internal())) == NULL) {
        SSLerr(SSL_F_SSL_SESSION_PRINT_FP, ERR_R_BUF_LIB);
        return (0);
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = SSL_SESSION_print(b, x);
    BIO_free(b);
    return (ret);
}
#endif

int SSL_SESSION_print(BIO *bp, const SSL_SESSION *x)
{
    unsigned int i;
    const char *s;

    if (x == NULL)
        goto err;
    if (BIO_puts(bp, "\x53\x53\x4c\x2d\x53\x65\x73\x73\x69\x6f\x6e\x3a\xa") <= 0)
        goto err;
    if (x->ssl_version == SSL2_VERSION)
        s = "\x53\x53\x4c\x76\x32";
    else if (x->ssl_version == SSL3_VERSION)
        s = "\x53\x53\x4c\x76\x33";
    else if (x->ssl_version == TLS1_2_VERSION)
        s = "\x54\x4c\x53\x76\x31\x2e\x32";
    else if (x->ssl_version == TLS1_1_VERSION)
        s = "\x54\x4c\x53\x76\x31\x2e\x31";
    else if (x->ssl_version == TLS1_VERSION)
        s = "\x54\x4c\x53\x76\x31";
    else if (x->ssl_version == DTLS1_VERSION)
        s = "\x44\x54\x4c\x53\x76\x31";
    else if (x->ssl_version == DTLS1_2_VERSION)
        s = "\x44\x54\x4c\x53\x76\x31\x2e\x32";
    else if (x->ssl_version == DTLS1_BAD_VER)
        s = "\x44\x54\x4c\x53\x76\x31\x2d\x62\x61\x64";
    else
        s = "\x75\x6e\x6b\x6e\x6f\x77\x6e";
    if (BIO_printf(bp, "\x20\x20\x20\x20\x50\x72\x6f\x74\x6f\x63\x6f\x6c\x20\x20\x3a\x20\x25\x73\xa", s) <= 0)
        goto err;

    if (x->cipher == NULL) {
        if (((x->cipher_id) & 0xff000000) == 0x02000000) {
            if (BIO_printf
                (bp, "\x20\x20\x20\x20\x43\x69\x70\x68\x65\x72\x20\x20\x20\x20\x3a\x20\x25\x30\x36\x6c\x58\xa", x->cipher_id & 0xffffff) <= 0)
                goto err;
        } else {
            if (BIO_printf
                (bp, "\x20\x20\x20\x20\x43\x69\x70\x68\x65\x72\x20\x20\x20\x20\x3a\x20\x25\x30\x34\x6c\x58\xa", x->cipher_id & 0xffff) <= 0)
                goto err;
        }
    } else {
        if (BIO_printf
            (bp, "\x20\x20\x20\x20\x43\x69\x70\x68\x65\x72\x20\x20\x20\x20\x3a\x20\x25\x73\xa",
             ((x->cipher == NULL) ? "\x75\x6e\x6b\x6e\x6f\x77\x6e" : x->cipher->name)) <= 0)
            goto err;
    }
    if (BIO_puts(bp, "\x20\x20\x20\x20\x53\x65\x73\x73\x69\x6f\x6e\x2d\x49\x44\x3a\x20") <= 0)
        goto err;
    for (i = 0; i < x->session_id_length; i++) {
        if (BIO_printf(bp, "\x25\x30\x32\x58", x->session_id[i]) <= 0)
            goto err;
    }
    if (BIO_puts(bp, "\xa\x20\x20\x20\x20\x53\x65\x73\x73\x69\x6f\x6e\x2d\x49\x44\x2d\x63\x74\x78\x3a\x20") <= 0)
        goto err;
    for (i = 0; i < x->sid_ctx_length; i++) {
        if (BIO_printf(bp, "\x25\x30\x32\x58", x->sid_ctx[i]) <= 0)
            goto err;
    }
    if (BIO_puts(bp, "\xa\x20\x20\x20\x20\x4d\x61\x73\x74\x65\x72\x2d\x4b\x65\x79\x3a\x20") <= 0)
        goto err;
    for (i = 0; i < (unsigned int)x->master_key_length; i++) {
        if (BIO_printf(bp, "\x25\x30\x32\x58", x->master_key[i]) <= 0)
            goto err;
    }
    if (BIO_puts(bp, "\xa\x20\x20\x20\x20\x4b\x65\x79\x2d\x41\x72\x67\x20\x20\x20\x3a\x20") <= 0)
        goto err;
    if (x->key_arg_length == 0) {
        if (BIO_puts(bp, "\x4e\x6f\x6e\x65") <= 0)
            goto err;
    } else
        for (i = 0; i < x->key_arg_length; i++) {
            if (BIO_printf(bp, "\x25\x30\x32\x58", x->key_arg[i]) <= 0)
                goto err;
        }
#ifndef OPENSSL_NO_KRB5
    if (BIO_puts(bp, "\xa\x20\x20\x20\x20\x4b\x72\x62\x35\x20\x50\x72\x69\x6e\x63\x69\x70\x61\x6c\x3a\x20") <= 0)
        goto err;
    if (x->krb5_client_princ_len == 0) {
        if (BIO_puts(bp, "\x4e\x6f\x6e\x65") <= 0)
            goto err;
    } else
        for (i = 0; i < x->krb5_client_princ_len; i++) {
            if (BIO_printf(bp, "\x25\x30\x32\x58", x->krb5_client_princ[i]) <= 0)
                goto err;
        }
#endif                          /* OPENSSL_NO_KRB5 */
#ifndef OPENSSL_NO_PSK
    if (BIO_puts(bp, "\xa\x20\x20\x20\x20\x50\x53\x4b\x20\x69\x64\x65\x6e\x74\x69\x74\x79\x3a\x20") <= 0)
        goto err;
    if (BIO_printf(bp, "\x25\x73", x->psk_identity ? x->psk_identity : "\x4e\x6f\x6e\x65") <= 0)
        goto err;
    if (BIO_puts(bp, "\xa\x20\x20\x20\x20\x50\x53\x4b\x20\x69\x64\x65\x6e\x74\x69\x74\x79\x20\x68\x69\x6e\x74\x3a\x20") <= 0)
        goto err;
    if (BIO_printf
        (bp, "\x25\x73", x->psk_identity_hint ? x->psk_identity_hint : "\x4e\x6f\x6e\x65") <= 0)
        goto err;
#endif
#ifndef OPENSSL_NO_SRP
    if (BIO_puts(bp, "\xa\x20\x20\x20\x20\x53\x52\x50\x20\x75\x73\x65\x72\x6e\x61\x6d\x65\x3a\x20") <= 0)
        goto err;
    if (BIO_printf(bp, "\x25\x73", x->srp_username ? x->srp_username : "\x4e\x6f\x6e\x65") <= 0)
        goto err;
#endif
#ifndef OPENSSL_NO_TLSEXT
    if (x->tlsext_tick_lifetime_hint) {
        if (BIO_printf(bp,
                       "\xa\x20\x20\x20\x20\x54\x4c\x53\x20\x73\x65\x73\x73\x69\x6f\x6e\x20\x74\x69\x63\x6b\x65\x74\x20\x6c\x69\x66\x65\x74\x69\x6d\x65\x20\x68\x69\x6e\x74\x3a\x20\x25\x6c\x64\x20\x28\x73\x65\x63\x6f\x6e\x64\x73\x29",
                       x->tlsext_tick_lifetime_hint) <= 0)
            goto err;
    }
    if (x->tlsext_tick) {
        if (BIO_puts(bp, "\xa\x20\x20\x20\x20\x54\x4c\x53\x20\x73\x65\x73\x73\x69\x6f\x6e\x20\x74\x69\x63\x6b\x65\x74\x3a\xa") <= 0)
            goto err;
        if (BIO_dump_indent(bp, (char *)x->tlsext_tick, x->tlsext_ticklen, 4)
            <= 0)
            goto err;
    }
#endif

#ifndef OPENSSL_NO_COMP
    if (x->compress_meth != 0) {
        SSL_COMP *comp = NULL;

        ssl_cipher_get_evp(x, NULL, NULL, NULL, NULL, &comp);
        if (comp == NULL) {
            if (BIO_printf(bp, "\xa\x20\x20\x20\x20\x43\x6f\x6d\x70\x72\x65\x73\x73\x69\x6f\x6e\x3a\x20\x25\x64", x->compress_meth) <=
                0)
                goto err;
        } else {
            if (BIO_printf
                (bp, "\xa\x20\x20\x20\x20\x43\x6f\x6d\x70\x72\x65\x73\x73\x69\x6f\x6e\x3a\x20\x25\x64\x20\x28\x25\x73\x29", comp->id,
                 comp->method->name) <= 0)
                goto err;
        }
    }
#endif
    if (x->time != 0L) {
        if (BIO_printf(bp, "\xa\x20\x20\x20\x20\x53\x74\x61\x72\x74\x20\x54\x69\x6d\x65\x3a\x20\x25\x6c\x64", x->time) <= 0)
            goto err;
    }
    if (x->timeout != 0L) {
        if (BIO_printf(bp, "\xa\x20\x20\x20\x20\x54\x69\x6d\x65\x6f\x75\x74\x20\x20\x20\x3a\x20\x25\x6c\x64\x20\x28\x73\x65\x63\x29", x->timeout) <= 0)
            goto err;
    }
    if (BIO_puts(bp, "\xa") <= 0)
        goto err;

    if (BIO_puts(bp, "\x20\x20\x20\x20\x56\x65\x72\x69\x66\x79\x20\x72\x65\x74\x75\x72\x6e\x20\x63\x6f\x64\x65\x3a\x20") <= 0)
        goto err;
    if (BIO_printf(bp, "\x25\x6c\x64\x20\x28\x25\x73\x29\xa", x->verify_result,
                   X509_verify_cert_error_string(x->verify_result)) <= 0)
        goto err;

    return (1);
 err:
    return (0);
}
