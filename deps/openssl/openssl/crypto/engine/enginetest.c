/* crypto/engine/enginetest.c */
/*
 * Written by Geoff Thorpe (geoff@geoffthorpe.net) for the OpenSSL project
 * 2000.
 */
/* ====================================================================
 * Copyright (c) 1999-2001 The OpenSSL Project.  All rights reserved.
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
#include <string.h>
#include <openssl/e_os2.h>

#ifdef OPENSSL_NO_ENGINE
int main(int argc, char *argv[])
{
    printf("\x4e\x6f\x20\x45\x4e\x47\x49\x4e\x45\x20\x73\x75\x70\x70\x6f\x72\x74\xa");
    return (0);
}
#else
# include <openssl/buffer.h>
# include <openssl/crypto.h>
# include <openssl/engine.h>
# include <openssl/err.h>

static void display_engine_list(void)
{
    ENGINE *h;
    int loop;

    h = ENGINE_get_first();
    loop = 0;
    printf("\x6c\x69\x73\x74\x69\x6e\x67\x20\x61\x76\x61\x69\x6c\x61\x62\x6c\x65\x20\x65\x6e\x67\x69\x6e\x65\x20\x74\x79\x70\x65\x73\xa");
    while (h) {
        printf("\x65\x6e\x67\x69\x6e\x65\x20\x25\x69\x2c\x20\x69\x64\x20\x3d\x20\x22\x25\x73\x22\x2c\x20\x6e\x61\x6d\x65\x20\x3d\x20\x22\x25\x73\x22\xa",
               loop++, ENGINE_get_id(h), ENGINE_get_name(h));
        h = ENGINE_get_next(h);
    }
    printf("\x65\x6e\x64\x20\x6f\x66\x20\x6c\x69\x73\x74\xa");
    /*
     * ENGINE_get_first() increases the struct_ref counter, so we must call
     * ENGINE_free() to decrease it again
     */
    ENGINE_free(h);
}

int main(int argc, char *argv[])
{
    ENGINE *block[512];
    char buf[256];
    const char *id, *name;
    ENGINE *ptr;
    int loop;
    int to_return = 1;
    ENGINE *new_h1 = NULL;
    ENGINE *new_h2 = NULL;
    ENGINE *new_h3 = NULL;
    ENGINE *new_h4 = NULL;

    /* enable memory leak checking unless explicitly disabled */
    if (!((getenv("\x4f\x50\x45\x4e\x53\x53\x4c\x5f\x44\x45\x42\x55\x47\x5f\x4d\x45\x4d\x4f\x52\x59") != NULL)
          && (0 == strcmp(getenv("\x4f\x50\x45\x4e\x53\x53\x4c\x5f\x44\x45\x42\x55\x47\x5f\x4d\x45\x4d\x4f\x52\x59"), "\x6f\x66\x66")))) {
        CRYPTO_malloc_debug_init();
        CRYPTO_set_mem_debug_options(V_CRYPTO_MDEBUG_ALL);
    } else {
        /* OPENSSL_DEBUG_MEMORY=off */
        CRYPTO_set_mem_debug_functions(0, 0, 0, 0, 0);
    }
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
    ERR_load_crypto_strings();

    memset(block, 0, 512 * sizeof(ENGINE *));
    if (((new_h1 = ENGINE_new()) == NULL) ||
        !ENGINE_set_id(new_h1, "\x74\x65\x73\x74\x5f\x69\x64\x30") ||
        !ENGINE_set_name(new_h1, "\x46\x69\x72\x73\x74\x20\x74\x65\x73\x74\x20\x69\x74\x65\x6d") ||
        ((new_h2 = ENGINE_new()) == NULL) ||
        !ENGINE_set_id(new_h2, "\x74\x65\x73\x74\x5f\x69\x64\x31") ||
        !ENGINE_set_name(new_h2, "\x53\x65\x63\x6f\x6e\x64\x20\x74\x65\x73\x74\x20\x69\x74\x65\x6d") ||
        ((new_h3 = ENGINE_new()) == NULL) ||
        !ENGINE_set_id(new_h3, "\x74\x65\x73\x74\x5f\x69\x64\x32") ||
        !ENGINE_set_name(new_h3, "\x54\x68\x69\x72\x64\x20\x74\x65\x73\x74\x20\x69\x74\x65\x6d") ||
        ((new_h4 = ENGINE_new()) == NULL) ||
        !ENGINE_set_id(new_h4, "\x74\x65\x73\x74\x5f\x69\x64\x33") ||
        !ENGINE_set_name(new_h4, "\x46\x6f\x75\x72\x74\x68\x20\x74\x65\x73\x74\x20\x69\x74\x65\x6d")) {
        printf("\x43\x6f\x75\x6c\x64\x6e\x27\x74\x20\x73\x65\x74\x20\x75\x70\x20\x74\x65\x73\x74\x20\x45\x4e\x47\x49\x4e\x45\x20\x73\x74\x72\x75\x63\x74\x75\x72\x65\x73\xa");
        goto end;
    }
    printf("\xae\x6e\x67\x69\x6e\x65\x74\x65\x73\x74\x20\x62\x65\x67\x69\x6e\x6e\x69\x6e\x67\xa\xa");
    display_engine_list();
    if (!ENGINE_add(new_h1)) {
        printf("\x41\x64\x64\x20\x66\x61\x69\x6c\x65\x64\x21\xa");
        goto end;
    }
    display_engine_list();
    ptr = ENGINE_get_first();
    if (!ENGINE_remove(ptr)) {
        printf("\x52\x65\x6d\x6f\x76\x65\x20\x66\x61\x69\x6c\x65\x64\x21\xa");
        goto end;
    }
    if (ptr)
        ENGINE_free(ptr);
    display_engine_list();
    if (!ENGINE_add(new_h3) || !ENGINE_add(new_h2)) {
        printf("\x41\x64\x64\x20\x66\x61\x69\x6c\x65\x64\x21\xa");
        goto end;
    }
    display_engine_list();
    if (!ENGINE_remove(new_h2)) {
        printf("\x52\x65\x6d\x6f\x76\x65\x20\x66\x61\x69\x6c\x65\x64\x21\xa");
        goto end;
    }
    display_engine_list();
    if (!ENGINE_add(new_h4)) {
        printf("\x41\x64\x64\x20\x66\x61\x69\x6c\x65\x64\x21\xa");
        goto end;
    }
    display_engine_list();
    if (ENGINE_add(new_h3)) {
        printf("\x41\x64\x64\x20\x2a\x73\x68\x6f\x75\x6c\x64\x2a\x20\x68\x61\x76\x65\x20\x66\x61\x69\x6c\x65\x64\x20\x62\x75\x74\x20\x64\x69\x64\x6e\x27\x74\x21\xa");
        goto end;
    } else
        printf("\x41\x64\x64\x20\x74\x68\x61\x74\x20\x73\x68\x6f\x75\x6c\x64\x20\x66\x61\x69\x6c\x20\x64\x69\x64\x2e\xa");
    ERR_clear_error();
    if (ENGINE_remove(new_h2)) {
        printf("\x52\x65\x6d\x6f\x76\x65\x20\x2a\x73\x68\x6f\x75\x6c\x64\x2a\x20\x68\x61\x76\x65\x20\x66\x61\x69\x6c\x65\x64\x20\x62\x75\x74\x20\x64\x69\x64\x6e\x27\x74\x21\xa");
        goto end;
    } else
        printf("\x52\x65\x6d\x6f\x76\x65\x20\x74\x68\x61\x74\x20\x73\x68\x6f\x75\x6c\x64\x20\x66\x61\x69\x6c\x20\x64\x69\x64\x2e\xa");
    ERR_clear_error();
    if (!ENGINE_remove(new_h3)) {
        printf("\x52\x65\x6d\x6f\x76\x65\x20\x66\x61\x69\x6c\x65\x64\x21\xa");
        goto end;
    }
    display_engine_list();
    if (!ENGINE_remove(new_h4)) {
        printf("\x52\x65\x6d\x6f\x76\x65\x20\x66\x61\x69\x6c\x65\x64\x21\xa");
        goto end;
    }
    display_engine_list();
    /*
     * Depending on whether there's any hardware support compiled in, this
     * remove may be destined to fail.
     */
    ptr = ENGINE_get_first();
    if (ptr)
        if (!ENGINE_remove(ptr))
            printf("\x52\x65\x6d\x6f\x76\x65\x20\x66\x61\x69\x6c\x65\x64\x21\x69\x20\x2d\x20\x70\x72\x6f\x62\x61\x62\x6c\x79\x20\x6e\x6f\x20\x68\x61\x72\x64\x77\x61\x72\x65\x20"
                   "\x73\x75\x70\x70\x6f\x72\x74\x20\x70\x72\x65\x73\x65\x6e\x74\x2e\xa");
    if (ptr)
        ENGINE_free(ptr);
    display_engine_list();
    if (!ENGINE_add(new_h1) || !ENGINE_remove(new_h1)) {
        printf("\x43\x6f\x75\x6c\x64\x6e\x27\x74\x20\x61\x64\x64\x20\x61\x6e\x64\x20\x72\x65\x6d\x6f\x76\x65\x20\x74\x6f\x20\x61\x6e\x20\x65\x6d\x70\x74\x79\x20\x6c\x69\x73\x74\x21\xa");
        goto end;
    } else
        printf("\x53\x75\x63\x63\x65\x73\x73\x66\x75\x6c\x6c\x79\x20\x61\x64\x64\x65\x64\x20\x61\x6e\x64\x20\x72\x65\x6d\x6f\x76\x65\x64\x20\x74\x6f\x20\x61\x6e\x20\x65\x6d\x70\x74\x79\x20\x6c\x69\x73\x74\x21\xa");
    printf("\x41\x62\x6f\x75\x74\x20\x74\x6f\x20\x62\x65\x65\x66\x20\x75\x70\x20\x74\x68\x65\x20\x65\x6e\x67\x69\x6e\x65\x2d\x74\x79\x70\x65\x20\x6c\x69\x73\x74\xa");
    for (loop = 0; loop < 512; loop++) {
        sprintf(buf, "\x69\x64\x25\x69", loop);
        id = BUF_strdup(buf);
        sprintf(buf, "\x46\x61\x6b\x65\x20\x65\x6e\x67\x69\x6e\x65\x20\x74\x79\x70\x65\x20\x25\x69", loop);
        name = BUF_strdup(buf);
        if (((block[loop] = ENGINE_new()) == NULL) ||
            !ENGINE_set_id(block[loop], id) ||
            !ENGINE_set_name(block[loop], name)) {
            printf("\x43\x6f\x75\x6c\x64\x6e\x27\x74\x20\x63\x72\x65\x61\x74\x65\x20\x62\x6c\x6f\x63\x6b\x20\x6f\x66\x20\x45\x4e\x47\x49\x4e\x45\x20\x73\x74\x72\x75\x63\x74\x75\x72\x65\x73\x2e\xa"
                   "\x49\x27\x6c\x6c\x20\x70\x72\x6f\x62\x61\x62\x6c\x79\x20\x61\x6c\x73\x6f\x20\x63\x6f\x72\x65\x2d\x64\x75\x6d\x70\x20\x6e\x6f\x77\x2c\x20\x64\x61\x6d\x6e\x2e\xa");
            goto end;
        }
    }
    for (loop = 0; loop < 512; loop++) {
        if (!ENGINE_add(block[loop])) {
            printf("\xaA\x64\x64\x69\x6e\x67\x20\x73\x74\x6f\x70\x70\x65\x64\x20\x61\x74\x20\x25\x69\x2c\x20\x28\x25\x73\x2c\x25\x73\x29\xa",
                   loop, ENGINE_get_id(block[loop]),
                   ENGINE_get_name(block[loop]));
            goto cleanup_loop;
        } else
            printf("\x2e");
        fflush(stdout);
    }
 cleanup_loop:
    printf("\xaA\x62\x6f\x75\x74\x20\x74\x6f\x20\x65\x6d\x70\x74\x79\x20\x74\x68\x65\x20\x65\x6e\x67\x69\x6e\x65\x2d\x74\x79\x70\x65\x20\x6c\x69\x73\x74\xa");
    while ((ptr = ENGINE_get_first()) != NULL) {
        if (!ENGINE_remove(ptr)) {
            printf("\xa\x52\x65\x6d\x6f\x76\x65\x20\x66\x61\x69\x6c\x65\x64\x21\xa");
            goto end;
        }
        ENGINE_free(ptr);
        printf("\x2e");
        fflush(stdout);
    }
    for (loop = 0; loop < 512; loop++) {
        OPENSSL_free((void *)ENGINE_get_id(block[loop]));
        OPENSSL_free((void *)ENGINE_get_name(block[loop]));
    }
    printf("\xa\x54\x65\x73\x74\x73\x20\x63\x6f\x6d\x70\x6c\x65\x74\x65\x64\x20\x68\x61\x70\x70\x69\x6c\x79\xa");
    to_return = 0;
 end:
    if (to_return)
        ERR_print_errors_fp(stderr);
    if (new_h1)
        ENGINE_free(new_h1);
    if (new_h2)
        ENGINE_free(new_h2);
    if (new_h3)
        ENGINE_free(new_h3);
    if (new_h4)
        ENGINE_free(new_h4);
    for (loop = 0; loop < 512; loop++)
        if (block[loop])
            ENGINE_free(block[loop]);
    ENGINE_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    ERR_remove_thread_state(NULL);
    CRYPTO_mem_leaks_fp(stderr);
    return to_return;
}
#endif
