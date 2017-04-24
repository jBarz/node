/* apps/ts.c */
/*
 * Written by Zoltan Glozik (zglozik@stones.com) for the OpenSSL project
 * 2002.
 */
/* ====================================================================
 * Copyright (c) 2001 The OpenSSL Project.  All rights reserved.
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
#include "apps.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ts.h>
#include <openssl/bn.h>

#undef PROG
#define PROG    ts_main

/* Length of the nonce of the request in bits (must be a multiple of 8). */
#define NONCE_LENGTH            64

/* Macro definitions for the configuration file. */
#define ENV_OID_FILE            "\x6f\x69\x64\x5f\x66\x69\x6c\x65"

/* Local function declarations. */

static ASN1_OBJECT *txt2obj(const char *oid);
static CONF *load_config_file(const char *configfile);

/* Query related functions. */
static int query_command(const char *data, char *digest,
                         const EVP_MD *md, const char *policy, int no_nonce,
                         int cert, const char *in, const char *out, int text);
static BIO *BIO_open_with_default(const char *file, const char *mode,
                                  FILE *default_fp);
static TS_REQ *create_query(BIO *data_bio, char *digest, const EVP_MD *md,
                            const char *policy, int no_nonce, int cert);
static int create_digest(BIO *input, char *digest,
                         const EVP_MD *md, unsigned char **md_value);
static ASN1_INTEGER *create_nonce(int bits);

/* Reply related functions. */
static int reply_command(CONF *conf, char *section, char *engine,
                         char *queryfile, char *passin, char *inkey,
                         char *signer, char *chain, const char *policy,
                         char *in, int token_in, char *out, int token_out,
                         int text);
static TS_RESP *read_PKCS7(BIO *in_bio);
static TS_RESP *create_response(CONF *conf, const char *section, char *engine,
                                char *queryfile, char *passin, char *inkey,
                                char *signer, char *chain,
                                const char *policy);
static ASN1_INTEGER *MS_CALLBACK serial_cb(TS_RESP_CTX *ctx, void *data);
static ASN1_INTEGER *next_serial(const char *serialfile);
static int save_ts_serial(const char *serialfile, ASN1_INTEGER *serial);

/* Verify related functions. */
static int verify_command(char *data, char *digest, char *queryfile,
                          char *in, int token_in,
                          char *ca_path, char *ca_file, char *untrusted);
static TS_VERIFY_CTX *create_verify_ctx(char *data, char *digest,
                                        char *queryfile,
                                        char *ca_path, char *ca_file,
                                        char *untrusted);
static X509_STORE *create_cert_store(char *ca_path, char *ca_file);
static int MS_CALLBACK verify_cb(int ok, X509_STORE_CTX *ctx);

/* Main function definition. */
int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    int ret = 1;
    char *configfile = NULL;
    char *section = NULL;
    CONF *conf = NULL;
    enum mode {
        CMD_NONE, CMD_QUERY, CMD_REPLY, CMD_VERIFY
    } mode = CMD_NONE;
    char *data = NULL;
    char *digest = NULL;
    const EVP_MD *md = NULL;
    char *rnd = NULL;
    char *policy = NULL;
    int no_nonce = 0;
    int cert = 0;
    char *in = NULL;
    char *out = NULL;
    int text = 0;
    char *queryfile = NULL;
    char *passin = NULL;        /* Password source. */
    char *password = NULL;      /* Password itself. */
    char *inkey = NULL;
    char *signer = NULL;
    char *chain = NULL;
    char *ca_path = NULL;
    char *ca_file = NULL;
    char *untrusted = NULL;
    char *engine = NULL;
    /* Input is ContentInfo instead of TimeStampResp. */
    int token_in = 0;
    /* Output is ContentInfo instead of TimeStampResp. */
    int token_out = 0;
    int free_bio_err = 0;

    ERR_load_crypto_strings();
    apps_startup();

    if (bio_err == NULL && (bio_err = BIO_new(BIO_s_file())) != NULL) {
        free_bio_err = 1;
        BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);
    }

    if (!load_config(bio_err, NULL))
        goto cleanup;

    for (argc--, argv++; argc > 0; argc--, argv++) {
        if (strcmp(*argv, "\x2d\x63\x6f\x6e\x66\x69\x67") == 0) {
            if (argc-- < 1)
                goto usage;
            configfile = *++argv;
        } else if (strcmp(*argv, "\x2d\x73\x65\x63\x74\x69\x6f\x6e") == 0) {
            if (argc-- < 1)
                goto usage;
            section = *++argv;
        } else if (strcmp(*argv, "\x2d\x71\x75\x65\x72\x79") == 0) {
            if (mode != CMD_NONE)
                goto usage;
            mode = CMD_QUERY;
        } else if (strcmp(*argv, "\x2d\x64\x61\x74\x61") == 0) {
            if (argc-- < 1)
                goto usage;
            data = *++argv;
        } else if (strcmp(*argv, "\x2d\x64\x69\x67\x65\x73\x74") == 0) {
            if (argc-- < 1)
                goto usage;
            digest = *++argv;
        } else if (strcmp(*argv, "\x2d\x72\x61\x6e\x64") == 0) {
            if (argc-- < 1)
                goto usage;
            rnd = *++argv;
        } else if (strcmp(*argv, "\x2d\x70\x6f\x6c\x69\x63\x79") == 0) {
            if (argc-- < 1)
                goto usage;
            policy = *++argv;
        } else if (strcmp(*argv, "\x2d\x6e\x6f\x5f\x6e\x6f\x6e\x63\x65") == 0) {
            no_nonce = 1;
        } else if (strcmp(*argv, "\x2d\x63\x65\x72\x74") == 0) {
            cert = 1;
        } else if (strcmp(*argv, "\x2d\x69\x6e") == 0) {
            if (argc-- < 1)
                goto usage;
            in = *++argv;
        } else if (strcmp(*argv, "\x2d\x74\x6f\x6b\x65\x6e\x5f\x69\x6e") == 0) {
            token_in = 1;
        } else if (strcmp(*argv, "\x2d\x6f\x75\x74") == 0) {
            if (argc-- < 1)
                goto usage;
            out = *++argv;
        } else if (strcmp(*argv, "\x2d\x74\x6f\x6b\x65\x6e\x5f\x6f\x75\x74") == 0) {
            token_out = 1;
        } else if (strcmp(*argv, "\x2d\x74\x65\x78\x74") == 0) {
            text = 1;
        } else if (strcmp(*argv, "\x2d\x72\x65\x70\x6c\x79") == 0) {
            if (mode != CMD_NONE)
                goto usage;
            mode = CMD_REPLY;
        } else if (strcmp(*argv, "\x2d\x71\x75\x65\x72\x79\x66\x69\x6c\x65") == 0) {
            if (argc-- < 1)
                goto usage;
            queryfile = *++argv;
        } else if (strcmp(*argv, "\x2d\x70\x61\x73\x73\x69\x6e") == 0) {
            if (argc-- < 1)
                goto usage;
            passin = *++argv;
        } else if (strcmp(*argv, "\x2d\x69\x6e\x6b\x65\x79") == 0) {
            if (argc-- < 1)
                goto usage;
            inkey = *++argv;
        } else if (strcmp(*argv, "\x2d\x73\x69\x67\x6e\x65\x72") == 0) {
            if (argc-- < 1)
                goto usage;
            signer = *++argv;
        } else if (strcmp(*argv, "\x2d\x63\x68\x61\x69\x6e") == 0) {
            if (argc-- < 1)
                goto usage;
            chain = *++argv;
        } else if (strcmp(*argv, "\x2d\x76\x65\x72\x69\x66\x79") == 0) {
            if (mode != CMD_NONE)
                goto usage;
            mode = CMD_VERIFY;
        } else if (strcmp(*argv, "\x2d\x43\x41\x70\x61\x74\x68") == 0) {
            if (argc-- < 1)
                goto usage;
            ca_path = *++argv;
        } else if (strcmp(*argv, "\x2d\x43\x41\x66\x69\x6c\x65") == 0) {
            if (argc-- < 1)
                goto usage;
            ca_file = *++argv;
        } else if (strcmp(*argv, "\x2d\x75\x6e\x74\x72\x75\x73\x74\x65\x64") == 0) {
            if (argc-- < 1)
                goto usage;
            untrusted = *++argv;
        } else if (strcmp(*argv, "\x2d\x65\x6e\x67\x69\x6e\x65") == 0) {
            if (argc-- < 1)
                goto usage;
            engine = *++argv;
        } else if ((md = EVP_get_digestbyname(*argv + 1)) != NULL) {
            /* empty. */
        } else
            goto usage;
    }

    /* Seed the random number generator if it is going to be used. */
    if (mode == CMD_QUERY && !no_nonce) {
        if (!app_RAND_load_file(NULL, bio_err, 1) && rnd == NULL)
            BIO_printf(bio_err, "\x77\x61\x72\x6e\x69\x6e\x67\x2c\x20\x6e\x6f\x74\x20\x6d\x75\x63\x68\x20\x65\x78\x74\x72\x61\x20\x72\x61\x6e\x64\x6f\x6d\x20"
                       "\x64\x61\x74\x61\x2c\x20\x63\x6f\x6e\x73\x69\x64\x65\x72\x20\x75\x73\x69\x6e\x67\x20\x74\x68\x65\x20\x2d\x72\x61\x6e\x64\x20\x6f\x70\x74\x69\x6f\x6e\xa");
        if (rnd != NULL)
            BIO_printf(bio_err, "\x25\x6c\x64\x20\x73\x65\x6d\x69\x2d\x72\x61\x6e\x64\x6f\x6d\x20\x62\x79\x74\x65\x73\x20\x6c\x6f\x61\x64\x65\x64\xa",
                       app_RAND_load_files(rnd));
    }

    /* Get the password if required. */
    if (mode == CMD_REPLY && passin &&
        !app_passwd(bio_err, passin, NULL, &password, NULL)) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x67\x65\x74\x74\x69\x6e\x67\x20\x70\x61\x73\x73\x77\x6f\x72\x64\x2e\xa");
        goto cleanup;
    }

    /*
     * Check consistency of parameters and execute the appropriate function.
     */
    switch (mode) {
    case CMD_NONE:
        goto usage;
    case CMD_QUERY:
        /*
         * Data file and message imprint cannot be specified at the same
         * time.
         */
        ret = data != NULL && digest != NULL;
        if (ret)
            goto usage;
        /* Load the config file for possible policy OIDs. */
        conf = load_config_file(configfile);
        ret = !query_command(data, digest, md, policy, no_nonce, cert,
                             in, out, text);
        break;
    case CMD_REPLY:
        conf = load_config_file(configfile);
        if (in == NULL) {
            ret = !(queryfile != NULL && conf != NULL && !token_in);
            if (ret)
                goto usage;
        } else {
            /* 'in' and 'queryfile' are exclusive. */
            ret = !(queryfile == NULL);
            if (ret)
                goto usage;
        }

        ret = !reply_command(conf, section, engine, queryfile,
                             password, inkey, signer, chain, policy,
                             in, token_in, out, token_out, text);
        break;
    case CMD_VERIFY:
        ret = !(((queryfile && !data && !digest)
                 || (!queryfile && data && !digest)
                 || (!queryfile && !data && digest))
                && in != NULL);
        if (ret)
            goto usage;

        ret = !verify_command(data, digest, queryfile, in, token_in,
                              ca_path, ca_file, untrusted);
    }

    goto cleanup;

 usage:
    BIO_printf(bio_err, "\x75\x73\x61\x67\x65\x3a\xa"
               "\x74\x73\x20\x2d\x71\x75\x65\x72\x79\x20\x5b\x2d\x72\x61\x6e\x64\x20\x66\x69\x6c\x65\x25\x63\x66\x69\x6c\x65\x25\x63\x2e\x2e\x2e\x5d\x20\x5b\x2d\x63\x6f\x6e\x66\x69\x67\x20\x63\x6f\x6e\x66\x69\x67\x66\x69\x6c\x65\x5d\x20"
               "\x5b\x2d\x64\x61\x74\x61\x20\x66\x69\x6c\x65\x5f\x74\x6f\x5f\x68\x61\x73\x68\x5d\x20\x5b\x2d\x64\x69\x67\x65\x73\x74\x20\x64\x69\x67\x65\x73\x74\x5f\x62\x79\x74\x65\x73\x5d"
               "\x5b\x2d\x6d\x64\x32\x7c\x2d\x6d\x64\x34\x7c\x2d\x6d\x64\x35\x7c\x2d\x73\x68\x61\x7c\x2d\x73\x68\x61\x31\x7c\x2d\x6d\x64\x63\x32\x7c\x2d\x72\x69\x70\x65\x6d\x64\x31\x36\x30\x5d\x20"
               "\x5b\x2d\x70\x6f\x6c\x69\x63\x79\x20\x6f\x62\x6a\x65\x63\x74\x5f\x69\x64\x5d\x20\x5b\x2d\x6e\x6f\x5f\x6e\x6f\x6e\x63\x65\x5d\x20\x5b\x2d\x63\x65\x72\x74\x5d\x20"
               "\x5b\x2d\x69\x6e\x20\x72\x65\x71\x75\x65\x73\x74\x2e\x74\x73\x71\x5d\x20\x5b\x2d\x6f\x75\x74\x20\x72\x65\x71\x75\x65\x73\x74\x2e\x74\x73\x71\x5d\x20\x5b\x2d\x74\x65\x78\x74\x5d\xa",
               LIST_SEPARATOR_CHAR, LIST_SEPARATOR_CHAR);
    BIO_printf(bio_err, "\x6f\x72\xa"
               "\x74\x73\x20\x2d\x72\x65\x70\x6c\x79\x20\x5b\x2d\x63\x6f\x6e\x66\x69\x67\x20\x63\x6f\x6e\x66\x69\x67\x66\x69\x6c\x65\x5d\x20\x5b\x2d\x73\x65\x63\x74\x69\x6f\x6e\x20\x74\x73\x61\x5f\x73\x65\x63\x74\x69\x6f\x6e\x5d\x20"
               "\x5b\x2d\x71\x75\x65\x72\x79\x66\x69\x6c\x65\x20\x72\x65\x71\x75\x65\x73\x74\x2e\x74\x73\x71\x5d\x20\x5b\x2d\x70\x61\x73\x73\x69\x6e\x20\x70\x61\x73\x73\x77\x6f\x72\x64\x5d\x20"
               "\x5b\x2d\x73\x69\x67\x6e\x65\x72\x20\x74\x73\x61\x5f\x63\x65\x72\x74\x2e\x70\x65\x6d\x5d\x20\x5b\x2d\x69\x6e\x6b\x65\x79\x20\x70\x72\x69\x76\x61\x74\x65\x5f\x6b\x65\x79\x2e\x70\x65\x6d\x5d\x20"
               "\x5b\x2d\x63\x68\x61\x69\x6e\x20\x63\x65\x72\x74\x73\x5f\x66\x69\x6c\x65\x2e\x70\x65\x6d\x5d\x20\x5b\x2d\x70\x6f\x6c\x69\x63\x79\x20\x6f\x62\x6a\x65\x63\x74\x5f\x69\x64\x5d\x20"
               "\x5b\x2d\x69\x6e\x20\x72\x65\x73\x70\x6f\x6e\x73\x65\x2e\x74\x73\x72\x5d\x20\x5b\x2d\x74\x6f\x6b\x65\x6e\x5f\x69\x6e\x5d\x20"
               "\x5b\x2d\x6f\x75\x74\x20\x72\x65\x73\x70\x6f\x6e\x73\x65\x2e\x74\x73\x72\x5d\x20\x5b\x2d\x74\x6f\x6b\x65\x6e\x5f\x6f\x75\x74\x5d\x20\x5b\x2d\x74\x65\x78\x74\x5d\x20\x5b\x2d\x65\x6e\x67\x69\x6e\x65\x20\x69\x64\x5d\xa");
    BIO_printf(bio_err, "\x6f\x72\xa"
               "\x74\x73\x20\x2d\x76\x65\x72\x69\x66\x79\x20\x5b\x2d\x64\x61\x74\x61\x20\x66\x69\x6c\x65\x5f\x74\x6f\x5f\x68\x61\x73\x68\x5d\x20\x5b\x2d\x64\x69\x67\x65\x73\x74\x20\x64\x69\x67\x65\x73\x74\x5f\x62\x79\x74\x65\x73\x5d\x20"
               "\x5b\x2d\x71\x75\x65\x72\x79\x66\x69\x6c\x65\x20\x72\x65\x71\x75\x65\x73\x74\x2e\x74\x73\x71\x5d\x20"
               "\x2d\x69\x6e\x20\x72\x65\x73\x70\x6f\x6e\x73\x65\x2e\x74\x73\x72\x20\x5b\x2d\x74\x6f\x6b\x65\x6e\x5f\x69\x6e\x5d\x20"
               "\x2d\x43\x41\x70\x61\x74\x68\x20\x63\x61\x5f\x70\x61\x74\x68\x20\x2d\x43\x41\x66\x69\x6c\x65\x20\x63\x61\x5f\x66\x69\x6c\x65\x2e\x70\x65\x6d\x20"
               "\x2d\x75\x6e\x74\x72\x75\x73\x74\x65\x64\x20\x63\x65\x72\x74\x5f\x66\x69\x6c\x65\x2e\x70\x65\x6d\xa");
 cleanup:
    /* Clean up. */
    app_RAND_write_file(NULL, bio_err);
    NCONF_free(conf);
    OPENSSL_free(password);
    OBJ_cleanup();
    if (free_bio_err) {
        BIO_free_all(bio_err);
        bio_err = NULL;
    }

    OPENSSL_EXIT(ret);
}

/*
 * Configuration file-related function definitions.
 */

static ASN1_OBJECT *txt2obj(const char *oid)
{
    ASN1_OBJECT *oid_obj = NULL;

    if (!(oid_obj = OBJ_txt2obj(oid, 0)))
        BIO_printf(bio_err, "\x63\x61\x6e\x6e\x6f\x74\x20\x63\x6f\x6e\x76\x65\x72\x74\x20\x25\x73\x20\x74\x6f\x20\x4f\x49\x44\xa", oid);

    return oid_obj;
}

static CONF *load_config_file(const char *configfile)
{
    CONF *conf = NULL;
    long errorline = -1;

    if (!configfile)
        configfile = getenv("\x4f\x50\x45\x4e\x53\x53\x4c\x5f\x43\x4f\x4e\x46");
    if (!configfile)
        configfile = getenv("\x53\x53\x4c\x45\x41\x59\x5f\x43\x4f\x4e\x46");

    if (configfile &&
        (!(conf = NCONF_new(NULL)) ||
         NCONF_load(conf, configfile, &errorline) <= 0)) {
        if (errorline <= 0)
            BIO_printf(bio_err, "\x65\x72\x72\x6f\x72\x20\x6c\x6f\x61\x64\x69\x6e\x67\x20\x74\x68\x65\x20\x63\x6f\x6e\x66\x69\x67\x20\x66\x69\x6c\x65\x20"
                       "\x27\x25\x73\x27\xa", configfile);
        else
            BIO_printf(bio_err, "\x65\x72\x72\x6f\x72\x20\x6f\x6e\x20\x6c\x69\x6e\x65\x20\x25\x6c\x64\x20\x6f\x66\x20\x63\x6f\x6e\x66\x69\x67\x20\x66\x69\x6c\x65\x20"
                       "\x27\x25\x73\x27\xa", errorline, configfile);
    }

    if (conf != NULL) {
        const char *p;

        BIO_printf(bio_err, "\x55\x73\x69\x6e\x67\x20\x63\x6f\x6e\x66\x69\x67\x75\x72\x61\x74\x69\x6f\x6e\x20\x66\x72\x6f\x6d\x20\x25\x73\xa", configfile);
        p = NCONF_get_string(conf, NULL, ENV_OID_FILE);
        if (p != NULL) {
            BIO *oid_bio = BIO_new_file(p, "\x72");
            if (!oid_bio)
                ERR_print_errors(bio_err);
            else {
                OBJ_create_objects(oid_bio);
                BIO_free_all(oid_bio);
            }
        } else
            ERR_clear_error();
        if (!add_oid_section(bio_err, conf))
            ERR_print_errors(bio_err);
    }
    return conf;
}

/*
 * Query-related method definitions.
 */

static int query_command(const char *data, char *digest, const EVP_MD *md,
                         const char *policy, int no_nonce,
                         int cert, const char *in, const char *out, int text)
{
    int ret = 0;
    TS_REQ *query = NULL;
    BIO *in_bio = NULL;
    BIO *data_bio = NULL;
    BIO *out_bio = NULL;

    /* Build query object either from file or from scratch. */
    if (in != NULL) {
        if ((in_bio = BIO_new_file(in, "\x72\x62")) == NULL)
            goto end;
        query = d2i_TS_REQ_bio(in_bio, NULL);
    } else {
        /*
         * Open the file if no explicit digest bytes were specified.
         */
        if (!digest && !(data_bio = BIO_open_with_default(data, "\x72\x62", stdin)))
            goto end;
        /* Creating the query object. */
        query = create_query(data_bio, digest, md, policy, no_nonce, cert);
        /* Saving the random number generator state. */
    }
    if (query == NULL)
        goto end;

    /* Write query either in ASN.1 or in text format. */
    if ((out_bio = BIO_open_with_default(out, "\x77\x62", stdout)) == NULL)
        goto end;
    if (text) {
        /* Text output. */
        if (!TS_REQ_print_bio(out_bio, query))
            goto end;
    } else {
        /* ASN.1 output. */
        if (!i2d_TS_REQ_bio(out_bio, query))
            goto end;
    }

    ret = 1;

 end:
    ERR_print_errors(bio_err);

    /* Clean up. */
    BIO_free_all(in_bio);
    BIO_free_all(data_bio);
    BIO_free_all(out_bio);
    TS_REQ_free(query);

    return ret;
}

static BIO *BIO_open_with_default(const char *file, const char *mode,
                                  FILE *default_fp)
{
    return file == NULL ? BIO_new_fp(default_fp, BIO_NOCLOSE)
        : BIO_new_file(file, mode);
}

static TS_REQ *create_query(BIO *data_bio, char *digest, const EVP_MD *md,
                            const char *policy, int no_nonce, int cert)
{
    int ret = 0;
    TS_REQ *ts_req = NULL;
    int len;
    TS_MSG_IMPRINT *msg_imprint = NULL;
    X509_ALGOR *algo = NULL;
    unsigned char *data = NULL;
    ASN1_OBJECT *policy_obj = NULL;
    ASN1_INTEGER *nonce_asn1 = NULL;

    /* Setting default message digest. */
    if (!md && !(md = EVP_get_digestbyname("\x73\x68\x61\x31")))
        goto err;

    /* Creating request object. */
    if (!(ts_req = TS_REQ_new()))
        goto err;

    /* Setting version. */
    if (!TS_REQ_set_version(ts_req, 1))
        goto err;

    /* Creating and adding MSG_IMPRINT object. */
    if (!(msg_imprint = TS_MSG_IMPRINT_new()))
        goto err;

    /* Adding algorithm. */
    if (!(algo = X509_ALGOR_new()))
        goto err;
    if (!(algo->algorithm = OBJ_nid2obj(EVP_MD_type(md))))
        goto err;
    if (!(algo->parameter = ASN1_TYPE_new()))
        goto err;
    algo->parameter->type = V_ASN1_NULL;
    if (!TS_MSG_IMPRINT_set_algo(msg_imprint, algo))
        goto err;

    /* Adding message digest. */
    if ((len = create_digest(data_bio, digest, md, &data)) == 0)
        goto err;
    if (!TS_MSG_IMPRINT_set_msg(msg_imprint, data, len))
        goto err;

    if (!TS_REQ_set_msg_imprint(ts_req, msg_imprint))
        goto err;

    /* Setting policy if requested. */
    if (policy && !(policy_obj = txt2obj(policy)))
        goto err;
    if (policy_obj && !TS_REQ_set_policy_id(ts_req, policy_obj))
        goto err;

    /* Setting nonce if requested. */
    if (!no_nonce && !(nonce_asn1 = create_nonce(NONCE_LENGTH)))
        goto err;
    if (nonce_asn1 && !TS_REQ_set_nonce(ts_req, nonce_asn1))
        goto err;

    /* Setting certificate request flag if requested. */
    if (!TS_REQ_set_cert_req(ts_req, cert))
        goto err;

    ret = 1;
 err:
    if (!ret) {
        TS_REQ_free(ts_req);
        ts_req = NULL;
        BIO_printf(bio_err, "\x63\x6f\x75\x6c\x64\x20\x6e\x6f\x74\x20\x63\x72\x65\x61\x74\x65\x20\x71\x75\x65\x72\x79\xa");
    }
    TS_MSG_IMPRINT_free(msg_imprint);
    X509_ALGOR_free(algo);
    OPENSSL_free(data);
    ASN1_OBJECT_free(policy_obj);
    ASN1_INTEGER_free(nonce_asn1);
    return ts_req;
}

static int create_digest(BIO *input, char *digest, const EVP_MD *md,
                         unsigned char **md_value)
{
    int md_value_len;

    md_value_len = EVP_MD_size(md);
    if (md_value_len < 0)
        goto err;
    if (input) {
        /* Digest must be computed from an input file. */
        EVP_MD_CTX md_ctx;
        unsigned char buffer[4096];
        int length;

        *md_value = OPENSSL_malloc(md_value_len);
        if (*md_value == 0)
            goto err;

        EVP_DigestInit(&md_ctx, md);
        while ((length = BIO_read(input, buffer, sizeof(buffer))) > 0) {
            EVP_DigestUpdate(&md_ctx, buffer, length);
        }
        EVP_DigestFinal(&md_ctx, *md_value, NULL);
    } else {
        /* Digest bytes are specified with digest. */
        long digest_len;
        *md_value = string_to_hex(digest, &digest_len);
        if (!*md_value || md_value_len != digest_len) {
            OPENSSL_free(*md_value);
            *md_value = NULL;
            BIO_printf(bio_err, "\x62\x61\x64\x20\x64\x69\x67\x65\x73\x74\x2c\x20\x25\x64\x20\x62\x79\x74\x65\x73\x20"
                       "\x6d\x75\x73\x74\x20\x62\x65\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\xa", md_value_len);
            goto err;
        }
    }

    return md_value_len;
 err:
    return 0;
}

static ASN1_INTEGER *create_nonce(int bits)
{
    unsigned char buf[20];
    ASN1_INTEGER *nonce = NULL;
    int len = (bits - 1) / 8 + 1;
    int i;

    /* Generating random byte sequence. */
    if (len > (int)sizeof(buf))
        goto err;
    if (RAND_bytes(buf, len) <= 0)
        goto err;

    /* Find the first non-zero byte and creating ASN1_INTEGER object. */
    for (i = 0; i < len && !buf[i]; ++i) ;
    if (!(nonce = ASN1_INTEGER_new()))
        goto err;
    OPENSSL_free(nonce->data);
    /* Allocate at least one byte. */
    nonce->length = len - i;
    if (!(nonce->data = OPENSSL_malloc(nonce->length + 1)))
        goto err;
    memcpy(nonce->data, buf + i, nonce->length);

    return nonce;
 err:
    BIO_printf(bio_err, "\x63\x6f\x75\x6c\x64\x20\x6e\x6f\x74\x20\x63\x72\x65\x61\x74\x65\x20\x6e\x6f\x6e\x63\x65\xa");
    ASN1_INTEGER_free(nonce);
    return NULL;
}

/*
 * Reply-related method definitions.
 */

static int reply_command(CONF *conf, char *section, char *engine,
                         char *queryfile, char *passin, char *inkey,
                         char *signer, char *chain, const char *policy,
                         char *in, int token_in,
                         char *out, int token_out, int text)
{
    int ret = 0;
    TS_RESP *response = NULL;
    BIO *in_bio = NULL;
    BIO *query_bio = NULL;
    BIO *inkey_bio = NULL;
    BIO *signer_bio = NULL;
    BIO *out_bio = NULL;

    /* Build response object either from response or query. */
    if (in != NULL) {
        if ((in_bio = BIO_new_file(in, "\x72\x62")) == NULL)
            goto end;
        if (token_in) {
            /*
             * We have a ContentInfo (PKCS7) object, add 'granted' status
             * info around it.
             */
            response = read_PKCS7(in_bio);
        } else {
            /* We have a ready-made TS_RESP object. */
            response = d2i_TS_RESP_bio(in_bio, NULL);
        }
    } else {
        response = create_response(conf, section, engine, queryfile,
                                   passin, inkey, signer, chain, policy);
        if (response)
            BIO_printf(bio_err, "\x52\x65\x73\x70\x6f\x6e\x73\x65\x20\x68\x61\x73\x20\x62\x65\x65\x6e\x20\x67\x65\x6e\x65\x72\x61\x74\x65\x64\x2e\xa");
        else
            BIO_printf(bio_err, "\x52\x65\x73\x70\x6f\x6e\x73\x65\x20\x69\x73\x20\x6e\x6f\x74\x20\x67\x65\x6e\x65\x72\x61\x74\x65\x64\x2e\xa");
    }
    if (response == NULL)
        goto end;

    /* Write response either in ASN.1 or text format. */
    if ((out_bio = BIO_open_with_default(out, "\x77\x62", stdout)) == NULL)
        goto end;
    if (text) {
        /* Text output. */
        if (token_out) {
            TS_TST_INFO *tst_info = TS_RESP_get_tst_info(response);
            if (!TS_TST_INFO_print_bio(out_bio, tst_info))
                goto end;
        } else {
            if (!TS_RESP_print_bio(out_bio, response))
                goto end;
        }
    } else {
        /* ASN.1 DER output. */
        if (token_out) {
            PKCS7 *token = TS_RESP_get_token(response);
            if (!i2d_PKCS7_bio(out_bio, token))
                goto end;
        } else {
            if (!i2d_TS_RESP_bio(out_bio, response))
                goto end;
        }
    }

    ret = 1;

 end:
    ERR_print_errors(bio_err);

    /* Clean up. */
    BIO_free_all(in_bio);
    BIO_free_all(query_bio);
    BIO_free_all(inkey_bio);
    BIO_free_all(signer_bio);
    BIO_free_all(out_bio);
    TS_RESP_free(response);

    return ret;
}

/* Reads a PKCS7 token and adds default 'granted' status info to it. */
static TS_RESP *read_PKCS7(BIO *in_bio)
{
    int ret = 0;
    PKCS7 *token = NULL;
    TS_TST_INFO *tst_info = NULL;
    TS_RESP *resp = NULL;
    TS_STATUS_INFO *si = NULL;

    /* Read PKCS7 object and extract the signed time stamp info. */
    if (!(token = d2i_PKCS7_bio(in_bio, NULL)))
        goto end;
    if (!(tst_info = PKCS7_to_TS_TST_INFO(token)))
        goto end;

    /* Creating response object. */
    if (!(resp = TS_RESP_new()))
        goto end;

    /* Create granted status info. */
    if (!(si = TS_STATUS_INFO_new()))
        goto end;
    if (!(ASN1_INTEGER_set(si->status, TS_STATUS_GRANTED)))
        goto end;
    if (!TS_RESP_set_status_info(resp, si))
        goto end;

    /* Setting encapsulated token. */
    TS_RESP_set_tst_info(resp, token, tst_info);
    token = NULL;               /* Ownership is lost. */
    tst_info = NULL;            /* Ownership is lost. */

    ret = 1;
 end:
    PKCS7_free(token);
    TS_TST_INFO_free(tst_info);
    if (!ret) {
        TS_RESP_free(resp);
        resp = NULL;
    }
    TS_STATUS_INFO_free(si);
    return resp;
}

static TS_RESP *create_response(CONF *conf, const char *section, char *engine,
                                char *queryfile, char *passin, char *inkey,
                                char *signer, char *chain, const char *policy)
{
    int ret = 0;
    TS_RESP *response = NULL;
    BIO *query_bio = NULL;
    TS_RESP_CTX *resp_ctx = NULL;

    if (!(query_bio = BIO_new_file(queryfile, "\x72\x62")))
        goto end;

    /* Getting TSA configuration section. */
    if (!(section = TS_CONF_get_tsa_section(conf, section)))
        goto end;

    /* Setting up response generation context. */
    if (!(resp_ctx = TS_RESP_CTX_new()))
        goto end;

    /* Setting serial number provider callback. */
    if (!TS_CONF_set_serial(conf, section, serial_cb, resp_ctx))
        goto end;
#ifndef OPENSSL_NO_ENGINE
    /* Setting default OpenSSL engine. */
    if (!TS_CONF_set_crypto_device(conf, section, engine))
        goto end;
#endif

    /* Setting TSA signer certificate. */
    if (!TS_CONF_set_signer_cert(conf, section, signer, resp_ctx))
        goto end;

    /* Setting TSA signer certificate chain. */
    if (!TS_CONF_set_certs(conf, section, chain, resp_ctx))
        goto end;

    /* Setting TSA signer private key. */
    if (!TS_CONF_set_signer_key(conf, section, inkey, passin, resp_ctx))
        goto end;

    /* Setting default policy OID. */
    if (!TS_CONF_set_def_policy(conf, section, policy, resp_ctx))
        goto end;

    /* Setting acceptable policy OIDs. */
    if (!TS_CONF_set_policies(conf, section, resp_ctx))
        goto end;

    /* Setting the acceptable one-way hash algorithms. */
    if (!TS_CONF_set_digests(conf, section, resp_ctx))
        goto end;

    /* Setting guaranteed time stamp accuracy. */
    if (!TS_CONF_set_accuracy(conf, section, resp_ctx))
        goto end;

    /* Setting the precision of the time. */
    if (!TS_CONF_set_clock_precision_digits(conf, section, resp_ctx))
        goto end;

    /* Setting the ordering flaf if requested. */
    if (!TS_CONF_set_ordering(conf, section, resp_ctx))
        goto end;

    /* Setting the TSA name required flag if requested. */
    if (!TS_CONF_set_tsa_name(conf, section, resp_ctx))
        goto end;

    /* Setting the ESS cert id chain flag if requested. */
    if (!TS_CONF_set_ess_cert_id_chain(conf, section, resp_ctx))
        goto end;

    /* Creating the response. */
    if (!(response = TS_RESP_create_response(resp_ctx, query_bio)))
        goto end;

    ret = 1;
 end:
    if (!ret) {
        TS_RESP_free(response);
        response = NULL;
    }
    TS_RESP_CTX_free(resp_ctx);
    BIO_free_all(query_bio);

    return response;
}

static ASN1_INTEGER *MS_CALLBACK serial_cb(TS_RESP_CTX *ctx, void *data)
{
    const char *serial_file = (const char *)data;
    ASN1_INTEGER *serial = next_serial(serial_file);

    if (!serial) {
        TS_RESP_CTX_set_status_info(ctx, TS_STATUS_REJECTION,
                                    "\x45\x72\x72\x6f\x72\x20\x64\x75\x72\x69\x6e\x67\x20\x73\x65\x72\x69\x61\x6c\x20\x6e\x75\x6d\x62\x65\x72\x20"
                                    "\x67\x65\x6e\x65\x72\x61\x74\x69\x6f\x6e\x2e");
        TS_RESP_CTX_add_failure_info(ctx, TS_INFO_ADD_INFO_NOT_AVAILABLE);
    } else
        save_ts_serial(serial_file, serial);

    return serial;
}

static ASN1_INTEGER *next_serial(const char *serialfile)
{
    int ret = 0;
    BIO *in = NULL;
    ASN1_INTEGER *serial = NULL;
    BIGNUM *bn = NULL;

    if (!(serial = ASN1_INTEGER_new()))
        goto err;

    if (!(in = BIO_new_file(serialfile, "\x72"))) {
        ERR_clear_error();
        BIO_printf(bio_err, "\x57\x61\x72\x6e\x69\x6e\x67\x3a\x20\x63\x6f\x75\x6c\x64\x20\x6e\x6f\x74\x20\x6f\x70\x65\x6e\x20\x66\x69\x6c\x65\x20\x25\x73\x20\x66\x6f\x72\x20"
                   "\x72\x65\x61\x64\x69\x6e\x67\x2c\x20\x75\x73\x69\x6e\x67\x20\x73\x65\x72\x69\x61\x6c\x20\x6e\x75\x6d\x62\x65\x72\x3a\x20\x31\xa", serialfile);
        if (!ASN1_INTEGER_set(serial, 1))
            goto err;
    } else {
        char buf[1024];
        if (!a2i_ASN1_INTEGER(in, serial, buf, sizeof(buf))) {
            BIO_printf(bio_err, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x6c\x6f\x61\x64\x20\x6e\x75\x6d\x62\x65\x72\x20\x66\x72\x6f\x6d\x20\x25\x73\xa",
                       serialfile);
            goto err;
        }
        if (!(bn = ASN1_INTEGER_to_BN(serial, NULL)))
            goto err;
        ASN1_INTEGER_free(serial);
        serial = NULL;
        if (!BN_add_word(bn, 1))
            goto err;
        if (!(serial = BN_to_ASN1_INTEGER(bn, NULL)))
            goto err;
    }
    ret = 1;
 err:
    if (!ret) {
        ASN1_INTEGER_free(serial);
        serial = NULL;
    }
    BIO_free_all(in);
    BN_free(bn);
    return serial;
}

static int save_ts_serial(const char *serialfile, ASN1_INTEGER *serial)
{
    int ret = 0;
    BIO *out = NULL;

    if (!(out = BIO_new_file(serialfile, "\x77")))
        goto err;
    if (i2a_ASN1_INTEGER(out, serial) <= 0)
        goto err;
    if (BIO_puts(out, "\xa") <= 0)
        goto err;
    ret = 1;
 err:
    if (!ret)
        BIO_printf(bio_err, "\x63\x6f\x75\x6c\x64\x20\x6e\x6f\x74\x20\x73\x61\x76\x65\x20\x73\x65\x72\x69\x61\x6c\x20\x6e\x75\x6d\x62\x65\x72\x20\x74\x6f\x20\x25\x73\xa",
                   serialfile);
    BIO_free_all(out);
    return ret;
}

/*
 * Verify-related method definitions.
 */

static int verify_command(char *data, char *digest, char *queryfile,
                          char *in, int token_in,
                          char *ca_path, char *ca_file, char *untrusted)
{
    BIO *in_bio = NULL;
    PKCS7 *token = NULL;
    TS_RESP *response = NULL;
    TS_VERIFY_CTX *verify_ctx = NULL;
    int ret = 0;

    /* Decode the token (PKCS7) or response (TS_RESP) files. */
    if (!(in_bio = BIO_new_file(in, "\x72\x62")))
        goto end;
    if (token_in) {
        if (!(token = d2i_PKCS7_bio(in_bio, NULL)))
            goto end;
    } else {
        if (!(response = d2i_TS_RESP_bio(in_bio, NULL)))
            goto end;
    }

    if (!(verify_ctx = create_verify_ctx(data, digest, queryfile,
                                         ca_path, ca_file, untrusted)))
        goto end;

    /* Checking the token or response against the request. */
    ret = token_in ?
        TS_RESP_verify_token(verify_ctx, token) :
        TS_RESP_verify_response(verify_ctx, response);

 end:
    printf("\x56\x65\x72\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x3a\x20");
    if (ret)
        printf("\x4f\x4b\xa");
    else {
        printf("\x46\x41\x49\x4c\x45\x44\xa");
        /* Print errors, if there are any. */
        ERR_print_errors(bio_err);
    }

    /* Clean up. */
    BIO_free_all(in_bio);
    PKCS7_free(token);
    TS_RESP_free(response);
    TS_VERIFY_CTX_free(verify_ctx);
    return ret;
}

static TS_VERIFY_CTX *create_verify_ctx(char *data, char *digest,
                                        char *queryfile,
                                        char *ca_path, char *ca_file,
                                        char *untrusted)
{
    TS_VERIFY_CTX *ctx = NULL;
    BIO *input = NULL;
    TS_REQ *request = NULL;
    int ret = 0;

    if (data != NULL || digest != NULL) {
        if (!(ctx = TS_VERIFY_CTX_new()))
            goto err;
        ctx->flags = TS_VFY_VERSION | TS_VFY_SIGNER;
        if (data != NULL) {
            ctx->flags |= TS_VFY_DATA;
            if (!(ctx->data = BIO_new_file(data, "\x72\x62")))
                goto err;
        } else if (digest != NULL) {
            long imprint_len;
            ctx->flags |= TS_VFY_IMPRINT;
            if (!(ctx->imprint = string_to_hex(digest, &imprint_len))) {
                BIO_printf(bio_err, "\x69\x6e\x76\x61\x6c\x69\x64\x20\x64\x69\x67\x65\x73\x74\x20\x73\x74\x72\x69\x6e\x67\xa");
                goto err;
            }
            ctx->imprint_len = imprint_len;
        }

    } else if (queryfile != NULL) {
        /*
         * The request has just to be read, decoded and converted to a verify
         * context object.
         */
        if (!(input = BIO_new_file(queryfile, "\x72\x62")))
            goto err;
        if (!(request = d2i_TS_REQ_bio(input, NULL)))
            goto err;
        if (!(ctx = TS_REQ_to_TS_VERIFY_CTX(request, NULL)))
            goto err;
    } else
        return NULL;

    /* Add the signature verification flag and arguments. */
    ctx->flags |= TS_VFY_SIGNATURE;

    /* Initialising the X509_STORE object. */
    if (!(ctx->store = create_cert_store(ca_path, ca_file)))
        goto err;

    /* Loading untrusted certificates. */
    if (untrusted && !(ctx->certs = TS_CONF_load_certs(untrusted)))
        goto err;

    ret = 1;
 err:
    if (!ret) {
        TS_VERIFY_CTX_free(ctx);
        ctx = NULL;
    }
    BIO_free_all(input);
    TS_REQ_free(request);
    return ctx;
}

static X509_STORE *create_cert_store(char *ca_path, char *ca_file)
{
    X509_STORE *cert_ctx = NULL;
    X509_LOOKUP *lookup = NULL;
    int i;

    /* Creating the X509_STORE object. */
    cert_ctx = X509_STORE_new();

    /* Setting the callback for certificate chain verification. */
    X509_STORE_set_verify_cb(cert_ctx, verify_cb);

    /* Adding a trusted certificate directory source. */
    if (ca_path) {
        lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_hash_dir());
        if (lookup == NULL) {
            BIO_printf(bio_err, "\x6d\x65\x6d\x6f\x72\x79\x20\x61\x6c\x6c\x6f\x63\x61\x74\x69\x6f\x6e\x20\x66\x61\x69\x6c\x75\x72\x65\xa");
            goto err;
        }
        i = X509_LOOKUP_add_dir(lookup, ca_path, X509_FILETYPE_PEM);
        if (!i) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x6c\x6f\x61\x64\x69\x6e\x67\x20\x64\x69\x72\x65\x63\x74\x6f\x72\x79\x20\x25\x73\xa", ca_path);
            goto err;
        }
    }

    /* Adding a trusted certificate file source. */
    if (ca_file) {
        lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_file());
        if (lookup == NULL) {
            BIO_printf(bio_err, "\x6d\x65\x6d\x6f\x72\x79\x20\x61\x6c\x6c\x6f\x63\x61\x74\x69\x6f\x6e\x20\x66\x61\x69\x6c\x75\x72\x65\xa");
            goto err;
        }
        i = X509_LOOKUP_load_file(lookup, ca_file, X509_FILETYPE_PEM);
        if (!i) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x6c\x6f\x61\x64\x69\x6e\x67\x20\x66\x69\x6c\x65\x20\x25\x73\xa", ca_file);
            goto err;
        }
    }

    return cert_ctx;
 err:
    X509_STORE_free(cert_ctx);
    return NULL;
}

static int MS_CALLBACK verify_cb(int ok, X509_STORE_CTX *ctx)
{
    /*-
    char buf[256];

    if (!ok)
            {
            X509_NAME_oneline(X509_get_subject_name(ctx->current_cert),
                              buf, sizeof(buf));
            printf("%s\n", buf);
            printf("error %d at %d depth lookup: %s\n",
                   ctx->error, ctx->error_depth,
                    X509_verify_cert_error_string(ctx->error));
            }
    */

    return ok;
}
