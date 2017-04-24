/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "ssltestlib.h"
#include "testutil.h"

static char *cert = NULL;
static char *privkey = NULL;

#define NUM_TESTS   2


#define DUMMY_CERT_STATUS_LEN  12

unsigned char certstatus[] = {
    SSL3_RT_HANDSHAKE, /* Content type */
    0xfe, 0xfd, /* Record version */
    0, 1, /* Epoch */
    0, 0, 0, 0, 0, 0x0f, /* Record sequence number */
    0, DTLS1_HM_HEADER_LENGTH + DUMMY_CERT_STATUS_LEN - 2,
    SSL3_MT_CERTIFICATE_STATUS, /* Cert Status handshake message type */
    0, 0, DUMMY_CERT_STATUS_LEN, /* Message len */
    0, 5, /* Message sequence */
    0, 0, 0, /* Fragment offset */
    0, 0, DUMMY_CERT_STATUS_LEN - 2, /* Fragment len */
    0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80 /* Dummy data */
};

#define RECORD_SEQUENCE 10

static int test_dtls_unprocessed(int testidx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl1 = NULL, *clientssl1 = NULL;
    BIO *c_to_s_fbio, *c_to_s_mempacket;
    int testresult = 0;

    printf("\x53\x74\x61\x72\x74\x69\x6e\x67\x20\x54\x65\x73\x74\x20\x25\x64\xa", testidx);

    if (!create_ssl_ctx_pair(DTLS_server_method(), DTLS_client_method(), &sctx,
                             &cctx, cert, privkey)) {
        printf("\x55\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x63\x72\x65\x61\x74\x65\x20\x53\x53\x4c\x5f\x43\x54\x58\x20\x70\x61\x69\x72\xa");
        return 0;
    }

    if (!SSL_CTX_set_ecdh_auto(sctx, 1)) {
        printf("\x46\x61\x69\x6c\x65\x64\x20\x63\x6f\x6e\x66\x69\x67\x75\x72\x69\x6e\x67\x20\x61\x75\x74\x6f\x20\x45\x43\x44\x48\xa");
    }

    if (!SSL_CTX_set_cipher_list(cctx, "\x41\x45\x53\x31\x32\x38\x2d\x53\x48\x41")) {
        printf("\x46\x61\x69\x6c\x65\x64\x20\x73\x65\x74\x74\x69\x6e\x67\x20\x63\x69\x70\x68\x65\x72\x20\x6c\x69\x73\x74\xa");
    }

    c_to_s_fbio = BIO_new(bio_f_tls_dump_filter());
    if (c_to_s_fbio == NULL) {
        printf("\x46\x61\x69\x6c\x65\x64\x20\x74\x6f\x20\x63\x72\x65\x61\x74\x65\x20\x66\x69\x6c\x74\x65\x72\x20\x42\x49\x4f\xa");
        goto end;
    }

    /* BIO is freed by create_ssl_connection on error */
    if (!create_ssl_objects(sctx, cctx, &serverssl1, &clientssl1, NULL,
                               c_to_s_fbio)) {
        printf("\x55\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x63\x72\x65\x61\x74\x65\x20\x53\x53\x4c\x20\x6f\x62\x6a\x65\x63\x74\x73\xa");
        ERR_print_errors_fp(stdout);
        goto end;
    }

    if (testidx == 1)
        certstatus[RECORD_SEQUENCE] = 0xff;

    /*
     * Inject a dummy record from the next epoch. In test 0, this should never
     * get used because the message sequence number is too big. In test 1 we set
     * the record sequence number to be way off in the future. This should not
     * have an impact on the record replay protection because the record should
     * be dropped before it is marked as arrivedg
     */
    c_to_s_mempacket = SSL_get_wbio(clientssl1);
    c_to_s_mempacket = BIO_next(c_to_s_mempacket);
    mempacket_test_inject(c_to_s_mempacket, (char *)certstatus,
                          sizeof(certstatus), 1, INJECT_PACKET_IGNORE_REC_SEQ);

    if (!create_ssl_connection(serverssl1, clientssl1)) {
        printf("\x55\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x63\x72\x65\x61\x74\x65\x20\x53\x53\x4c\x20\x63\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\xa");
        ERR_print_errors_fp(stdout);
        goto end;
    }

    testresult = 1;
 end:
    SSL_free(serverssl1);
    SSL_free(clientssl1);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}

int main(int argc, char *argv[])
{
    BIO *err = NULL;
    int testresult = 0;

    if (argc != 3) {
        printf("\x49\x6e\x76\x61\x6c\x69\x64\x20\x61\x72\x67\x75\x6d\x65\x6e\x74\x20\x63\x6f\x75\x6e\x74\xa");
        return 1;
    }

    cert = argv[1];
    privkey = argv[2];

    err = BIO_new_fp(stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    SSL_library_init();
    SSL_load_error_strings();

    CRYPTO_malloc_debug_init();
    CRYPTO_dbg_set_options(V_CRYPTO_MDEBUG_ALL);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    if (!test_dtls_unprocessed(0) || !test_dtls_unprocessed(1))
        testresult = 1;

    ERR_free_strings();
    ERR_remove_thread_state(NULL);
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    CRYPTO_mem_leaks(err);
    BIO_free(err);

    if (!testresult)
        printf("\x50\x41\x53\x53\xa");

    return testresult;
}
