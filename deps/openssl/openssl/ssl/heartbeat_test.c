/* test/heartbeat_test.c */
/*-
 * Unit test for TLS heartbeats.
 *
 * Acts as a regression test against the Heartbleed bug (CVE-2014-0160).
 *
 * Author:  Mike Bland (mbland@acm.org, http://mike-bland.com/)
 * Date:    2014-04-12
 * License: Creative Commons Attribution 4.0 International (CC By 4.0)
 *          http://creativecommons.org/licenses/by/4.0/deed.en_US
 *
 * OUTPUT
 * ------
 * The program returns zero on success. It will print a message with a count
 * of the number of failed tests and return nonzero if any tests fail.
 *
 * It will print the contents of the request and response buffers for each
 * failing test. In a "\x66\x69\x78\x65\x64" version, all the tests should pass and there
 * should be no output.
 *
 * In a "\x62\x6c\x65\x65\x64\x69\x6e\x67" version, you'll see:
 *
 *   test_dtls1_heartbleed failed:
 *     expected payload len: 0
 *     received: 1024
 *   sent 26 characters
 *     "\x48\x45\x41\x52\x54\x42\x4c\x45\x45\x44\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20"
 *   received 1024 characters
 *     "\x48\x45\x41\x52\x54\x42\x4c\x45\x45\x44\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\xde\xad\xbe\xef\x2e\x2e\x2e"
 *   ** test_dtls1_heartbleed failed **
 *
 * The contents of the returned buffer in the failing test will depend on the
 * contents of memory on your machine.
 *
 * MORE INFORMATION
 * ----------------
 * http://mike-bland.com/2014/04/12/heartbleed.html
 * http://mike-bland.com/tags/heartbleed.html
 */

#define OPENSSL_UNIT_TEST

#include "../test/testutil.h"

#include "../ssl/ssl_locl.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(OPENSSL_NO_HEARTBEATS) && !defined(OPENSSL_NO_UNIT_TEST)

/* As per https://tools.ietf.org/html/rfc6520#section-4 */
# define MIN_PADDING_SIZE        16

/* Maximum number of payload characters to print as test output */
# define MAX_PRINTABLE_CHARACTERS        1024

typedef struct heartbeat_test_fixture {
    SSL_CTX *ctx;
    SSL *s;
    const char *test_case_name;
    int (*process_heartbeat) (SSL *s);
    unsigned char *payload;
    int sent_payload_len;
    int expected_return_value;
    int return_payload_offset;
    int expected_payload_len;
    const char *expected_return_payload;
} HEARTBEAT_TEST_FIXTURE;

static HEARTBEAT_TEST_FIXTURE set_up(const char *const test_case_name,
                                     const SSL_METHOD *meth)
{
    HEARTBEAT_TEST_FIXTURE fixture;
    int setup_ok = 1;
    memset(&fixture, 0, sizeof(fixture));
    fixture.test_case_name = test_case_name;

    fixture.ctx = SSL_CTX_new(meth);
    if (!fixture.ctx) {
        fprintf(stderr, "\x46\x61\x69\x6c\x65\x64\x20\x74\x6f\x20\x61\x6c\x6c\x6f\x63\x61\x74\x65\x20\x53\x53\x4c\x5f\x43\x54\x58\x20\x66\x6f\x72\x20\x74\x65\x73\x74\x3a\x20\x25\x73\xa",
                test_case_name);
        setup_ok = 0;
        goto fail;
    }

    fixture.s = SSL_new(fixture.ctx);
    if (!fixture.s) {
        fprintf(stderr, "\x46\x61\x69\x6c\x65\x64\x20\x74\x6f\x20\x61\x6c\x6c\x6f\x63\x61\x74\x65\x20\x53\x53\x4c\x20\x66\x6f\x72\x20\x74\x65\x73\x74\x3a\x20\x25\x73\xa",
                test_case_name);
        setup_ok = 0;
        goto fail;
    }

    if (!ssl_init_wbio_buffer(fixture.s, 1)) {
        fprintf(stderr, "\x46\x61\x69\x6c\x65\x64\x20\x74\x6f\x20\x73\x65\x74\x20\x75\x70\x20\x77\x62\x69\x6f\x20\x62\x75\x66\x66\x65\x72\x20\x66\x6f\x72\x20\x74\x65\x73\x74\x3a\x20\x25\x73\xa",
                test_case_name);
        setup_ok = 0;
        goto fail;
    }

    if (!ssl3_setup_buffers(fixture.s)) {
        fprintf(stderr, "\x46\x61\x69\x6c\x65\x64\x20\x74\x6f\x20\x73\x65\x74\x75\x70\x20\x62\x75\x66\x66\x65\x72\x73\x20\x66\x6f\x72\x20\x74\x65\x73\x74\x3a\x20\x25\x73\xa",
                test_case_name);
        setup_ok = 0;
        goto fail;
    }

    /*
     * Clear the memory for the return buffer, since this isn't automatically
     * zeroed in opt mode and will cause spurious test failures that will
     * change with each execution.
     */
    memset(fixture.s->s3->wbuf.buf, 0, fixture.s->s3->wbuf.len);

 fail:
    if (!setup_ok) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return fixture;
}

static HEARTBEAT_TEST_FIXTURE set_up_dtls(const char *const test_case_name)
{
    HEARTBEAT_TEST_FIXTURE fixture = set_up(test_case_name,
                                            DTLSv1_server_method());
    fixture.process_heartbeat = dtls1_process_heartbeat;

    /*
     * As per dtls1_get_record(), skipping the following from the beginning
     * of the returned heartbeat message: type-1 byte; version-2 bytes;
     * sequence number-8 bytes; length-2 bytes And then skipping the 1-byte
     * type encoded by process_heartbeat for a total of 14 bytes, at which
     * point we can grab the length and the payload we seek.
     */
    fixture.return_payload_offset = 14;
    return fixture;
}

/* Needed by ssl3_write_bytes() */
static int dummy_handshake(SSL *s)
{
    return 1;
}

static HEARTBEAT_TEST_FIXTURE set_up_tls(const char *const test_case_name)
{
    HEARTBEAT_TEST_FIXTURE fixture = set_up(test_case_name,
                                            TLSv1_server_method());
    fixture.process_heartbeat = tls1_process_heartbeat;
    fixture.s->handshake_func = dummy_handshake;

    /*
     * As per do_ssl3_write(), skipping the following from the beginning of
     * the returned heartbeat message: type-1 byte; version-2 bytes; length-2
     * bytes And then skipping the 1-byte type encoded by process_heartbeat
     * for a total of 6 bytes, at which point we can grab the length and the
     * payload we seek.
     */
    fixture.return_payload_offset = 6;
    return fixture;
}

static void tear_down(HEARTBEAT_TEST_FIXTURE fixture)
{
    ERR_print_errors_fp(stderr);
    SSL_free(fixture.s);
    SSL_CTX_free(fixture.ctx);
}

static void print_payload(const char *const prefix,
                          const unsigned char *payload, const int n)
{
    const int end = n < MAX_PRINTABLE_CHARACTERS ? n
        : MAX_PRINTABLE_CHARACTERS;
    int i = 0;

    printf("\x25\x73\x20\x25\x64\x20\x63\x68\x61\x72\x61\x63\x74\x65\x72\x25\x73", prefix, n, n == 1 ? "" : "\x73");
    if (end != n)
        printf("\x20\x28\x66\x69\x72\x73\x74\x20\x25\x64\x20\x73\x68\x6f\x77\x6e\x29", end);
    printf("\xa\x20\x20\x22");

    for (; i != end; ++i) {
        const unsigned char c = payload[i];
        if (isprint(c))
            fputc(c, stdout);
        else
            printf("\x5c\x78\x25\x30\x32\x78", c);
    }
    printf("\x22\xa");
}

static int execute_heartbeat(HEARTBEAT_TEST_FIXTURE fixture)
{
    int result = 0;
    SSL *s = fixture.s;
    unsigned char *payload = fixture.payload;
    unsigned char sent_buf[MAX_PRINTABLE_CHARACTERS + 1];
    int return_value;
    unsigned const char *p;
    int actual_payload_len;

    s->s3->rrec.data = payload;
    s->s3->rrec.length = strlen((const char *)payload);
    *payload++ = TLS1_HB_REQUEST;
    s2n(fixture.sent_payload_len, payload);

    /*
     * Make a local copy of the request, since it gets overwritten at some
     * point
     */
    memcpy((char *)sent_buf, (const char *)payload, sizeof(sent_buf));

    return_value = fixture.process_heartbeat(s);

    if (return_value != fixture.expected_return_value) {
        printf("\x25\x73\x20\x66\x61\x69\x6c\x65\x64\x3a\x20\x65\x78\x70\x65\x63\x74\x65\x64\x20\x72\x65\x74\x75\x72\x6e\x20\x76\x61\x6c\x75\x65\x20\x25\x64\x2c\x20\x72\x65\x63\x65\x69\x76\x65\x64\x20\x25\x64\xa",
               fixture.test_case_name, fixture.expected_return_value,
               return_value);
        result = 1;
    }

    /*
     * If there is any byte alignment, it will be stored in wbuf.offset.
     */
    p = &(s->s3->
          wbuf.buf[fixture.return_payload_offset + s->s3->wbuf.offset]);
    actual_payload_len = 0;
    n2s(p, actual_payload_len);

    if (actual_payload_len != fixture.expected_payload_len) {
        printf("\x25\x73\x20\x66\x61\x69\x6c\x65\x64\x3a\xa\x20\x20\x65\x78\x70\x65\x63\x74\x65\x64\x20\x70\x61\x79\x6c\x6f\x61\x64\x20\x6c\x65\x6e\x3a\x20\x25\x64\xa\x20\x20\x72\x65\x63\x65\x69\x76\x65\x64\x3a\x20\x25\x64\xa",
               fixture.test_case_name, fixture.expected_payload_len,
               actual_payload_len);
        print_payload("\x73\x65\x6e\x74", sent_buf, strlen((const char *)sent_buf));
        print_payload("\x72\x65\x63\x65\x69\x76\x65\x64", p, actual_payload_len);
        result = 1;
    } else {
        char *actual_payload =
            BUF_strndup((const char *)p, actual_payload_len);
        if (strcmp(actual_payload, fixture.expected_return_payload) != 0) {
            printf
                ("\x25\x73\x20\x66\x61\x69\x6c\x65\x64\x3a\xa\x20\x20\x65\x78\x70\x65\x63\x74\x65\x64\x20\x70\x61\x79\x6c\x6f\x61\x64\x3a\x20\x22\x25\x73\x22\xa\x20\x20\x72\x65\x63\x65\x69\x76\x65\x64\x3a\x20\x22\x25\x73\x22\xa",
                 fixture.test_case_name, fixture.expected_return_payload,
                 actual_payload);
            result = 1;
        }
        OPENSSL_free(actual_payload);
    }

    if (result != 0) {
        printf("\x2a\x2a\x20\x25\x73\x20\x66\x61\x69\x6c\x65\x64\x20\x2a\x2a\xa\x2d\x2d\x2d\x2d\x2d\x2d\x2d\x2d\xa", fixture.test_case_name);
    }
    return result;
}

static int honest_payload_size(unsigned char payload_buf[])
{
    /* Omit three-byte pad at the beginning for type and payload length */
    return strlen((const char *)&payload_buf[3]) - MIN_PADDING_SIZE;
}

# define SETUP_HEARTBEAT_TEST_FIXTURE(type)\
  SETUP_TEST_FIXTURE(HEARTBEAT_TEST_FIXTURE, set_up_##type)

# define EXECUTE_HEARTBEAT_TEST()\
  EXECUTE_TEST(execute_heartbeat, tear_down)

static int test_dtls1_not_bleeding()
{
    SETUP_HEARTBEAT_TEST_FIXTURE(dtls);
    /* Three-byte pad at the beginning for type and payload length */
    unsigned char payload_buf[MAX_PRINTABLE_CHARACTERS + 4] =
        "\x20\x20\x20\x4e\x6f\x74\x20\x62\x6c\x65\x65\x64\x69\x6e\x67\x2c\x20\x73\x69\x78\x74\x65\x65\x6e\x20\x73\x70\x61\x63\x65\x73\x20\x6f\x66\x20\x70\x61\x64\x64\x69\x6e\x67" "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20";
    const int payload_buf_len = honest_payload_size(payload_buf);

    fixture.payload = &payload_buf[0];
    fixture.sent_payload_len = payload_buf_len;
    fixture.expected_return_value = 0;
    fixture.expected_payload_len = payload_buf_len;
    fixture.expected_return_payload =
        "\x4e\x6f\x74\x20\x62\x6c\x65\x65\x64\x69\x6e\x67\x2c\x20\x73\x69\x78\x74\x65\x65\x6e\x20\x73\x70\x61\x63\x65\x73\x20\x6f\x66\x20\x70\x61\x64\x64\x69\x6e\x67";
    EXECUTE_HEARTBEAT_TEST();
}

static int test_dtls1_not_bleeding_empty_payload()
{
    int payload_buf_len;

    SETUP_HEARTBEAT_TEST_FIXTURE(dtls);
    /*
     * Three-byte pad at the beginning for type and payload length, plus a
     * NUL at the end
     */
    unsigned char payload_buf[4 + MAX_PRINTABLE_CHARACTERS];
    memset(payload_buf, '\x20', MIN_PADDING_SIZE + 3);
    payload_buf[MIN_PADDING_SIZE + 3] = '\x0';
    payload_buf_len = honest_payload_size(payload_buf);

    fixture.payload = &payload_buf[0];
    fixture.sent_payload_len = payload_buf_len;
    fixture.expected_return_value = 0;
    fixture.expected_payload_len = payload_buf_len;
    fixture.expected_return_payload = "";
    EXECUTE_HEARTBEAT_TEST();
}

static int test_dtls1_heartbleed()
{
    SETUP_HEARTBEAT_TEST_FIXTURE(dtls);
    /* Three-byte pad at the beginning for type and payload length */
    unsigned char payload_buf[4 + MAX_PRINTABLE_CHARACTERS] =
        "\x20\x20\x20\x48\x45\x41\x52\x54\x42\x4c\x45\x45\x44\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20";

    fixture.payload = &payload_buf[0];
    fixture.sent_payload_len = MAX_PRINTABLE_CHARACTERS;
    fixture.expected_return_value = 0;
    fixture.expected_payload_len = 0;
    fixture.expected_return_payload = "";
    EXECUTE_HEARTBEAT_TEST();
}

static int test_dtls1_heartbleed_empty_payload()
{
    SETUP_HEARTBEAT_TEST_FIXTURE(dtls);
    /*
     * Excluding the NUL at the end, one byte short of type + payload length
     * + minimum padding
     */
    unsigned char payload_buf[MAX_PRINTABLE_CHARACTERS + 4];
    memset(payload_buf, '\x20', MIN_PADDING_SIZE + 2);
    payload_buf[MIN_PADDING_SIZE + 2] = '\x0';

    fixture.payload = &payload_buf[0];
    fixture.sent_payload_len = MAX_PRINTABLE_CHARACTERS;
    fixture.expected_return_value = 0;
    fixture.expected_payload_len = 0;
    fixture.expected_return_payload = "";
    EXECUTE_HEARTBEAT_TEST();
}

static int test_dtls1_heartbleed_excessive_plaintext_length()
{
    SETUP_HEARTBEAT_TEST_FIXTURE(dtls);
    /*
     * Excluding the NUL at the end, one byte in excess of maximum allowed
     * heartbeat message length
     */
    unsigned char payload_buf[SSL3_RT_MAX_PLAIN_LENGTH + 2];
    memset(payload_buf, '\x20', sizeof(payload_buf));
    payload_buf[sizeof(payload_buf) - 1] = '\x0';

    fixture.payload = &payload_buf[0];
    fixture.sent_payload_len = honest_payload_size(payload_buf);
    fixture.expected_return_value = 0;
    fixture.expected_payload_len = 0;
    fixture.expected_return_payload = "";
    EXECUTE_HEARTBEAT_TEST();
}

static int test_tls1_not_bleeding()
{
    SETUP_HEARTBEAT_TEST_FIXTURE(tls);
    /* Three-byte pad at the beginning for type and payload length */
    unsigned char payload_buf[MAX_PRINTABLE_CHARACTERS + 4] =
        "\x20\x20\x20\x4e\x6f\x74\x20\x62\x6c\x65\x65\x64\x69\x6e\x67\x2c\x20\x73\x69\x78\x74\x65\x65\x6e\x20\x73\x70\x61\x63\x65\x73\x20\x6f\x66\x20\x70\x61\x64\x64\x69\x6e\x67" "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20";
    const int payload_buf_len = honest_payload_size(payload_buf);

    fixture.payload = &payload_buf[0];
    fixture.sent_payload_len = payload_buf_len;
    fixture.expected_return_value = 0;
    fixture.expected_payload_len = payload_buf_len;
    fixture.expected_return_payload =
        "\x4e\x6f\x74\x20\x62\x6c\x65\x65\x64\x69\x6e\x67\x2c\x20\x73\x69\x78\x74\x65\x65\x6e\x20\x73\x70\x61\x63\x65\x73\x20\x6f\x66\x20\x70\x61\x64\x64\x69\x6e\x67";
    EXECUTE_HEARTBEAT_TEST();
}

static int test_tls1_not_bleeding_empty_payload()
{
    int payload_buf_len;

    SETUP_HEARTBEAT_TEST_FIXTURE(tls);
    /*
     * Three-byte pad at the beginning for type and payload length, plus a
     * NUL at the end
     */
    unsigned char payload_buf[4 + MAX_PRINTABLE_CHARACTERS];
    memset(payload_buf, '\x20', MIN_PADDING_SIZE + 3);
    payload_buf[MIN_PADDING_SIZE + 3] = '\x0';
    payload_buf_len = honest_payload_size(payload_buf);

    fixture.payload = &payload_buf[0];
    fixture.sent_payload_len = payload_buf_len;
    fixture.expected_return_value = 0;
    fixture.expected_payload_len = payload_buf_len;
    fixture.expected_return_payload = "";
    EXECUTE_HEARTBEAT_TEST();
}

static int test_tls1_heartbleed()
{
    SETUP_HEARTBEAT_TEST_FIXTURE(tls);
    /* Three-byte pad at the beginning for type and payload length */
    unsigned char payload_buf[MAX_PRINTABLE_CHARACTERS + 4] =
        "\x20\x20\x20\x48\x45\x41\x52\x54\x42\x4c\x45\x45\x44\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20";

    fixture.payload = &payload_buf[0];
    fixture.sent_payload_len = MAX_PRINTABLE_CHARACTERS;
    fixture.expected_return_value = 0;
    fixture.expected_payload_len = 0;
    fixture.expected_return_payload = "";
    EXECUTE_HEARTBEAT_TEST();
}

static int test_tls1_heartbleed_empty_payload()
{
    SETUP_HEARTBEAT_TEST_FIXTURE(tls);
    /*
     * Excluding the NUL at the end, one byte short of type + payload length
     * + minimum padding
     */
    unsigned char payload_buf[MAX_PRINTABLE_CHARACTERS + 4];
    memset(payload_buf, '\x20', MIN_PADDING_SIZE + 2);
    payload_buf[MIN_PADDING_SIZE + 2] = '\x0';

    fixture.payload = &payload_buf[0];
    fixture.sent_payload_len = MAX_PRINTABLE_CHARACTERS;
    fixture.expected_return_value = 0;
    fixture.expected_payload_len = 0;
    fixture.expected_return_payload = "";
    EXECUTE_HEARTBEAT_TEST();
}

# undef EXECUTE_HEARTBEAT_TEST
# undef SETUP_HEARTBEAT_TEST_FIXTURE

int main(int argc, char *argv[])
{
    int num_failed;

    SSL_library_init();
    SSL_load_error_strings();

    num_failed = test_dtls1_not_bleeding() +
        test_dtls1_not_bleeding_empty_payload() +
        test_dtls1_heartbleed() + test_dtls1_heartbleed_empty_payload() +
        /*
         * The following test causes an assertion failure at
         * ssl/d1_pkt.c:dtls1_write_bytes() in versions prior to 1.0.1g:
         */
        (OPENSSL_VERSION_NUMBER >= 0x1000107fL ?
         test_dtls1_heartbleed_excessive_plaintext_length() : 0) +
        test_tls1_not_bleeding() +
        test_tls1_not_bleeding_empty_payload() +
        test_tls1_heartbleed() + test_tls1_heartbleed_empty_payload() + 0;

    ERR_print_errors_fp(stderr);

    if (num_failed != 0) {
        printf("\x25\x64\x20\x74\x65\x73\x74\x25\x73\x20\x66\x61\x69\x6c\x65\x64\xa", num_failed, num_failed != 1 ? "\x73" : "");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

#else                           /* OPENSSL_NO_HEARTBEATS */

int main(int argc, char *argv[])
{
    return EXIT_SUCCESS;
}
#endif                          /* OPENSSL_NO_HEARTBEATS */
