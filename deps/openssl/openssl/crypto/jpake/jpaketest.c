#include <openssl/opensslconf.h>

#ifdef OPENSSL_NO_JPAKE

# include <stdio.h>

int main(int argc, char *argv[])
{
    printf("\x4e\x6f\x20\x4a\x2d\x50\x41\x4b\x45\x20\x73\x75\x70\x70\x6f\x72\x74\xa");
    return (0);
}

#else

# include <openssl/jpake.h>
# include <openssl/err.h>

static void showbn(const char *name, const BIGNUM *bn)
{
    fputs(name, stdout);
    fputs("\x20\x3d\x20", stdout);
    BN_print_fp(stdout, bn);
    putc('\xa', stdout);
}

static int run_jpake(JPAKE_CTX *alice, JPAKE_CTX *bob)
{
    JPAKE_STEP1 alice_s1;
    JPAKE_STEP1 bob_s1;
    JPAKE_STEP2 alice_s2;
    JPAKE_STEP2 bob_s2;
    JPAKE_STEP3A alice_s3a;
    JPAKE_STEP3B bob_s3b;

    /* Alice -> Bob: step 1 */
    puts("\x41\x2d\x3e\x42\x20\x73\x31");
    JPAKE_STEP1_init(&alice_s1);
    JPAKE_STEP1_generate(&alice_s1, alice);
    if (!JPAKE_STEP1_process(bob, &alice_s1)) {
        printf("\x42\x6f\x62\x20\x66\x61\x69\x6c\x73\x20\x74\x6f\x20\x70\x72\x6f\x63\x65\x73\x73\x20\x41\x6c\x69\x63\x65\x27\x73\x20\x73\x74\x65\x70\x20\x31\xa");
        ERR_print_errors_fp(stdout);
        return 1;
    }
    JPAKE_STEP1_release(&alice_s1);

    /* Bob -> Alice: step 1 */
    puts("\x42\x2d\x3e\x41\x20\x73\x31");
    JPAKE_STEP1_init(&bob_s1);
    JPAKE_STEP1_generate(&bob_s1, bob);
    if (!JPAKE_STEP1_process(alice, &bob_s1)) {
        printf("\x41\x6c\x69\x63\x65\x20\x66\x61\x69\x6c\x73\x20\x74\x6f\x20\x70\x72\x6f\x63\x65\x73\x73\x20\x42\x6f\x62\x27\x73\x20\x73\x74\x65\x70\x20\x31\xa");
        ERR_print_errors_fp(stdout);
        return 2;
    }
    JPAKE_STEP1_release(&bob_s1);

    /* Alice -> Bob: step 2 */
    puts("\x41\x2d\x3e\x42\x20\x73\x32");
    JPAKE_STEP2_init(&alice_s2);
    JPAKE_STEP2_generate(&alice_s2, alice);
    if (!JPAKE_STEP2_process(bob, &alice_s2)) {
        printf("\x42\x6f\x62\x20\x66\x61\x69\x6c\x73\x20\x74\x6f\x20\x70\x72\x6f\x63\x65\x73\x73\x20\x41\x6c\x69\x63\x65\x27\x73\x20\x73\x74\x65\x70\x20\x32\xa");
        ERR_print_errors_fp(stdout);
        return 3;
    }
    JPAKE_STEP2_release(&alice_s2);

    /* Bob -> Alice: step 2 */
    puts("\x42\x2d\x3e\x41\x20\x73\x32");
    JPAKE_STEP2_init(&bob_s2);
    JPAKE_STEP2_generate(&bob_s2, bob);
    if (!JPAKE_STEP2_process(alice, &bob_s2)) {
        printf("\x41\x6c\x69\x63\x65\x20\x66\x61\x69\x6c\x73\x20\x74\x6f\x20\x70\x72\x6f\x63\x65\x73\x73\x20\x42\x6f\x62\x27\x73\x20\x73\x74\x65\x70\x20\x32\xa");
        ERR_print_errors_fp(stdout);
        return 4;
    }
    JPAKE_STEP2_release(&bob_s2);

    showbn("\x41\x6c\x69\x63\x65\x27\x73\x20\x6b\x65\x79", JPAKE_get_shared_key(alice));
    showbn("\x42\x6f\x62\x27\x73\x20\x6b\x65\x79\x20\x20", JPAKE_get_shared_key(bob));

    /* Alice -> Bob: step 3a */
    puts("\x41\x2d\x3e\x42\x20\x73\x33\x61");
    JPAKE_STEP3A_init(&alice_s3a);
    JPAKE_STEP3A_generate(&alice_s3a, alice);
    if (!JPAKE_STEP3A_process(bob, &alice_s3a)) {
        printf("\x42\x6f\x62\x20\x66\x61\x69\x6c\x73\x20\x74\x6f\x20\x70\x72\x6f\x63\x65\x73\x73\x20\x41\x6c\x69\x63\x65\x27\x73\x20\x73\x74\x65\x70\x20\x33\x61\xa");
        ERR_print_errors_fp(stdout);
        return 5;
    }
    JPAKE_STEP3A_release(&alice_s3a);

    /* Bob -> Alice: step 3b */
    puts("\x42\x2d\x3e\x41\x20\x73\x33\x62");
    JPAKE_STEP3B_init(&bob_s3b);
    JPAKE_STEP3B_generate(&bob_s3b, bob);
    if (!JPAKE_STEP3B_process(alice, &bob_s3b)) {
        printf("\x41\x6c\x69\x63\x65\x20\x66\x61\x69\x6c\x73\x20\x74\x6f\x20\x70\x72\x6f\x63\x65\x73\x73\x20\x42\x6f\x62\x27\x73\x20\x73\x74\x65\x70\x20\x33\x62\xa");
        ERR_print_errors_fp(stdout);
        return 6;
    }
    JPAKE_STEP3B_release(&bob_s3b);

    return 0;
}

int main(int argc, char **argv)
{
    JPAKE_CTX *alice;
    JPAKE_CTX *bob;
    BIGNUM *p = NULL;
    BIGNUM *g = NULL;
    BIGNUM *q = NULL;
    BIGNUM *secret = BN_new();
    BIO *bio_err;

    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

    CRYPTO_malloc_debug_init();
    CRYPTO_dbg_set_options(V_CRYPTO_MDEBUG_ALL);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    ERR_load_crypto_strings();

    /*-
    BN_hex2bn(&p, "fd7f53811d75122952df4a9c2eece4e7f611b7523cef4400c31e3f80b6512669455d402251fb593d8d58fabfc5f5ba30f6cb9b556cd7813b801d346ff26660b76b9950a5a49f9fe8047b1022c24fbba9d7feb7c61bf83b57e7c6a8a6150f04fb83f6d3c51ec3023554135a169132f675f3ae2b61d72aeff22203199dd14801c7");
    BN_hex2bn(&g, "f7e1a085d69b3ddecbbcab5c36b857b97994afbbfa3aea82f9574c0b3d0782675159578ebad4594fe67107108180b449167123e84c281613b7cf09328cc8a6e13c167a8b547c8d28e0a3ae1e2bb3a675916ea37f0bfa213562f1fb627a01243bcca4f1bea8519089a883dfe15ae59f06928b665e807b552564014c3bfecf492a");
    BN_hex2bn(&q, "9760508f15230bccb292b982a2eb840bf0581cf5");
    */
    /*-
    p = BN_new();
    BN_generate_prime(p, 1024, 1, NULL, NULL, NULL, NULL);
    */
    /* Use a safe prime for p (that we found earlier) */
    BN_hex2bn(&p,
              "\x46\x39\x45\x35\x42\x33\x36\x35\x36\x36\x35\x45\x41\x37\x41\x30\x35\x41\x39\x43\x35\x33\x34\x35\x30\x32\x37\x38\x30\x46\x45\x45\x36\x46\x31\x41\x42\x35\x42\x44\x34\x46\x34\x39\x39\x34\x37\x46\x44\x30\x33\x36\x44\x42\x44\x37\x45\x39\x30\x35\x32\x36\x39\x41\x46\x34\x36\x45\x46\x32\x38\x42\x30\x46\x43\x30\x37\x34\x38\x37\x45\x45\x34\x46\x35\x44\x32\x30\x46\x42\x33\x43\x30\x41\x46\x38\x45\x37\x30\x30\x46\x33\x41\x32\x46\x41\x33\x34\x31\x34\x39\x37\x30\x43\x42\x45\x44\x34\x34\x46\x45\x44\x46\x46\x38\x30\x43\x45\x37\x38\x44\x38\x30\x30\x46\x31\x38\x34\x42\x42\x38\x32\x34\x33\x35\x44\x31\x33\x37\x41\x41\x44\x41\x32\x43\x36\x43\x31\x36\x35\x32\x33\x32\x34\x37\x39\x33\x30\x41\x36\x33\x42\x38\x35\x36\x36\x31\x44\x31\x46\x43\x38\x31\x37\x41\x35\x31\x41\x43\x44\x39\x36\x31\x36\x38\x45\x39\x35\x38\x39\x38\x41\x31\x46\x38\x33\x41\x37\x39\x46\x46\x42\x35\x32\x39\x33\x36\x38\x41\x41\x37\x38\x33\x33\x41\x42\x44\x31\x42\x30\x43\x33\x41\x45\x44\x44\x42\x31\x34\x44\x32\x45\x31\x41\x32\x46\x37\x31\x44\x39\x39\x46\x37\x36\x33\x46");
    showbn("\x70", p);
    g = BN_new();
    BN_set_word(g, 2);
    showbn("\x67", g);
    q = BN_new();
    BN_rshift1(q, p);
    showbn("\x71", q);

    BN_rand(secret, 32, -1, 0);

    /* A normal run, expect this to work... */
    alice = JPAKE_CTX_new("\x41\x6c\x69\x63\x65", "\x42\x6f\x62", p, g, q, secret);
    bob = JPAKE_CTX_new("\x42\x6f\x62", "\x41\x6c\x69\x63\x65", p, g, q, secret);

    if (run_jpake(alice, bob) != 0) {
        fprintf(stderr, "\x50\x6c\x61\x69\x6e\x20\x4a\x50\x41\x4b\x45\x20\x72\x75\x6e\x20\x66\x61\x69\x6c\x65\x64\xa");
        return 1;
    }

    JPAKE_CTX_free(bob);
    JPAKE_CTX_free(alice);

    /* Now give Alice and Bob different secrets */
    alice = JPAKE_CTX_new("\x41\x6c\x69\x63\x65", "\x42\x6f\x62", p, g, q, secret);
    BN_add_word(secret, 1);
    bob = JPAKE_CTX_new("\x42\x6f\x62", "\x41\x6c\x69\x63\x65", p, g, q, secret);

    if (run_jpake(alice, bob) != 5) {
        fprintf(stderr, "\x4d\x69\x73\x6d\x61\x74\x63\x68\x65\x64\x20\x73\x65\x63\x72\x65\x74\x20\x4a\x50\x41\x4b\x45\x20\x72\x75\x6e\x20\x66\x61\x69\x6c\x65\x64\xa");
        return 1;
    }

    JPAKE_CTX_free(bob);
    JPAKE_CTX_free(alice);

    BN_free(secret);
    BN_free(q);
    BN_free(g);
    BN_free(p);

    CRYPTO_cleanup_all_ex_data();
    ERR_remove_thread_state(NULL);
    ERR_free_strings();
    CRYPTO_mem_leaks(bio_err);

    return 0;
}

#endif
