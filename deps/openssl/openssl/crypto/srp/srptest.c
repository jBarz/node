#include <openssl/opensslconf.h>
#ifdef OPENSSL_NO_SRP

# include <stdio.h>

int main(int argc, char *argv[])
{
    printf("\x4e\x6f\x20\x53\x52\x50\x20\x73\x75\x70\x70\x6f\x72\x74\xa");
    return (0);
}

#else

# include <openssl/srp.h>
# include <openssl/rand.h>
# include <openssl/err.h>

static void showbn(const char *name, const BIGNUM *bn)
{
    fputs(name, stdout);
    fputs("\x20\x3d\x20", stdout);
    BN_print_fp(stdout, bn);
    putc('\xa', stdout);
}

# define RANDOM_SIZE 32         /* use 256 bits on each side */

static int run_srp(const char *username, const char *client_pass,
                   const char *server_pass)
{
    int ret = -1;
    BIGNUM *s = NULL;
    BIGNUM *v = NULL;
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    BIGNUM *u = NULL;
    BIGNUM *x = NULL;
    BIGNUM *Apub = NULL;
    BIGNUM *Bpub = NULL;
    BIGNUM *Kclient = NULL;
    BIGNUM *Kserver = NULL;
    unsigned char rand_tmp[RANDOM_SIZE];
    /* use builtin 1024-bit params */
    SRP_gN *GN = SRP_get_default_gN("\x31\x30\x32\x34");

    if (GN == NULL) {
        fprintf(stderr, "\x46\x61\x69\x6c\x65\x64\x20\x74\x6f\x20\x67\x65\x74\x20\x53\x52\x50\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\xa");
        return -1;
    }
    /* Set up server's password entry */
    if (!SRP_create_verifier_BN(username, server_pass, &s, &v, GN->N, GN->g)) {
        fprintf(stderr, "\x46\x61\x69\x6c\x65\x64\x20\x74\x6f\x20\x63\x72\x65\x61\x74\x65\x20\x53\x52\x50\x20\x76\x65\x72\x69\x66\x69\x65\x72\xa");
        return -1;
    }

    showbn("\x4e", GN->N);
    showbn("\x67", GN->g);
    showbn("\x53\x61\x6c\x74", s);
    showbn("\x56\x65\x72\x69\x66\x69\x65\x72", v);

    /* Server random */
    RAND_pseudo_bytes(rand_tmp, sizeof(rand_tmp));
    b = BN_bin2bn(rand_tmp, sizeof(rand_tmp), NULL);
    /* TODO - check b != 0 */
    showbn("\x62", b);

    /* Server's first message */
    Bpub = SRP_Calc_B(b, GN->N, GN->g, v);
    showbn("\x42", Bpub);

    if (!SRP_Verify_B_mod_N(Bpub, GN->N)) {
        fprintf(stderr, "\x49\x6e\x76\x61\x6c\x69\x64\x20\x42\xa");
        return -1;
    }

    /* Client random */
    RAND_pseudo_bytes(rand_tmp, sizeof(rand_tmp));
    a = BN_bin2bn(rand_tmp, sizeof(rand_tmp), NULL);
    /* TODO - check a != 0 */
    showbn("\x61", a);

    /* Client's response */
    Apub = SRP_Calc_A(a, GN->N, GN->g);
    showbn("\x41", Apub);

    if (!SRP_Verify_A_mod_N(Apub, GN->N)) {
        fprintf(stderr, "\x49\x6e\x76\x61\x6c\x69\x64\x20\x41\xa");
        return -1;
    }

    /* Both sides calculate u */
    u = SRP_Calc_u(Apub, Bpub, GN->N);

    /* Client's key */
    x = SRP_Calc_x(s, username, client_pass);
    Kclient = SRP_Calc_client_key(GN->N, Bpub, GN->g, x, a, u);
    showbn("\x43\x6c\x69\x65\x6e\x74\x27\x73\x20\x6b\x65\x79", Kclient);

    /* Server's key */
    Kserver = SRP_Calc_server_key(Apub, v, u, b, GN->N);
    showbn("\x53\x65\x72\x76\x65\x72\x27\x73\x20\x6b\x65\x79", Kserver);

    if (BN_cmp(Kclient, Kserver) == 0) {
        ret = 0;
    } else {
        fprintf(stderr, "\x4b\x65\x79\x73\x20\x6d\x69\x73\x6d\x61\x74\x63\x68\xa");
        ret = 1;
    }

    BN_clear_free(Kclient);
    BN_clear_free(Kserver);
    BN_clear_free(x);
    BN_free(u);
    BN_free(Apub);
    BN_clear_free(a);
    BN_free(Bpub);
    BN_clear_free(b);
    BN_free(s);
    BN_clear_free(v);

    return ret;
}

int main(int argc, char **argv)
{
    BIO *bio_err;
    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

    CRYPTO_malloc_debug_init();
    CRYPTO_dbg_set_options(V_CRYPTO_MDEBUG_ALL);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    ERR_load_crypto_strings();

    /* "Negative" test, expect a mismatch */
    if (run_srp("\x61\x6c\x69\x63\x65", "\x70\x61\x73\x73\x77\x6f\x72\x64\x31", "\x70\x61\x73\x73\x77\x6f\x72\x64\x32") == 0) {
        fprintf(stderr, "\x4d\x69\x73\x6d\x61\x74\x63\x68\x65\x64\x20\x53\x52\x50\x20\x72\x75\x6e\x20\x66\x61\x69\x6c\x65\x64\xa");
        return 1;
    }

    /* "Positive" test, should pass */
    if (run_srp("\x61\x6c\x69\x63\x65", "\x70\x61\x73\x73\x77\x6f\x72\x64", "\x70\x61\x73\x73\x77\x6f\x72\x64") != 0) {
        fprintf(stderr, "\x50\x6c\x61\x69\x6e\x20\x53\x52\x50\x20\x72\x75\x6e\x20\x66\x61\x69\x6c\x65\x64\xa");
        return 1;
    }

    CRYPTO_cleanup_all_ex_data();
    ERR_remove_thread_state(NULL);
    ERR_free_strings();
    CRYPTO_mem_leaks(bio_err);
    BIO_free(bio_err);

    return 0;
}
#endif
