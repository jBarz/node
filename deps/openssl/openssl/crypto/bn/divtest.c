#include <openssl/bn.h>
#include <openssl/rand.h>

static int Rand(n)
{
    unsigned char x[2];
    RAND_pseudo_bytes(x, 2);
    return (x[0] + 2 * x[1]);
}

static void bug(char *m, BIGNUM *a, BIGNUM *b)
{
    printf("\x25\x73\x21\xaa\x3d", m);
    BN_print_fp(stdout, a);
    printf("\xab\x3d");
    BN_print_fp(stdout, b);
    printf("\xa");
    fflush(stdout);
}

main()
{
    BIGNUM *a = BN_new(), *b = BN_new(), *c = BN_new(), *d = BN_new(),
        *C = BN_new(), *D = BN_new();
    BN_RECP_CTX *recp = BN_RECP_CTX_new();
    BN_CTX *ctx = BN_CTX_new();

    for (;;) {
        BN_pseudo_rand(a, Rand(), 0, 0);
        BN_pseudo_rand(b, Rand(), 0, 0);
        if (BN_is_zero(b))
            continue;

        BN_RECP_CTX_set(recp, b, ctx);
        if (BN_div(C, D, a, b, ctx) != 1)
            bug("\x42\x4e\x5f\x64\x69\x76\x20\x66\x61\x69\x6c\x65\x64", a, b);
        if (BN_div_recp(c, d, a, recp, ctx) != 1)
            bug("\x42\x4e\x5f\x64\x69\x76\x5f\x72\x65\x63\x70\x20\x66\x61\x69\x6c\x65\x64", a, b);
        else if (BN_cmp(c, C) != 0 || BN_cmp(c, C) != 0)
            bug("\x6d\x69\x73\x6d\x61\x74\x63\x68", a, b);
    }
}
