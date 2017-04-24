typedef int cl_engine_init(void);
typedef int cl_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                       const BIGNUM *m, BN_CTX *cgx);
typedef int cl_mod_exp_crt(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
                           const BIGNUM *q, const BIGNUM *dmp1,
                           const BIGNUM *dmq1, const BIGNUM *iqmp,
                           BN_CTX *ctx);
typedef int cl_rsa_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa);
typedef int cl_rsa_pub_enc(int flen, const unsigned char *from,
                           unsigned char *to, RSA *rsa, int padding);
typedef int cl_rsa_pub_dec(int flen, const unsigned char *from,
                           unsigned char *to, RSA *rsa, int padding);
typedef int cl_rsa_priv_enc(int flen, const unsigned char *from,
                            unsigned char *to, RSA *rsa, int padding);
typedef int cl_rsa_priv_dec(int flen, const unsigned char *from,
                            unsigned char *to, RSA *rsa, int padding);
typedef int cl_rand_bytes(unsigned char *buf, int num);
typedef DSA_SIG *cl_dsa_sign(const unsigned char *dgst, int dlen, DSA *dsa);
typedef int cl_dsa_verify(const unsigned char *dgst, int dgst_len,
                          DSA_SIG *sig, DSA *dsa);

static const char *CLUSTER_LABS_LIB_NAME = "\x63\x6c\x75\x73\x74\x65\x72\x5f\x6c\x61\x62\x73";
static const char *CLUSTER_LABS_F1 = "\x68\x77\x5f\x65\x6e\x67\x69\x6e\x65\x5f\x69\x6e\x69\x74";
static const char *CLUSTER_LABS_F2 = "\x68\x77\x5f\x6d\x6f\x64\x5f\x65\x78\x70";
static const char *CLUSTER_LABS_F3 = "\x68\x77\x5f\x6d\x6f\x64\x5f\x65\x78\x70\x5f\x63\x72\x74";
static const char *CLUSTER_LABS_F4 = "\x68\x77\x5f\x72\x73\x61\x5f\x6d\x6f\x64\x5f\x65\x78\x70";
static const char *CLUSTER_LABS_F5 = "\x68\x77\x5f\x72\x73\x61\x5f\x70\x72\x69\x76\x5f\x65\x6e\x63";
static const char *CLUSTER_LABS_F6 = "\x68\x77\x5f\x72\x73\x61\x5f\x70\x72\x69\x76\x5f\x64\x65\x63";
static const char *CLUSTER_LABS_F7 = "\x68\x77\x5f\x72\x73\x61\x5f\x70\x75\x62\x5f\x65\x6e\x63";
static const char *CLUSTER_LABS_F8 = "\x68\x77\x5f\x72\x73\x61\x5f\x70\x75\x62\x5f\x64\x65\x63";
static const char *CLUSTER_LABS_F20 = "\x68\x77\x5f\x72\x61\x6e\x64\x5f\x62\x79\x74\x65\x73";
static const char *CLUSTER_LABS_F30 = "\x68\x77\x5f\x64\x73\x61\x5f\x73\x69\x67\x6e";
static const char *CLUSTER_LABS_F31 = "\x68\x77\x5f\x64\x73\x61\x5f\x76\x65\x72\x69\x66\x79";
