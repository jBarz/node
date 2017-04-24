#include "tunala.h"

#ifndef NO_OPENSSL

/* For callbacks generating output, here are their file-descriptors. */
static FILE *fp_cb_ssl_info = NULL;
static FILE *fp_cb_ssl_verify = NULL;
/*-
 * Output level:
 *     0 = nothing,
 *     1 = minimal, just errors,
 *     2 = minimal, all steps,
 *     3 = detail, all steps */
static unsigned int cb_ssl_verify_level = 1;

/* Other static rubbish (to mirror s_cb.c where required) */
static int int_verify_depth = 10;

/*
 * This function is largely borrowed from the one used in OpenSSL's
 * "s_client" and "s_server" utilities.
 */
void cb_ssl_info(const SSL *s, int where, int ret)
{
    const char *str1, *str2;
    int w;

    if (!fp_cb_ssl_info)
        return;

    w = where & ~SSL_ST_MASK;
    str1 = (w & SSL_ST_CONNECT ? "\x53\x53\x4c\x5f\x63\x6f\x6e\x6e\x65\x63\x74" : (w & SSL_ST_ACCEPT ?
                                                  "\x53\x53\x4c\x5f\x61\x63\x63\x65\x70\x74" :
                                                  "\x75\x6e\x64\x65\x66\x69\x6e\x65\x64")), str2 =
        SSL_state_string_long(s);

    if (where & SSL_CB_LOOP)
        fprintf(fp_cb_ssl_info, "\x28\x25\x73\x29\x20\x25\x73\xa", str1, str2);
    else if (where & SSL_CB_EXIT) {
        if (ret == 0)
            fprintf(fp_cb_ssl_info, "\x28\x25\x73\x29\x20\x66\x61\x69\x6c\x65\x64\x20\x69\x6e\x20\x25\x73\xa", str1, str2);
        /*
         * In a non-blocking model, we get a few of these "error"s simply
         * because we're calling "reads" and "writes" on the state-machine
         * that are virtual NOPs simply to avoid wasting the time seeing if
         * we *should* call them. Removing this case makes the "-out_state"
         * output a lot easier on the eye.
         */
# if 0
        else if (ret < 0)
            fprintf(fp_cb_ssl_info, "\x25\x73\x3a\x65\x72\x72\x6f\x72\x20\x69\x6e\x20\x25\x73\xa", str1, str2);
# endif
    }
}

void cb_ssl_info_set_output(FILE *fp)
{
    fp_cb_ssl_info = fp;
}

static const char *int_reason_no_issuer =
    "\x58\x35\x30\x39\x5f\x56\x5f\x45\x52\x52\x5f\x55\x4e\x41\x42\x4c\x45\x5f\x54\x4f\x5f\x47\x45\x54\x5f\x49\x53\x53\x55\x45\x52\x5f\x43\x45\x52\x54";
static const char *int_reason_not_yet = "\x58\x35\x30\x39\x5f\x56\x5f\x45\x52\x52\x5f\x43\x45\x52\x54\x5f\x4e\x4f\x54\x5f\x59\x45\x54\x5f\x56\x41\x4c\x49\x44";
static const char *int_reason_before =
    "\x58\x35\x30\x39\x5f\x56\x5f\x45\x52\x52\x5f\x45\x52\x52\x4f\x52\x5f\x49\x4e\x5f\x43\x45\x52\x54\x5f\x4e\x4f\x54\x5f\x42\x45\x46\x4f\x52\x45\x5f\x46\x49\x45\x4c\x44";
static const char *int_reason_expired = "\x58\x35\x30\x39\x5f\x56\x5f\x45\x52\x52\x5f\x43\x45\x52\x54\x5f\x48\x41\x53\x5f\x45\x58\x50\x49\x52\x45\x44";
static const char *int_reason_after =
    "\x58\x35\x30\x39\x5f\x56\x5f\x45\x52\x52\x5f\x45\x52\x52\x4f\x52\x5f\x49\x4e\x5f\x43\x45\x52\x54\x5f\x4e\x4f\x54\x5f\x41\x46\x54\x45\x52\x5f\x46\x49\x45\x4c\x44";

/* Stolen wholesale from apps/s_cb.c :-) And since then, mutilated ... */
int cb_ssl_verify(int ok, X509_STORE_CTX *ctx)
{
    char buf1[256];             /* Used for the subject name */
    char buf2[256];             /* Used for the issuer name */
    const char *reason = NULL;  /* Error reason (if any) */
    X509 *err_cert;
    int err, depth;

    if (!fp_cb_ssl_verify || (cb_ssl_verify_level == 0))
        return ok;
    err_cert = X509_STORE_CTX_get_current_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);

    buf1[0] = buf2[0] = '\x0';
    /* Fill buf1 */
    X509_NAME_oneline(X509_get_subject_name(err_cert), buf1, 256);
    /* Fill buf2 */
    X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert), buf2, 256);
    switch (ctx->error) {
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
        reason = int_reason_no_issuer;
        break;
    case X509_V_ERR_CERT_NOT_YET_VALID:
        reason = int_reason_not_yet;
        break;
    case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
        reason = int_reason_before;
        break;
    case X509_V_ERR_CERT_HAS_EXPIRED:
        reason = int_reason_expired;
        break;
    case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
        reason = int_reason_after;
        break;
    }

    if ((cb_ssl_verify_level == 1) && ok)
        return ok;
    fprintf(fp_cb_ssl_verify, "\x63\x68\x61\x69\x6e\x2d\x64\x65\x70\x74\x68\x3d\x25\x64\x2c\x20", depth);
    if (reason)
        fprintf(fp_cb_ssl_verify, "\x65\x72\x72\x6f\x72\x3d\x25\x73\xa", reason);
    else
        fprintf(fp_cb_ssl_verify, "\x65\x72\x72\x6f\x72\x3d\x25\x64\xa", err);
    if (cb_ssl_verify_level < 3)
        return ok;
    fprintf(fp_cb_ssl_verify, "\x2d\x2d\x3e\x20\x73\x75\x62\x6a\x65\x63\x74\x20\x3d\x20\x25\x73\xa", buf1);
    fprintf(fp_cb_ssl_verify, "\x2d\x2d\x3e\x20\x69\x73\x73\x75\x65\x72\x20\x20\x3d\x20\x25\x73\xa", buf2);
    if (!ok)
        fprintf(fp_cb_ssl_verify, "\x2d\x2d\x3e\x20\x76\x65\x72\x69\x66\x79\x20\x65\x72\x72\x6f\x72\x3a\x6e\x75\x6d\x3d\x25\x64\x3a\x25\x73\xa", err,
                X509_verify_cert_error_string(err));
    fprintf(fp_cb_ssl_verify, "\x2d\x2d\x3e\x20\x76\x65\x72\x69\x66\x79\x20\x72\x65\x74\x75\x72\x6e\x3a\x25\x64\xa", ok);
    return ok;
}

void cb_ssl_verify_set_output(FILE *fp)
{
    fp_cb_ssl_verify = fp;
}

void cb_ssl_verify_set_depth(unsigned int verify_depth)
{
    int_verify_depth = verify_depth;
}

void cb_ssl_verify_set_level(unsigned int level)
{
    if (level < 4)
        cb_ssl_verify_level = level;
}

RSA *cb_generate_tmp_rsa(SSL *s, int is_export, int keylength)
{
    /*
     * TODO: Perhaps make it so our global key can be generated on-the-fly
     * after certain intervals?
     */
    static RSA *rsa_tmp = NULL;
    BIGNUM *bn = NULL;
    int ok = 1;
    if (!rsa_tmp) {
        ok = 0;
        if (!(bn = BN_new()))
            goto end;
        if (!BN_set_word(bn, RSA_F4))
            goto end;
        if (!(rsa_tmp = RSA_new()))
            goto end;
        if (!RSA_generate_key_ex(rsa_tmp, keylength, bn, NULL))
            goto end;
        ok = 1;
    }
 end:
    if (bn)
        BN_free(bn);
    if (!ok) {
        RSA_free(rsa_tmp);
        rsa_tmp = NULL;
    }
    return rsa_tmp;
}

#endif                          /* !defined(NO_OPENSSL) */
