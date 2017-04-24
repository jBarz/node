/* crypto/evp/c_allc.c */
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

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/objects.h>

void OpenSSL_add_all_ciphers(void)
{

#ifndef OPENSSL_NO_DES
    EVP_add_cipher(EVP_des_cfb());
    EVP_add_cipher(EVP_des_cfb1());
    EVP_add_cipher(EVP_des_cfb8());
    EVP_add_cipher(EVP_des_ede_cfb());
    EVP_add_cipher(EVP_des_ede3_cfb());
    EVP_add_cipher(EVP_des_ede3_cfb1());
    EVP_add_cipher(EVP_des_ede3_cfb8());

    EVP_add_cipher(EVP_des_ofb());
    EVP_add_cipher(EVP_des_ede_ofb());
    EVP_add_cipher(EVP_des_ede3_ofb());

    EVP_add_cipher(EVP_desx_cbc());
    EVP_add_cipher_alias(SN_desx_cbc, "\x44\x45\x53\x58");
    EVP_add_cipher_alias(SN_desx_cbc, "\x64\x65\x73\x78");

    EVP_add_cipher(EVP_des_cbc());
    EVP_add_cipher_alias(SN_des_cbc, "\x44\x45\x53");
    EVP_add_cipher_alias(SN_des_cbc, "\x64\x65\x73");
    EVP_add_cipher(EVP_des_ede_cbc());
    EVP_add_cipher(EVP_des_ede3_cbc());
    EVP_add_cipher_alias(SN_des_ede3_cbc, "\x44\x45\x53\x33");
    EVP_add_cipher_alias(SN_des_ede3_cbc, "\x64\x65\x73\x33");

    EVP_add_cipher(EVP_des_ecb());
    EVP_add_cipher(EVP_des_ede());
    EVP_add_cipher(EVP_des_ede3());
    EVP_add_cipher(EVP_des_ede3_wrap());
#endif

#ifndef OPENSSL_NO_RC4
    EVP_add_cipher(EVP_rc4());
    EVP_add_cipher(EVP_rc4_40());
# ifndef OPENSSL_NO_MD5
    EVP_add_cipher(EVP_rc4_hmac_md5());
# endif
#endif

#ifndef OPENSSL_NO_IDEA
    EVP_add_cipher(EVP_idea_ecb());
    EVP_add_cipher(EVP_idea_cfb());
    EVP_add_cipher(EVP_idea_ofb());
    EVP_add_cipher(EVP_idea_cbc());
    EVP_add_cipher_alias(SN_idea_cbc, "\x49\x44\x45\x41");
    EVP_add_cipher_alias(SN_idea_cbc, "\x69\x64\x65\x61");
#endif

#ifndef OPENSSL_NO_SEED
    EVP_add_cipher(EVP_seed_ecb());
    EVP_add_cipher(EVP_seed_cfb());
    EVP_add_cipher(EVP_seed_ofb());
    EVP_add_cipher(EVP_seed_cbc());
    EVP_add_cipher_alias(SN_seed_cbc, "\x53\x45\x45\x44");
    EVP_add_cipher_alias(SN_seed_cbc, "\x73\x65\x65\x64");
#endif

#ifndef OPENSSL_NO_RC2
    EVP_add_cipher(EVP_rc2_ecb());
    EVP_add_cipher(EVP_rc2_cfb());
    EVP_add_cipher(EVP_rc2_ofb());
    EVP_add_cipher(EVP_rc2_cbc());
    EVP_add_cipher(EVP_rc2_40_cbc());
    EVP_add_cipher(EVP_rc2_64_cbc());
    EVP_add_cipher_alias(SN_rc2_cbc, "\x52\x43\x32");
    EVP_add_cipher_alias(SN_rc2_cbc, "\x72\x63\x32");
#endif

#ifndef OPENSSL_NO_BF
    EVP_add_cipher(EVP_bf_ecb());
    EVP_add_cipher(EVP_bf_cfb());
    EVP_add_cipher(EVP_bf_ofb());
    EVP_add_cipher(EVP_bf_cbc());
    EVP_add_cipher_alias(SN_bf_cbc, "\x42\x46");
    EVP_add_cipher_alias(SN_bf_cbc, "\x62\x66");
    EVP_add_cipher_alias(SN_bf_cbc, "\x62\x6c\x6f\x77\x66\x69\x73\x68");
#endif

#ifndef OPENSSL_NO_CAST
    EVP_add_cipher(EVP_cast5_ecb());
    EVP_add_cipher(EVP_cast5_cfb());
    EVP_add_cipher(EVP_cast5_ofb());
    EVP_add_cipher(EVP_cast5_cbc());
    EVP_add_cipher_alias(SN_cast5_cbc, "\x43\x41\x53\x54");
    EVP_add_cipher_alias(SN_cast5_cbc, "\x63\x61\x73\x74");
    EVP_add_cipher_alias(SN_cast5_cbc, "\x43\x41\x53\x54\x2d\x63\x62\x63");
    EVP_add_cipher_alias(SN_cast5_cbc, "\x63\x61\x73\x74\x2d\x63\x62\x63");
#endif

#ifndef OPENSSL_NO_RC5
    EVP_add_cipher(EVP_rc5_32_12_16_ecb());
    EVP_add_cipher(EVP_rc5_32_12_16_cfb());
    EVP_add_cipher(EVP_rc5_32_12_16_ofb());
    EVP_add_cipher(EVP_rc5_32_12_16_cbc());
    EVP_add_cipher_alias(SN_rc5_cbc, "\x72\x63\x35");
    EVP_add_cipher_alias(SN_rc5_cbc, "\x52\x43\x35");
#endif

#ifndef OPENSSL_NO_AES
    EVP_add_cipher(EVP_aes_128_ecb());
    EVP_add_cipher(EVP_aes_128_cbc());
    EVP_add_cipher(EVP_aes_128_cfb());
    EVP_add_cipher(EVP_aes_128_cfb1());
    EVP_add_cipher(EVP_aes_128_cfb8());
    EVP_add_cipher(EVP_aes_128_ofb());
    EVP_add_cipher(EVP_aes_128_ctr());
    EVP_add_cipher(EVP_aes_128_gcm());
    EVP_add_cipher(EVP_aes_128_xts());
    EVP_add_cipher(EVP_aes_128_ccm());
    EVP_add_cipher(EVP_aes_128_wrap());
    EVP_add_cipher_alias(SN_aes_128_cbc, "\x41\x45\x53\x31\x32\x38");
    EVP_add_cipher_alias(SN_aes_128_cbc, "\x61\x65\x73\x31\x32\x38");
    EVP_add_cipher(EVP_aes_192_ecb());
    EVP_add_cipher(EVP_aes_192_cbc());
    EVP_add_cipher(EVP_aes_192_cfb());
    EVP_add_cipher(EVP_aes_192_cfb1());
    EVP_add_cipher(EVP_aes_192_cfb8());
    EVP_add_cipher(EVP_aes_192_ofb());
    EVP_add_cipher(EVP_aes_192_ctr());
    EVP_add_cipher(EVP_aes_192_gcm());
    EVP_add_cipher(EVP_aes_192_ccm());
    EVP_add_cipher(EVP_aes_192_wrap());
    EVP_add_cipher_alias(SN_aes_192_cbc, "\x41\x45\x53\x31\x39\x32");
    EVP_add_cipher_alias(SN_aes_192_cbc, "\x61\x65\x73\x31\x39\x32");
    EVP_add_cipher(EVP_aes_256_ecb());
    EVP_add_cipher(EVP_aes_256_cbc());
    EVP_add_cipher(EVP_aes_256_cfb());
    EVP_add_cipher(EVP_aes_256_cfb1());
    EVP_add_cipher(EVP_aes_256_cfb8());
    EVP_add_cipher(EVP_aes_256_ofb());
    EVP_add_cipher(EVP_aes_256_ctr());
    EVP_add_cipher(EVP_aes_256_gcm());
    EVP_add_cipher(EVP_aes_256_xts());
    EVP_add_cipher(EVP_aes_256_ccm());
    EVP_add_cipher(EVP_aes_256_wrap());
    EVP_add_cipher_alias(SN_aes_256_cbc, "\x41\x45\x53\x32\x35\x36");
    EVP_add_cipher_alias(SN_aes_256_cbc, "\x61\x65\x73\x32\x35\x36");
# if !defined(OPENSSL_NO_SHA) && !defined(OPENSSL_NO_SHA1)
    EVP_add_cipher(EVP_aes_128_cbc_hmac_sha1());
    EVP_add_cipher(EVP_aes_256_cbc_hmac_sha1());
# endif
# if !defined(OPENSSL_NO_SHA) && !defined(OPENSSL_NO_SHA256)
    EVP_add_cipher(EVP_aes_128_cbc_hmac_sha256());
    EVP_add_cipher(EVP_aes_256_cbc_hmac_sha256());
# endif
#endif

#ifndef OPENSSL_NO_CAMELLIA
    EVP_add_cipher(EVP_camellia_128_ecb());
    EVP_add_cipher(EVP_camellia_128_cbc());
    EVP_add_cipher(EVP_camellia_128_cfb());
    EVP_add_cipher(EVP_camellia_128_cfb1());
    EVP_add_cipher(EVP_camellia_128_cfb8());
    EVP_add_cipher(EVP_camellia_128_ofb());
    EVP_add_cipher_alias(SN_camellia_128_cbc, "\x43\x41\x4d\x45\x4c\x4c\x49\x41\x31\x32\x38");
    EVP_add_cipher_alias(SN_camellia_128_cbc, "\x63\x61\x6d\x65\x6c\x6c\x69\x61\x31\x32\x38");
    EVP_add_cipher(EVP_camellia_192_ecb());
    EVP_add_cipher(EVP_camellia_192_cbc());
    EVP_add_cipher(EVP_camellia_192_cfb());
    EVP_add_cipher(EVP_camellia_192_cfb1());
    EVP_add_cipher(EVP_camellia_192_cfb8());
    EVP_add_cipher(EVP_camellia_192_ofb());
    EVP_add_cipher_alias(SN_camellia_192_cbc, "\x43\x41\x4d\x45\x4c\x4c\x49\x41\x31\x39\x32");
    EVP_add_cipher_alias(SN_camellia_192_cbc, "\x63\x61\x6d\x65\x6c\x6c\x69\x61\x31\x39\x32");
    EVP_add_cipher(EVP_camellia_256_ecb());
    EVP_add_cipher(EVP_camellia_256_cbc());
    EVP_add_cipher(EVP_camellia_256_cfb());
    EVP_add_cipher(EVP_camellia_256_cfb1());
    EVP_add_cipher(EVP_camellia_256_cfb8());
    EVP_add_cipher(EVP_camellia_256_ofb());
    EVP_add_cipher_alias(SN_camellia_256_cbc, "\x43\x41\x4d\x45\x4c\x4c\x49\x41\x32\x35\x36");
    EVP_add_cipher_alias(SN_camellia_256_cbc, "\x63\x61\x6d\x65\x6c\x6c\x69\x61\x32\x35\x36");
#endif
}
