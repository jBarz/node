/* crypto/objects/objects.h */
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

#ifndef HEADER_OBJECTS_H
# define HEADER_OBJECTS_H

# define USE_OBJ_MAC

# ifdef USE_OBJ_MAC
#  include <openssl/obj_mac.h>
# else
#  define SN_undef                        "\x55\x4e\x44\x45\x46"
#  define LN_undef                        "\x75\x6e\x64\x65\x66\x69\x6e\x65\x64"
#  define NID_undef                       0
#  define OBJ_undef                       0L

#  define SN_Algorithm                    "\x41\x6c\x67\x6f\x72\x69\x74\x68\x6d"
#  define LN_algorithm                    "\x61\x6c\x67\x6f\x72\x69\x74\x68\x6d"
#  define NID_algorithm                   38
#  define OBJ_algorithm                   1L,3L,14L,3L,2L

#  define LN_rsadsi                       "\x72\x73\x61\x64\x73\x69"
#  define NID_rsadsi                      1
#  define OBJ_rsadsi                      1L,2L,840L,113549L

#  define LN_pkcs                         "\x70\x6b\x63\x73"
#  define NID_pkcs                        2
#  define OBJ_pkcs                        OBJ_rsadsi,1L

#  define SN_md2                          "\x4d\x44\x32"
#  define LN_md2                          "\x6d\x64\x32"
#  define NID_md2                         3
#  define OBJ_md2                         OBJ_rsadsi,2L,2L

#  define SN_md5                          "\x4d\x44\x35"
#  define LN_md5                          "\x6d\x64\x35"
#  define NID_md5                         4
#  define OBJ_md5                         OBJ_rsadsi,2L,5L

#  define SN_rc4                          "\x52\x43\x34"
#  define LN_rc4                          "\x72\x63\x34"
#  define NID_rc4                         5
#  define OBJ_rc4                         OBJ_rsadsi,3L,4L

#  define LN_rsaEncryption                "\x72\x73\x61\x45\x6e\x63\x72\x79\x70\x74\x69\x6f\x6e"
#  define NID_rsaEncryption               6
#  define OBJ_rsaEncryption               OBJ_pkcs,1L,1L

#  define SN_md2WithRSAEncryption         "\x52\x53\x41\x2d\x4d\x44\x32"
#  define LN_md2WithRSAEncryption         "\x6d\x64\x32\x57\x69\x74\x68\x52\x53\x41\x45\x6e\x63\x72\x79\x70\x74\x69\x6f\x6e"
#  define NID_md2WithRSAEncryption        7
#  define OBJ_md2WithRSAEncryption        OBJ_pkcs,1L,2L

#  define SN_md5WithRSAEncryption         "\x52\x53\x41\x2d\x4d\x44\x35"
#  define LN_md5WithRSAEncryption         "\x6d\x64\x35\x57\x69\x74\x68\x52\x53\x41\x45\x6e\x63\x72\x79\x70\x74\x69\x6f\x6e"
#  define NID_md5WithRSAEncryption        8
#  define OBJ_md5WithRSAEncryption        OBJ_pkcs,1L,4L

#  define SN_pbeWithMD2AndDES_CBC         "\x50\x42\x45\x2d\x4d\x44\x32\x2d\x44\x45\x53"
#  define LN_pbeWithMD2AndDES_CBC         "\x70\x62\x65\x57\x69\x74\x68\x4d\x44\x32\x41\x6e\x64\x44\x45\x53\x2d\x43\x42\x43"
#  define NID_pbeWithMD2AndDES_CBC        9
#  define OBJ_pbeWithMD2AndDES_CBC        OBJ_pkcs,5L,1L

#  define SN_pbeWithMD5AndDES_CBC         "\x50\x42\x45\x2d\x4d\x44\x35\x2d\x44\x45\x53"
#  define LN_pbeWithMD5AndDES_CBC         "\x70\x62\x65\x57\x69\x74\x68\x4d\x44\x35\x41\x6e\x64\x44\x45\x53\x2d\x43\x42\x43"
#  define NID_pbeWithMD5AndDES_CBC        10
#  define OBJ_pbeWithMD5AndDES_CBC        OBJ_pkcs,5L,3L

#  define LN_X500                         "\x58\x35\x30\x30"
#  define NID_X500                        11
#  define OBJ_X500                        2L,5L

#  define LN_X509                         "\x58\x35\x30\x39"
#  define NID_X509                        12
#  define OBJ_X509                        OBJ_X500,4L

#  define SN_commonName                   "\x43\x4e"
#  define LN_commonName                   "\x63\x6f\x6d\x6d\x6f\x6e\x4e\x61\x6d\x65"
#  define NID_commonName                  13
#  define OBJ_commonName                  OBJ_X509,3L

#  define SN_countryName                  "\x43"
#  define LN_countryName                  "\x63\x6f\x75\x6e\x74\x72\x79\x4e\x61\x6d\x65"
#  define NID_countryName                 14
#  define OBJ_countryName                 OBJ_X509,6L

#  define SN_localityName                 "\x4c"
#  define LN_localityName                 "\x6c\x6f\x63\x61\x6c\x69\x74\x79\x4e\x61\x6d\x65"
#  define NID_localityName                15
#  define OBJ_localityName                OBJ_X509,7L

/* Postal Address? PA */

/* should be "ST" (rfc1327) but MS uses 'S' */
#  define SN_stateOrProvinceName          "\x53\x54"
#  define LN_stateOrProvinceName          "\x73\x74\x61\x74\x65\x4f\x72\x50\x72\x6f\x76\x69\x6e\x63\x65\x4e\x61\x6d\x65"
#  define NID_stateOrProvinceName         16
#  define OBJ_stateOrProvinceName         OBJ_X509,8L

#  define SN_organizationName             "\x4f"
#  define LN_organizationName             "\x6f\x72\x67\x61\x6e\x69\x7a\x61\x74\x69\x6f\x6e\x4e\x61\x6d\x65"
#  define NID_organizationName            17
#  define OBJ_organizationName            OBJ_X509,10L

#  define SN_organizationalUnitName       "\x4f\x55"
#  define LN_organizationalUnitName       "\x6f\x72\x67\x61\x6e\x69\x7a\x61\x74\x69\x6f\x6e\x61\x6c\x55\x6e\x69\x74\x4e\x61\x6d\x65"
#  define NID_organizationalUnitName      18
#  define OBJ_organizationalUnitName      OBJ_X509,11L

#  define SN_rsa                          "\x52\x53\x41"
#  define LN_rsa                          "\x72\x73\x61"
#  define NID_rsa                         19
#  define OBJ_rsa                         OBJ_X500,8L,1L,1L

#  define LN_pkcs7                        "\x70\x6b\x63\x73\x37"
#  define NID_pkcs7                       20
#  define OBJ_pkcs7                       OBJ_pkcs,7L

#  define LN_pkcs7_data                   "\x70\x6b\x63\x73\x37\x2d\x64\x61\x74\x61"
#  define NID_pkcs7_data                  21
#  define OBJ_pkcs7_data                  OBJ_pkcs7,1L

#  define LN_pkcs7_signed                 "\x70\x6b\x63\x73\x37\x2d\x73\x69\x67\x6e\x65\x64\x44\x61\x74\x61"
#  define NID_pkcs7_signed                22
#  define OBJ_pkcs7_signed                OBJ_pkcs7,2L

#  define LN_pkcs7_enveloped              "\x70\x6b\x63\x73\x37\x2d\x65\x6e\x76\x65\x6c\x6f\x70\x65\x64\x44\x61\x74\x61"
#  define NID_pkcs7_enveloped             23
#  define OBJ_pkcs7_enveloped             OBJ_pkcs7,3L

#  define LN_pkcs7_signedAndEnveloped     "\x70\x6b\x63\x73\x37\x2d\x73\x69\x67\x6e\x65\x64\x41\x6e\x64\x45\x6e\x76\x65\x6c\x6f\x70\x65\x64\x44\x61\x74\x61"
#  define NID_pkcs7_signedAndEnveloped    24
#  define OBJ_pkcs7_signedAndEnveloped    OBJ_pkcs7,4L

#  define LN_pkcs7_digest                 "\x70\x6b\x63\x73\x37\x2d\x64\x69\x67\x65\x73\x74\x44\x61\x74\x61"
#  define NID_pkcs7_digest                25
#  define OBJ_pkcs7_digest                OBJ_pkcs7,5L

#  define LN_pkcs7_encrypted              "\x70\x6b\x63\x73\x37\x2d\x65\x6e\x63\x72\x79\x70\x74\x65\x64\x44\x61\x74\x61"
#  define NID_pkcs7_encrypted             26
#  define OBJ_pkcs7_encrypted             OBJ_pkcs7,6L

#  define LN_pkcs3                        "\x70\x6b\x63\x73\x33"
#  define NID_pkcs3                       27
#  define OBJ_pkcs3                       OBJ_pkcs,3L

#  define LN_dhKeyAgreement               "\x64\x68\x4b\x65\x79\x41\x67\x72\x65\x65\x6d\x65\x6e\x74"
#  define NID_dhKeyAgreement              28
#  define OBJ_dhKeyAgreement              OBJ_pkcs3,1L

#  define SN_des_ecb                      "\x44\x45\x53\x2d\x45\x43\x42"
#  define LN_des_ecb                      "\x64\x65\x73\x2d\x65\x63\x62"
#  define NID_des_ecb                     29
#  define OBJ_des_ecb                     OBJ_algorithm,6L

#  define SN_des_cfb64                    "\x44\x45\x53\x2d\x43\x46\x42"
#  define LN_des_cfb64                    "\x64\x65\x73\x2d\x63\x66\x62"
#  define NID_des_cfb64                   30
/* IV + num */
#  define OBJ_des_cfb64                   OBJ_algorithm,9L

#  define SN_des_cbc                      "\x44\x45\x53\x2d\x43\x42\x43"
#  define LN_des_cbc                      "\x64\x65\x73\x2d\x63\x62\x63"
#  define NID_des_cbc                     31
/* IV */
#  define OBJ_des_cbc                     OBJ_algorithm,7L

#  define SN_des_ede                      "\x44\x45\x53\x2d\x45\x44\x45"
#  define LN_des_ede                      "\x64\x65\x73\x2d\x65\x64\x65"
#  define NID_des_ede                     32
/* ?? */
#  define OBJ_des_ede                     OBJ_algorithm,17L

#  define SN_des_ede3                     "\x44\x45\x53\x2d\x45\x44\x45\x33"
#  define LN_des_ede3                     "\x64\x65\x73\x2d\x65\x64\x65\x33"
#  define NID_des_ede3                    33

#  define SN_idea_cbc                     "\x49\x44\x45\x41\x2d\x43\x42\x43"
#  define LN_idea_cbc                     "\x69\x64\x65\x61\x2d\x63\x62\x63"
#  define NID_idea_cbc                    34
#  define OBJ_idea_cbc                    1L,3L,6L,1L,4L,1L,188L,7L,1L,1L,2L

#  define SN_idea_cfb64                   "\x49\x44\x45\x41\x2d\x43\x46\x42"
#  define LN_idea_cfb64                   "\x69\x64\x65\x61\x2d\x63\x66\x62"
#  define NID_idea_cfb64                  35

#  define SN_idea_ecb                     "\x49\x44\x45\x41\x2d\x45\x43\x42"
#  define LN_idea_ecb                     "\x69\x64\x65\x61\x2d\x65\x63\x62"
#  define NID_idea_ecb                    36

#  define SN_rc2_cbc                      "\x52\x43\x32\x2d\x43\x42\x43"
#  define LN_rc2_cbc                      "\x72\x63\x32\x2d\x63\x62\x63"
#  define NID_rc2_cbc                     37
#  define OBJ_rc2_cbc                     OBJ_rsadsi,3L,2L

#  define SN_rc2_ecb                      "\x52\x43\x32\x2d\x45\x43\x42"
#  define LN_rc2_ecb                      "\x72\x63\x32\x2d\x65\x63\x62"
#  define NID_rc2_ecb                     38

#  define SN_rc2_cfb64                    "\x52\x43\x32\x2d\x43\x46\x42"
#  define LN_rc2_cfb64                    "\x72\x63\x32\x2d\x63\x66\x62"
#  define NID_rc2_cfb64                   39

#  define SN_rc2_ofb64                    "\x52\x43\x32\x2d\x4f\x46\x42"
#  define LN_rc2_ofb64                    "\x72\x63\x32\x2d\x6f\x66\x62"
#  define NID_rc2_ofb64                   40

#  define SN_sha                          "\x53\x48\x41"
#  define LN_sha                          "\x73\x68\x61"
#  define NID_sha                         41
#  define OBJ_sha                         OBJ_algorithm,18L

#  define SN_shaWithRSAEncryption         "\x52\x53\x41\x2d\x53\x48\x41"
#  define LN_shaWithRSAEncryption         "\x73\x68\x61\x57\x69\x74\x68\x52\x53\x41\x45\x6e\x63\x72\x79\x70\x74\x69\x6f\x6e"
#  define NID_shaWithRSAEncryption        42
#  define OBJ_shaWithRSAEncryption        OBJ_algorithm,15L

#  define SN_des_ede_cbc                  "\x44\x45\x53\x2d\x45\x44\x45\x2d\x43\x42\x43"
#  define LN_des_ede_cbc                  "\x64\x65\x73\x2d\x65\x64\x65\x2d\x63\x62\x63"
#  define NID_des_ede_cbc                 43

#  define SN_des_ede3_cbc                 "\x44\x45\x53\x2d\x45\x44\x45\x33\x2d\x43\x42\x43"
#  define LN_des_ede3_cbc                 "\x64\x65\x73\x2d\x65\x64\x65\x33\x2d\x63\x62\x63"
#  define NID_des_ede3_cbc                44
#  define OBJ_des_ede3_cbc                OBJ_rsadsi,3L,7L

#  define SN_des_ofb64                    "\x44\x45\x53\x2d\x4f\x46\x42"
#  define LN_des_ofb64                    "\x64\x65\x73\x2d\x6f\x66\x62"
#  define NID_des_ofb64                   45
#  define OBJ_des_ofb64                   OBJ_algorithm,8L

#  define SN_idea_ofb64                   "\x49\x44\x45\x41\x2d\x4f\x46\x42"
#  define LN_idea_ofb64                   "\x69\x64\x65\x61\x2d\x6f\x66\x62"
#  define NID_idea_ofb64                  46

#  define LN_pkcs9                        "\x70\x6b\x63\x73\x39"
#  define NID_pkcs9                       47
#  define OBJ_pkcs9                       OBJ_pkcs,9L

#  define SN_pkcs9_emailAddress           "\x45\x6d\x61\x69\x6c"
#  define LN_pkcs9_emailAddress           "\x65\x6d\x61\x69\x6c\x41\x64\x64\x72\x65\x73\x73"
#  define NID_pkcs9_emailAddress          48
#  define OBJ_pkcs9_emailAddress          OBJ_pkcs9,1L

#  define LN_pkcs9_unstructuredName       "\x75\x6e\x73\x74\x72\x75\x63\x74\x75\x72\x65\x64\x4e\x61\x6d\x65"
#  define NID_pkcs9_unstructuredName      49
#  define OBJ_pkcs9_unstructuredName      OBJ_pkcs9,2L

#  define LN_pkcs9_contentType            "\x63\x6f\x6e\x74\x65\x6e\x74\x54\x79\x70\x65"
#  define NID_pkcs9_contentType           50
#  define OBJ_pkcs9_contentType           OBJ_pkcs9,3L

#  define LN_pkcs9_messageDigest          "\x6d\x65\x73\x73\x61\x67\x65\x44\x69\x67\x65\x73\x74"
#  define NID_pkcs9_messageDigest         51
#  define OBJ_pkcs9_messageDigest         OBJ_pkcs9,4L

#  define LN_pkcs9_signingTime            "\x73\x69\x67\x6e\x69\x6e\x67\x54\x69\x6d\x65"
#  define NID_pkcs9_signingTime           52
#  define OBJ_pkcs9_signingTime           OBJ_pkcs9,5L

#  define LN_pkcs9_countersignature       "\x63\x6f\x75\x6e\x74\x65\x72\x73\x69\x67\x6e\x61\x74\x75\x72\x65"
#  define NID_pkcs9_countersignature      53
#  define OBJ_pkcs9_countersignature      OBJ_pkcs9,6L

#  define LN_pkcs9_challengePassword      "\x63\x68\x61\x6c\x6c\x65\x6e\x67\x65\x50\x61\x73\x73\x77\x6f\x72\x64"
#  define NID_pkcs9_challengePassword     54
#  define OBJ_pkcs9_challengePassword     OBJ_pkcs9,7L

#  define LN_pkcs9_unstructuredAddress    "\x75\x6e\x73\x74\x72\x75\x63\x74\x75\x72\x65\x64\x41\x64\x64\x72\x65\x73\x73"
#  define NID_pkcs9_unstructuredAddress   55
#  define OBJ_pkcs9_unstructuredAddress   OBJ_pkcs9,8L

#  define LN_pkcs9_extCertAttributes      "\x65\x78\x74\x65\x6e\x64\x65\x64\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x41\x74\x74\x72\x69\x62\x75\x74\x65\x73"
#  define NID_pkcs9_extCertAttributes     56
#  define OBJ_pkcs9_extCertAttributes     OBJ_pkcs9,9L

#  define SN_netscape                     "\x4e\x65\x74\x73\x63\x61\x70\x65"
#  define LN_netscape                     "\x4e\x65\x74\x73\x63\x61\x70\x65\x20\x43\x6f\x6d\x6d\x75\x6e\x69\x63\x61\x74\x69\x6f\x6e\x73\x20\x43\x6f\x72\x70\x2e"
#  define NID_netscape                    57
#  define OBJ_netscape                    2L,16L,840L,1L,113730L

#  define SN_netscape_cert_extension      "\x6e\x73\x43\x65\x72\x74\x45\x78\x74"
#  define LN_netscape_cert_extension      "\x4e\x65\x74\x73\x63\x61\x70\x65\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x45\x78\x74\x65\x6e\x73\x69\x6f\x6e"
#  define NID_netscape_cert_extension     58
#  define OBJ_netscape_cert_extension     OBJ_netscape,1L

#  define SN_netscape_data_type           "\x6e\x73\x44\x61\x74\x61\x54\x79\x70\x65"
#  define LN_netscape_data_type           "\x4e\x65\x74\x73\x63\x61\x70\x65\x20\x44\x61\x74\x61\x20\x54\x79\x70\x65"
#  define NID_netscape_data_type          59
#  define OBJ_netscape_data_type          OBJ_netscape,2L

#  define SN_des_ede_cfb64                "\x44\x45\x53\x2d\x45\x44\x45\x2d\x43\x46\x42"
#  define LN_des_ede_cfb64                "\x64\x65\x73\x2d\x65\x64\x65\x2d\x63\x66\x62"
#  define NID_des_ede_cfb64               60

#  define SN_des_ede3_cfb64               "\x44\x45\x53\x2d\x45\x44\x45\x33\x2d\x43\x46\x42"
#  define LN_des_ede3_cfb64               "\x64\x65\x73\x2d\x65\x64\x65\x33\x2d\x63\x66\x62"
#  define NID_des_ede3_cfb64              61

#  define SN_des_ede_ofb64                "\x44\x45\x53\x2d\x45\x44\x45\x2d\x4f\x46\x42"
#  define LN_des_ede_ofb64                "\x64\x65\x73\x2d\x65\x64\x65\x2d\x6f\x66\x62"
#  define NID_des_ede_ofb64               62

#  define SN_des_ede3_ofb64               "\x44\x45\x53\x2d\x45\x44\x45\x33\x2d\x4f\x46\x42"
#  define LN_des_ede3_ofb64               "\x64\x65\x73\x2d\x65\x64\x65\x33\x2d\x6f\x66\x62"
#  define NID_des_ede3_ofb64              63

/* I'm not sure about the object ID */
#  define SN_sha1                         "\x53\x48\x41\x31"
#  define LN_sha1                         "\x73\x68\x61\x31"
#  define NID_sha1                        64
#  define OBJ_sha1                        OBJ_algorithm,26L
/* 28 Jun 1996 - eay */
/* #define OBJ_sha1                     1L,3L,14L,2L,26L,05L <- wrong */

#  define SN_sha1WithRSAEncryption        "\x52\x53\x41\x2d\x53\x48\x41\x31"
#  define LN_sha1WithRSAEncryption        "\x73\x68\x61\x31\x57\x69\x74\x68\x52\x53\x41\x45\x6e\x63\x72\x79\x70\x74\x69\x6f\x6e"
#  define NID_sha1WithRSAEncryption       65
#  define OBJ_sha1WithRSAEncryption       OBJ_pkcs,1L,5L

#  define SN_dsaWithSHA                   "\x44\x53\x41\x2d\x53\x48\x41"
#  define LN_dsaWithSHA                   "\x64\x73\x61\x57\x69\x74\x68\x53\x48\x41"
#  define NID_dsaWithSHA                  66
#  define OBJ_dsaWithSHA                  OBJ_algorithm,13L

#  define SN_dsa_2                        "\x44\x53\x41\x2d\x6f\x6c\x64"
#  define LN_dsa_2                        "\x64\x73\x61\x45\x6e\x63\x72\x79\x70\x74\x69\x6f\x6e\x2d\x6f\x6c\x64"
#  define NID_dsa_2                       67
#  define OBJ_dsa_2                       OBJ_algorithm,12L

/* proposed by microsoft to RSA */
#  define SN_pbeWithSHA1AndRC2_CBC        "\x50\x42\x45\x2d\x53\x48\x41\x31\x2d\x52\x43\x32\x2d\x36\x34"
#  define LN_pbeWithSHA1AndRC2_CBC        "\x70\x62\x65\x57\x69\x74\x68\x53\x48\x41\x31\x41\x6e\x64\x52\x43\x32\x2d\x43\x42\x43"
#  define NID_pbeWithSHA1AndRC2_CBC       68
#  define OBJ_pbeWithSHA1AndRC2_CBC       OBJ_pkcs,5L,11L

/*
 * proposed by microsoft to RSA as pbeWithSHA1AndRC4: it is now defined
 * explicitly in PKCS#5 v2.0 as id-PBKDF2 which is something completely
 * different.
 */
#  define LN_id_pbkdf2                    "\x50\x42\x4b\x44\x46\x32"
#  define NID_id_pbkdf2                   69
#  define OBJ_id_pbkdf2                   OBJ_pkcs,5L,12L

#  define SN_dsaWithSHA1_2                "\x44\x53\x41\x2d\x53\x48\x41\x31\x2d\x6f\x6c\x64"
#  define LN_dsaWithSHA1_2                "\x64\x73\x61\x57\x69\x74\x68\x53\x48\x41\x31\x2d\x6f\x6c\x64"
#  define NID_dsaWithSHA1_2               70
/* Got this one from 'sdn706r20.pdf' which is actually an NSA document :-) */
#  define OBJ_dsaWithSHA1_2               OBJ_algorithm,27L

#  define SN_netscape_cert_type           "\x6e\x73\x43\x65\x72\x74\x54\x79\x70\x65"
#  define LN_netscape_cert_type           "\x4e\x65\x74\x73\x63\x61\x70\x65\x20\x43\x65\x72\x74\x20\x54\x79\x70\x65"
#  define NID_netscape_cert_type          71
#  define OBJ_netscape_cert_type          OBJ_netscape_cert_extension,1L

#  define SN_netscape_base_url            "\x6e\x73\x42\x61\x73\x65\x55\x72\x6c"
#  define LN_netscape_base_url            "\x4e\x65\x74\x73\x63\x61\x70\x65\x20\x42\x61\x73\x65\x20\x55\x72\x6c"
#  define NID_netscape_base_url           72
#  define OBJ_netscape_base_url           OBJ_netscape_cert_extension,2L

#  define SN_netscape_revocation_url      "\x6e\x73\x52\x65\x76\x6f\x63\x61\x74\x69\x6f\x6e\x55\x72\x6c"
#  define LN_netscape_revocation_url      "\x4e\x65\x74\x73\x63\x61\x70\x65\x20\x52\x65\x76\x6f\x63\x61\x74\x69\x6f\x6e\x20\x55\x72\x6c"
#  define NID_netscape_revocation_url     73
#  define OBJ_netscape_revocation_url     OBJ_netscape_cert_extension,3L

#  define SN_netscape_ca_revocation_url   "\x6e\x73\x43\x61\x52\x65\x76\x6f\x63\x61\x74\x69\x6f\x6e\x55\x72\x6c"
#  define LN_netscape_ca_revocation_url   "\x4e\x65\x74\x73\x63\x61\x70\x65\x20\x43\x41\x20\x52\x65\x76\x6f\x63\x61\x74\x69\x6f\x6e\x20\x55\x72\x6c"
#  define NID_netscape_ca_revocation_url  74
#  define OBJ_netscape_ca_revocation_url  OBJ_netscape_cert_extension,4L

#  define SN_netscape_renewal_url         "\x6e\x73\x52\x65\x6e\x65\x77\x61\x6c\x55\x72\x6c"
#  define LN_netscape_renewal_url         "\x4e\x65\x74\x73\x63\x61\x70\x65\x20\x52\x65\x6e\x65\x77\x61\x6c\x20\x55\x72\x6c"
#  define NID_netscape_renewal_url        75
#  define OBJ_netscape_renewal_url        OBJ_netscape_cert_extension,7L

#  define SN_netscape_ca_policy_url       "\x6e\x73\x43\x61\x50\x6f\x6c\x69\x63\x79\x55\x72\x6c"
#  define LN_netscape_ca_policy_url       "\x4e\x65\x74\x73\x63\x61\x70\x65\x20\x43\x41\x20\x50\x6f\x6c\x69\x63\x79\x20\x55\x72\x6c"
#  define NID_netscape_ca_policy_url      76
#  define OBJ_netscape_ca_policy_url      OBJ_netscape_cert_extension,8L

#  define SN_netscape_ssl_server_name     "\x6e\x73\x53\x73\x6c\x53\x65\x72\x76\x65\x72\x4e\x61\x6d\x65"
#  define LN_netscape_ssl_server_name     "\x4e\x65\x74\x73\x63\x61\x70\x65\x20\x53\x53\x4c\x20\x53\x65\x72\x76\x65\x72\x20\x4e\x61\x6d\x65"
#  define NID_netscape_ssl_server_name    77
#  define OBJ_netscape_ssl_server_name    OBJ_netscape_cert_extension,12L

#  define SN_netscape_comment             "\x6e\x73\x43\x6f\x6d\x6d\x65\x6e\x74"
#  define LN_netscape_comment             "\x4e\x65\x74\x73\x63\x61\x70\x65\x20\x43\x6f\x6d\x6d\x65\x6e\x74"
#  define NID_netscape_comment            78
#  define OBJ_netscape_comment            OBJ_netscape_cert_extension,13L

#  define SN_netscape_cert_sequence       "\x6e\x73\x43\x65\x72\x74\x53\x65\x71\x75\x65\x6e\x63\x65"
#  define LN_netscape_cert_sequence       "\x4e\x65\x74\x73\x63\x61\x70\x65\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x53\x65\x71\x75\x65\x6e\x63\x65"
#  define NID_netscape_cert_sequence      79
#  define OBJ_netscape_cert_sequence      OBJ_netscape_data_type,5L

#  define SN_desx_cbc                     "\x44\x45\x53\x58\x2d\x43\x42\x43"
#  define LN_desx_cbc                     "\x64\x65\x73\x78\x2d\x63\x62\x63"
#  define NID_desx_cbc                    80

#  define SN_id_ce                        "\x69\x64\x2d\x63\x65"
#  define NID_id_ce                       81
#  define OBJ_id_ce                       2L,5L,29L

#  define SN_subject_key_identifier       "\x73\x75\x62\x6a\x65\x63\x74\x4b\x65\x79\x49\x64\x65\x6e\x74\x69\x66\x69\x65\x72"
#  define LN_subject_key_identifier       "\x58\x35\x30\x39\x76\x33\x20\x53\x75\x62\x6a\x65\x63\x74\x20\x4b\x65\x79\x20\x49\x64\x65\x6e\x74\x69\x66\x69\x65\x72"
#  define NID_subject_key_identifier      82
#  define OBJ_subject_key_identifier      OBJ_id_ce,14L

#  define SN_key_usage                    "\x6b\x65\x79\x55\x73\x61\x67\x65"
#  define LN_key_usage                    "\x58\x35\x30\x39\x76\x33\x20\x4b\x65\x79\x20\x55\x73\x61\x67\x65"
#  define NID_key_usage                   83
#  define OBJ_key_usage                   OBJ_id_ce,15L

#  define SN_private_key_usage_period     "\x70\x72\x69\x76\x61\x74\x65\x4b\x65\x79\x55\x73\x61\x67\x65\x50\x65\x72\x69\x6f\x64"
#  define LN_private_key_usage_period     "\x58\x35\x30\x39\x76\x33\x20\x50\x72\x69\x76\x61\x74\x65\x20\x4b\x65\x79\x20\x55\x73\x61\x67\x65\x20\x50\x65\x72\x69\x6f\x64"
#  define NID_private_key_usage_period    84
#  define OBJ_private_key_usage_period    OBJ_id_ce,16L

#  define SN_subject_alt_name             "\x73\x75\x62\x6a\x65\x63\x74\x41\x6c\x74\x4e\x61\x6d\x65"
#  define LN_subject_alt_name             "\x58\x35\x30\x39\x76\x33\x20\x53\x75\x62\x6a\x65\x63\x74\x20\x41\x6c\x74\x65\x72\x6e\x61\x74\x69\x76\x65\x20\x4e\x61\x6d\x65"
#  define NID_subject_alt_name            85
#  define OBJ_subject_alt_name            OBJ_id_ce,17L

#  define SN_issuer_alt_name              "\x69\x73\x73\x75\x65\x72\x41\x6c\x74\x4e\x61\x6d\x65"
#  define LN_issuer_alt_name              "\x58\x35\x30\x39\x76\x33\x20\x49\x73\x73\x75\x65\x72\x20\x41\x6c\x74\x65\x72\x6e\x61\x74\x69\x76\x65\x20\x4e\x61\x6d\x65"
#  define NID_issuer_alt_name             86
#  define OBJ_issuer_alt_name             OBJ_id_ce,18L

#  define SN_basic_constraints            "\x62\x61\x73\x69\x63\x43\x6f\x6e\x73\x74\x72\x61\x69\x6e\x74\x73"
#  define LN_basic_constraints            "\x58\x35\x30\x39\x76\x33\x20\x42\x61\x73\x69\x63\x20\x43\x6f\x6e\x73\x74\x72\x61\x69\x6e\x74\x73"
#  define NID_basic_constraints           87
#  define OBJ_basic_constraints           OBJ_id_ce,19L

#  define SN_crl_number                   "\x63\x72\x6c\x4e\x75\x6d\x62\x65\x72"
#  define LN_crl_number                   "\x58\x35\x30\x39\x76\x33\x20\x43\x52\x4c\x20\x4e\x75\x6d\x62\x65\x72"
#  define NID_crl_number                  88
#  define OBJ_crl_number                  OBJ_id_ce,20L

#  define SN_certificate_policies         "\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x50\x6f\x6c\x69\x63\x69\x65\x73"
#  define LN_certificate_policies         "\x58\x35\x30\x39\x76\x33\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x50\x6f\x6c\x69\x63\x69\x65\x73"
#  define NID_certificate_policies        89
#  define OBJ_certificate_policies        OBJ_id_ce,32L

#  define SN_authority_key_identifier     "\x61\x75\x74\x68\x6f\x72\x69\x74\x79\x4b\x65\x79\x49\x64\x65\x6e\x74\x69\x66\x69\x65\x72"
#  define LN_authority_key_identifier     "\x58\x35\x30\x39\x76\x33\x20\x41\x75\x74\x68\x6f\x72\x69\x74\x79\x20\x4b\x65\x79\x20\x49\x64\x65\x6e\x74\x69\x66\x69\x65\x72"
#  define NID_authority_key_identifier    90
#  define OBJ_authority_key_identifier    OBJ_id_ce,35L

#  define SN_bf_cbc                       "\x42\x46\x2d\x43\x42\x43"
#  define LN_bf_cbc                       "\x62\x66\x2d\x63\x62\x63"
#  define NID_bf_cbc                      91
#  define OBJ_bf_cbc                      1L,3L,6L,1L,4L,1L,3029L,1L,2L

#  define SN_bf_ecb                       "\x42\x46\x2d\x45\x43\x42"
#  define LN_bf_ecb                       "\x62\x66\x2d\x65\x63\x62"
#  define NID_bf_ecb                      92

#  define SN_bf_cfb64                     "\x42\x46\x2d\x43\x46\x42"
#  define LN_bf_cfb64                     "\x62\x66\x2d\x63\x66\x62"
#  define NID_bf_cfb64                    93

#  define SN_bf_ofb64                     "\x42\x46\x2d\x4f\x46\x42"
#  define LN_bf_ofb64                     "\x62\x66\x2d\x6f\x66\x62"
#  define NID_bf_ofb64                    94

#  define SN_mdc2                         "\x4d\x44\x43\x32"
#  define LN_mdc2                         "\x6d\x64\x63\x32"
#  define NID_mdc2                        95
#  define OBJ_mdc2                        2L,5L,8L,3L,101L
/* An alternative?                      1L,3L,14L,3L,2L,19L */

#  define SN_mdc2WithRSA                  "\x52\x53\x41\x2d\x4d\x44\x43\x32"
#  define LN_mdc2WithRSA                  "\x6d\x64\x63\x32\x77\x69\x74\x68\x52\x53\x41"
#  define NID_mdc2WithRSA                 96
#  define OBJ_mdc2WithRSA                 2L,5L,8L,3L,100L

#  define SN_rc4_40                       "\x52\x43\x34\x2d\x34\x30"
#  define LN_rc4_40                       "\x72\x63\x34\x2d\x34\x30"
#  define NID_rc4_40                      97

#  define SN_rc2_40_cbc                   "\x52\x43\x32\x2d\x34\x30\x2d\x43\x42\x43"
#  define LN_rc2_40_cbc                   "\x72\x63\x32\x2d\x34\x30\x2d\x63\x62\x63"
#  define NID_rc2_40_cbc                  98

#  define SN_givenName                    "\x47"
#  define LN_givenName                    "\x67\x69\x76\x65\x6e\x4e\x61\x6d\x65"
#  define NID_givenName                   99
#  define OBJ_givenName                   OBJ_X509,42L

#  define SN_surname                      "\x53"
#  define LN_surname                      "\x73\x75\x72\x6e\x61\x6d\x65"
#  define NID_surname                     100
#  define OBJ_surname                     OBJ_X509,4L

#  define SN_initials                     "\x49"
#  define LN_initials                     "\x69\x6e\x69\x74\x69\x61\x6c\x73"
#  define NID_initials                    101
#  define OBJ_initials                    OBJ_X509,43L

#  define SN_uniqueIdentifier             "\x55\x49\x44"
#  define LN_uniqueIdentifier             "\x75\x6e\x69\x71\x75\x65\x49\x64\x65\x6e\x74\x69\x66\x69\x65\x72"
#  define NID_uniqueIdentifier            102
#  define OBJ_uniqueIdentifier            OBJ_X509,45L

#  define SN_crl_distribution_points      "\x63\x72\x6c\x44\x69\x73\x74\x72\x69\x62\x75\x74\x69\x6f\x6e\x50\x6f\x69\x6e\x74\x73"
#  define LN_crl_distribution_points      "\x58\x35\x30\x39\x76\x33\x20\x43\x52\x4c\x20\x44\x69\x73\x74\x72\x69\x62\x75\x74\x69\x6f\x6e\x20\x50\x6f\x69\x6e\x74\x73"
#  define NID_crl_distribution_points     103
#  define OBJ_crl_distribution_points     OBJ_id_ce,31L

#  define SN_md5WithRSA                   "\x52\x53\x41\x2d\x4e\x50\x2d\x4d\x44\x35"
#  define LN_md5WithRSA                   "\x6d\x64\x35\x57\x69\x74\x68\x52\x53\x41"
#  define NID_md5WithRSA                  104
#  define OBJ_md5WithRSA                  OBJ_algorithm,3L

#  define SN_serialNumber                 "\x53\x4e"
#  define LN_serialNumber                 "\x73\x65\x72\x69\x61\x6c\x4e\x75\x6d\x62\x65\x72"
#  define NID_serialNumber                105
#  define OBJ_serialNumber                OBJ_X509,5L

#  define SN_title                        "\x54"
#  define LN_title                        "\x74\x69\x74\x6c\x65"
#  define NID_title                       106
#  define OBJ_title                       OBJ_X509,12L

#  define SN_description                  "\x44"
#  define LN_description                  "\x64\x65\x73\x63\x72\x69\x70\x74\x69\x6f\x6e"
#  define NID_description                 107
#  define OBJ_description                 OBJ_X509,13L

/* CAST5 is CAST-128, I'm just sticking with the documentation */
#  define SN_cast5_cbc                    "\x43\x41\x53\x54\x35\x2d\x43\x42\x43"
#  define LN_cast5_cbc                    "\x63\x61\x73\x74\x35\x2d\x63\x62\x63"
#  define NID_cast5_cbc                   108
#  define OBJ_cast5_cbc                   1L,2L,840L,113533L,7L,66L,10L

#  define SN_cast5_ecb                    "\x43\x41\x53\x54\x35\x2d\x45\x43\x42"
#  define LN_cast5_ecb                    "\x63\x61\x73\x74\x35\x2d\x65\x63\x62"
#  define NID_cast5_ecb                   109

#  define SN_cast5_cfb64                  "\x43\x41\x53\x54\x35\x2d\x43\x46\x42"
#  define LN_cast5_cfb64                  "\x63\x61\x73\x74\x35\x2d\x63\x66\x62"
#  define NID_cast5_cfb64                 110

#  define SN_cast5_ofb64                  "\x43\x41\x53\x54\x35\x2d\x4f\x46\x42"
#  define LN_cast5_ofb64                  "\x63\x61\x73\x74\x35\x2d\x6f\x66\x62"
#  define NID_cast5_ofb64                 111

#  define LN_pbeWithMD5AndCast5_CBC       "\x70\x62\x65\x57\x69\x74\x68\x4d\x44\x35\x41\x6e\x64\x43\x61\x73\x74\x35\x43\x42\x43"
#  define NID_pbeWithMD5AndCast5_CBC      112
#  define OBJ_pbeWithMD5AndCast5_CBC      1L,2L,840L,113533L,7L,66L,12L

/*-
 * This is one sun will soon be using :-(
 * id-dsa-with-sha1 ID  ::= {
 *   iso(1) member-body(2) us(840) x9-57 (10040) x9cm(4) 3 }
 */
#  define SN_dsaWithSHA1                  "\x44\x53\x41\x2d\x53\x48\x41\x31"
#  define LN_dsaWithSHA1                  "\x64\x73\x61\x57\x69\x74\x68\x53\x48\x41\x31"
#  define NID_dsaWithSHA1                 113
#  define OBJ_dsaWithSHA1                 1L,2L,840L,10040L,4L,3L

#  define NID_md5_sha1                    114
#  define SN_md5_sha1                     "\x4d\x44\x35\x2d\x53\x48\x41\x31"
#  define LN_md5_sha1                     "\x6d\x64\x35\x2d\x73\x68\x61\x31"

#  define SN_sha1WithRSA                  "\x52\x53\x41\x2d\x53\x48\x41\x31\x2d\x32"
#  define LN_sha1WithRSA                  "\x73\x68\x61\x31\x57\x69\x74\x68\x52\x53\x41"
#  define NID_sha1WithRSA                 115
#  define OBJ_sha1WithRSA                 OBJ_algorithm,29L

#  define SN_dsa                          "\x44\x53\x41"
#  define LN_dsa                          "\x64\x73\x61\x45\x6e\x63\x72\x79\x70\x74\x69\x6f\x6e"
#  define NID_dsa                         116
#  define OBJ_dsa                         1L,2L,840L,10040L,4L,1L

#  define SN_ripemd160                    "\x52\x49\x50\x45\x4d\x44\x31\x36\x30"
#  define LN_ripemd160                    "\x72\x69\x70\x65\x6d\x64\x31\x36\x30"
#  define NID_ripemd160                   117
#  define OBJ_ripemd160                   1L,3L,36L,3L,2L,1L

/*
 * The name should actually be rsaSignatureWithripemd160, but I'm going to
 * continue using the convention I'm using with the other ciphers
 */
#  define SN_ripemd160WithRSA             "\x52\x53\x41\x2d\x52\x49\x50\x45\x4d\x44\x31\x36\x30"
#  define LN_ripemd160WithRSA             "\x72\x69\x70\x65\x6d\x64\x31\x36\x30\x57\x69\x74\x68\x52\x53\x41"
#  define NID_ripemd160WithRSA            119
#  define OBJ_ripemd160WithRSA            1L,3L,36L,3L,3L,1L,2L

/*-
 * Taken from rfc2040
 *  RC5_CBC_Parameters ::= SEQUENCE {
 *      version           INTEGER (v1_0(16)),
 *      rounds            INTEGER (8..127),
 *      blockSizeInBits   INTEGER (64, 128),
 *      iv                OCTET STRING OPTIONAL
 *      }
 */
#  define SN_rc5_cbc                      "\x52\x43\x35\x2d\x43\x42\x43"
#  define LN_rc5_cbc                      "\x72\x63\x35\x2d\x63\x62\x63"
#  define NID_rc5_cbc                     120
#  define OBJ_rc5_cbc                     OBJ_rsadsi,3L,8L

#  define SN_rc5_ecb                      "\x52\x43\x35\x2d\x45\x43\x42"
#  define LN_rc5_ecb                      "\x72\x63\x35\x2d\x65\x63\x62"
#  define NID_rc5_ecb                     121

#  define SN_rc5_cfb64                    "\x52\x43\x35\x2d\x43\x46\x42"
#  define LN_rc5_cfb64                    "\x72\x63\x35\x2d\x63\x66\x62"
#  define NID_rc5_cfb64                   122

#  define SN_rc5_ofb64                    "\x52\x43\x35\x2d\x4f\x46\x42"
#  define LN_rc5_ofb64                    "\x72\x63\x35\x2d\x6f\x66\x62"
#  define NID_rc5_ofb64                   123

#  define SN_rle_compression              "\x52\x4c\x45"
#  define LN_rle_compression              "\x72\x75\x6e\x20\x6c\x65\x6e\x67\x74\x68\x20\x63\x6f\x6d\x70\x72\x65\x73\x73\x69\x6f\x6e"
#  define NID_rle_compression             124
#  define OBJ_rle_compression             1L,1L,1L,1L,666L,1L

#  define SN_zlib_compression             "\x5a\x4c\x49\x42"
#  define LN_zlib_compression             "\x7a\x6c\x69\x62\x20\x63\x6f\x6d\x70\x72\x65\x73\x73\x69\x6f\x6e"
#  define NID_zlib_compression            125
#  define OBJ_zlib_compression            1L,1L,1L,1L,666L,2L

#  define SN_ext_key_usage                "\x65\x78\x74\x65\x6e\x64\x65\x64\x4b\x65\x79\x55\x73\x61\x67\x65"
#  define LN_ext_key_usage                "\x58\x35\x30\x39\x76\x33\x20\x45\x78\x74\x65\x6e\x64\x65\x64\x20\x4b\x65\x79\x20\x55\x73\x61\x67\x65"
#  define NID_ext_key_usage               126
#  define OBJ_ext_key_usage               OBJ_id_ce,37

#  define SN_id_pkix                      "\x50\x4b\x49\x58"
#  define NID_id_pkix                     127
#  define OBJ_id_pkix                     1L,3L,6L,1L,5L,5L,7L

#  define SN_id_kp                        "\x69\x64\x2d\x6b\x70"
#  define NID_id_kp                       128
#  define OBJ_id_kp                       OBJ_id_pkix,3L

/* PKIX extended key usage OIDs */

#  define SN_server_auth                  "\x73\x65\x72\x76\x65\x72\x41\x75\x74\x68"
#  define LN_server_auth                  "\x54\x4c\x53\x20\x57\x65\x62\x20\x53\x65\x72\x76\x65\x72\x20\x41\x75\x74\x68\x65\x6e\x74\x69\x63\x61\x74\x69\x6f\x6e"
#  define NID_server_auth                 129
#  define OBJ_server_auth                 OBJ_id_kp,1L

#  define SN_client_auth                  "\x63\x6c\x69\x65\x6e\x74\x41\x75\x74\x68"
#  define LN_client_auth                  "\x54\x4c\x53\x20\x57\x65\x62\x20\x43\x6c\x69\x65\x6e\x74\x20\x41\x75\x74\x68\x65\x6e\x74\x69\x63\x61\x74\x69\x6f\x6e"
#  define NID_client_auth                 130
#  define OBJ_client_auth                 OBJ_id_kp,2L

#  define SN_code_sign                    "\x63\x6f\x64\x65\x53\x69\x67\x6e\x69\x6e\x67"
#  define LN_code_sign                    "\x43\x6f\x64\x65\x20\x53\x69\x67\x6e\x69\x6e\x67"
#  define NID_code_sign                   131
#  define OBJ_code_sign                   OBJ_id_kp,3L

#  define SN_email_protect                "\x65\x6d\x61\x69\x6c\x50\x72\x6f\x74\x65\x63\x74\x69\x6f\x6e"
#  define LN_email_protect                "\x45\x2d\x6d\x61\x69\x6c\x20\x50\x72\x6f\x74\x65\x63\x74\x69\x6f\x6e"
#  define NID_email_protect               132
#  define OBJ_email_protect               OBJ_id_kp,4L

#  define SN_time_stamp                   "\x74\x69\x6d\x65\x53\x74\x61\x6d\x70\x69\x6e\x67"
#  define LN_time_stamp                   "\x54\x69\x6d\x65\x20\x53\x74\x61\x6d\x70\x69\x6e\x67"
#  define NID_time_stamp                  133
#  define OBJ_time_stamp                  OBJ_id_kp,8L

/* Additional extended key usage OIDs: Microsoft */

#  define SN_ms_code_ind                  "\x6d\x73\x43\x6f\x64\x65\x49\x6e\x64"
#  define LN_ms_code_ind                  "\x4d\x69\x63\x72\x6f\x73\x6f\x66\x74\x20\x49\x6e\x64\x69\x76\x69\x64\x75\x61\x6c\x20\x43\x6f\x64\x65\x20\x53\x69\x67\x6e\x69\x6e\x67"
#  define NID_ms_code_ind                 134
#  define OBJ_ms_code_ind                 1L,3L,6L,1L,4L,1L,311L,2L,1L,21L

#  define SN_ms_code_com                  "\x6d\x73\x43\x6f\x64\x65\x43\x6f\x6d"
#  define LN_ms_code_com                  "\x4d\x69\x63\x72\x6f\x73\x6f\x66\x74\x20\x43\x6f\x6d\x6d\x65\x72\x63\x69\x61\x6c\x20\x43\x6f\x64\x65\x20\x53\x69\x67\x6e\x69\x6e\x67"
#  define NID_ms_code_com                 135
#  define OBJ_ms_code_com                 1L,3L,6L,1L,4L,1L,311L,2L,1L,22L

#  define SN_ms_ctl_sign                  "\x6d\x73\x43\x54\x4c\x53\x69\x67\x6e"
#  define LN_ms_ctl_sign                  "\x4d\x69\x63\x72\x6f\x73\x6f\x66\x74\x20\x54\x72\x75\x73\x74\x20\x4c\x69\x73\x74\x20\x53\x69\x67\x6e\x69\x6e\x67"
#  define NID_ms_ctl_sign                 136
#  define OBJ_ms_ctl_sign                 1L,3L,6L,1L,4L,1L,311L,10L,3L,1L

#  define SN_ms_sgc                       "\x6d\x73\x53\x47\x43"
#  define LN_ms_sgc                       "\x4d\x69\x63\x72\x6f\x73\x6f\x66\x74\x20\x53\x65\x72\x76\x65\x72\x20\x47\x61\x74\x65\x64\x20\x43\x72\x79\x70\x74\x6f"
#  define NID_ms_sgc                      137
#  define OBJ_ms_sgc                      1L,3L,6L,1L,4L,1L,311L,10L,3L,3L

#  define SN_ms_efs                       "\x6d\x73\x45\x46\x53"
#  define LN_ms_efs                       "\x4d\x69\x63\x72\x6f\x73\x6f\x66\x74\x20\x45\x6e\x63\x72\x79\x70\x74\x65\x64\x20\x46\x69\x6c\x65\x20\x53\x79\x73\x74\x65\x6d"
#  define NID_ms_efs                      138
#  define OBJ_ms_efs                      1L,3L,6L,1L,4L,1L,311L,10L,3L,4L

/* Additional usage: Netscape */

#  define SN_ns_sgc                       "\x6e\x73\x53\x47\x43"
#  define LN_ns_sgc                       "\x4e\x65\x74\x73\x63\x61\x70\x65\x20\x53\x65\x72\x76\x65\x72\x20\x47\x61\x74\x65\x64\x20\x43\x72\x79\x70\x74\x6f"
#  define NID_ns_sgc                      139
#  define OBJ_ns_sgc                      OBJ_netscape,4L,1L

#  define SN_delta_crl                    "\x64\x65\x6c\x74\x61\x43\x52\x4c"
#  define LN_delta_crl                    "\x58\x35\x30\x39\x76\x33\x20\x44\x65\x6c\x74\x61\x20\x43\x52\x4c\x20\x49\x6e\x64\x69\x63\x61\x74\x6f\x72"
#  define NID_delta_crl                   140
#  define OBJ_delta_crl                   OBJ_id_ce,27L

#  define SN_crl_reason                   "\x43\x52\x4c\x52\x65\x61\x73\x6f\x6e"
#  define LN_crl_reason                   "\x43\x52\x4c\x20\x52\x65\x61\x73\x6f\x6e\x20\x43\x6f\x64\x65"
#  define NID_crl_reason                  141
#  define OBJ_crl_reason                  OBJ_id_ce,21L

#  define SN_invalidity_date              "\x69\x6e\x76\x61\x6c\x69\x64\x69\x74\x79\x44\x61\x74\x65"
#  define LN_invalidity_date              "\x49\x6e\x76\x61\x6c\x69\x64\x69\x74\x79\x20\x44\x61\x74\x65"
#  define NID_invalidity_date             142
#  define OBJ_invalidity_date             OBJ_id_ce,24L

#  define SN_sxnet                        "\x53\x58\x4e\x65\x74\x49\x44"
#  define LN_sxnet                        "\x53\x74\x72\x6f\x6e\x67\x20\x45\x78\x74\x72\x61\x6e\x65\x74\x20\x49\x44"
#  define NID_sxnet                       143
#  define OBJ_sxnet                       1L,3L,101L,1L,4L,1L

/* PKCS12 and related OBJECT IDENTIFIERS */

#  define OBJ_pkcs12                      OBJ_pkcs,12L
#  define OBJ_pkcs12_pbeids               OBJ_pkcs12, 1

#  define SN_pbe_WithSHA1And128BitRC4     "\x50\x42\x45\x2d\x53\x48\x41\x31\x2d\x52\x43\x34\x2d\x31\x32\x38"
#  define LN_pbe_WithSHA1And128BitRC4     "\x70\x62\x65\x57\x69\x74\x68\x53\x48\x41\x31\x41\x6e\x64\x31\x32\x38\x42\x69\x74\x52\x43\x34"
#  define NID_pbe_WithSHA1And128BitRC4    144
#  define OBJ_pbe_WithSHA1And128BitRC4    OBJ_pkcs12_pbeids, 1L

#  define SN_pbe_WithSHA1And40BitRC4      "\x50\x42\x45\x2d\x53\x48\x41\x31\x2d\x52\x43\x34\x2d\x34\x30"
#  define LN_pbe_WithSHA1And40BitRC4      "\x70\x62\x65\x57\x69\x74\x68\x53\x48\x41\x31\x41\x6e\x64\x34\x30\x42\x69\x74\x52\x43\x34"
#  define NID_pbe_WithSHA1And40BitRC4     145
#  define OBJ_pbe_WithSHA1And40BitRC4     OBJ_pkcs12_pbeids, 2L

#  define SN_pbe_WithSHA1And3_Key_TripleDES_CBC   "\x50\x42\x45\x2d\x53\x48\x41\x31\x2d\x33\x44\x45\x53"
#  define LN_pbe_WithSHA1And3_Key_TripleDES_CBC   "\x70\x62\x65\x57\x69\x74\x68\x53\x48\x41\x31\x41\x6e\x64\x33\x2d\x4b\x65\x79\x54\x72\x69\x70\x6c\x65\x44\x45\x53\x2d\x43\x42\x43"
#  define NID_pbe_WithSHA1And3_Key_TripleDES_CBC  146
#  define OBJ_pbe_WithSHA1And3_Key_TripleDES_CBC  OBJ_pkcs12_pbeids, 3L

#  define SN_pbe_WithSHA1And2_Key_TripleDES_CBC   "\x50\x42\x45\x2d\x53\x48\x41\x31\x2d\x32\x44\x45\x53"
#  define LN_pbe_WithSHA1And2_Key_TripleDES_CBC   "\x70\x62\x65\x57\x69\x74\x68\x53\x48\x41\x31\x41\x6e\x64\x32\x2d\x4b\x65\x79\x54\x72\x69\x70\x6c\x65\x44\x45\x53\x2d\x43\x42\x43"
#  define NID_pbe_WithSHA1And2_Key_TripleDES_CBC  147
#  define OBJ_pbe_WithSHA1And2_Key_TripleDES_CBC  OBJ_pkcs12_pbeids, 4L

#  define SN_pbe_WithSHA1And128BitRC2_CBC         "\x50\x42\x45\x2d\x53\x48\x41\x31\x2d\x52\x43\x32\x2d\x31\x32\x38"
#  define LN_pbe_WithSHA1And128BitRC2_CBC         "\x70\x62\x65\x57\x69\x74\x68\x53\x48\x41\x31\x41\x6e\x64\x31\x32\x38\x42\x69\x74\x52\x43\x32\x2d\x43\x42\x43"
#  define NID_pbe_WithSHA1And128BitRC2_CBC        148
#  define OBJ_pbe_WithSHA1And128BitRC2_CBC        OBJ_pkcs12_pbeids, 5L

#  define SN_pbe_WithSHA1And40BitRC2_CBC  "\x50\x42\x45\x2d\x53\x48\x41\x31\x2d\x52\x43\x32\x2d\x34\x30"
#  define LN_pbe_WithSHA1And40BitRC2_CBC  "\x70\x62\x65\x57\x69\x74\x68\x53\x48\x41\x31\x41\x6e\x64\x34\x30\x42\x69\x74\x52\x43\x32\x2d\x43\x42\x43"
#  define NID_pbe_WithSHA1And40BitRC2_CBC 149
#  define OBJ_pbe_WithSHA1And40BitRC2_CBC OBJ_pkcs12_pbeids, 6L

#  define OBJ_pkcs12_Version1     OBJ_pkcs12, 10L

#  define OBJ_pkcs12_BagIds       OBJ_pkcs12_Version1, 1L

#  define LN_keyBag               "\x6b\x65\x79\x42\x61\x67"
#  define NID_keyBag              150
#  define OBJ_keyBag              OBJ_pkcs12_BagIds, 1L

#  define LN_pkcs8ShroudedKeyBag  "\x70\x6b\x63\x73\x38\x53\x68\x72\x6f\x75\x64\x65\x64\x4b\x65\x79\x42\x61\x67"
#  define NID_pkcs8ShroudedKeyBag 151
#  define OBJ_pkcs8ShroudedKeyBag OBJ_pkcs12_BagIds, 2L

#  define LN_certBag              "\x63\x65\x72\x74\x42\x61\x67"
#  define NID_certBag             152
#  define OBJ_certBag             OBJ_pkcs12_BagIds, 3L

#  define LN_crlBag               "\x63\x72\x6c\x42\x61\x67"
#  define NID_crlBag              153
#  define OBJ_crlBag              OBJ_pkcs12_BagIds, 4L

#  define LN_secretBag            "\x73\x65\x63\x72\x65\x74\x42\x61\x67"
#  define NID_secretBag           154
#  define OBJ_secretBag           OBJ_pkcs12_BagIds, 5L

#  define LN_safeContentsBag      "\x73\x61\x66\x65\x43\x6f\x6e\x74\x65\x6e\x74\x73\x42\x61\x67"
#  define NID_safeContentsBag     155
#  define OBJ_safeContentsBag     OBJ_pkcs12_BagIds, 6L

#  define LN_friendlyName         "\x66\x72\x69\x65\x6e\x64\x6c\x79\x4e\x61\x6d\x65"
#  define NID_friendlyName        156
#  define OBJ_friendlyName        OBJ_pkcs9, 20L

#  define LN_localKeyID           "\x6c\x6f\x63\x61\x6c\x4b\x65\x79\x49\x44"
#  define NID_localKeyID          157
#  define OBJ_localKeyID          OBJ_pkcs9, 21L

#  define OBJ_certTypes           OBJ_pkcs9, 22L

#  define LN_x509Certificate      "\x78\x35\x30\x39\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65"
#  define NID_x509Certificate     158
#  define OBJ_x509Certificate     OBJ_certTypes, 1L

#  define LN_sdsiCertificate      "\x73\x64\x73\x69\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65"
#  define NID_sdsiCertificate     159
#  define OBJ_sdsiCertificate     OBJ_certTypes, 2L

#  define OBJ_crlTypes            OBJ_pkcs9, 23L

#  define LN_x509Crl              "\x78\x35\x30\x39\x43\x72\x6c"
#  define NID_x509Crl             160
#  define OBJ_x509Crl             OBJ_crlTypes, 1L

/* PKCS#5 v2 OIDs */

#  define LN_pbes2                "\x50\x42\x45\x53\x32"
#  define NID_pbes2               161
#  define OBJ_pbes2               OBJ_pkcs,5L,13L

#  define LN_pbmac1               "\x50\x42\x4d\x41\x43\x31"
#  define NID_pbmac1              162
#  define OBJ_pbmac1              OBJ_pkcs,5L,14L

#  define LN_hmacWithSHA1         "\x68\x6d\x61\x63\x57\x69\x74\x68\x53\x48\x41\x31"
#  define NID_hmacWithSHA1        163
#  define OBJ_hmacWithSHA1        OBJ_rsadsi,2L,7L

/* Policy Qualifier Ids */

#  define LN_id_qt_cps            "\x50\x6f\x6c\x69\x63\x79\x20\x51\x75\x61\x6c\x69\x66\x69\x65\x72\x20\x43\x50\x53"
#  define SN_id_qt_cps            "\x69\x64\x2d\x71\x74\x2d\x63\x70\x73"
#  define NID_id_qt_cps           164
#  define OBJ_id_qt_cps           OBJ_id_pkix,2L,1L

#  define LN_id_qt_unotice        "\x50\x6f\x6c\x69\x63\x79\x20\x51\x75\x61\x6c\x69\x66\x69\x65\x72\x20\x55\x73\x65\x72\x20\x4e\x6f\x74\x69\x63\x65"
#  define SN_id_qt_unotice        "\x69\x64\x2d\x71\x74\x2d\x75\x6e\x6f\x74\x69\x63\x65"
#  define NID_id_qt_unotice       165
#  define OBJ_id_qt_unotice       OBJ_id_pkix,2L,2L

#  define SN_rc2_64_cbc                   "\x52\x43\x32\x2d\x36\x34\x2d\x43\x42\x43"
#  define LN_rc2_64_cbc                   "\x72\x63\x32\x2d\x36\x34\x2d\x63\x62\x63"
#  define NID_rc2_64_cbc                  166

#  define SN_SMIMECapabilities            "\x53\x4d\x49\x4d\x45\x2d\x43\x41\x50\x53"
#  define LN_SMIMECapabilities            "\x53\x2f\x4d\x49\x4d\x45\x20\x43\x61\x70\x61\x62\x69\x6c\x69\x74\x69\x65\x73"
#  define NID_SMIMECapabilities           167
#  define OBJ_SMIMECapabilities           OBJ_pkcs9,15L

#  define SN_pbeWithMD2AndRC2_CBC         "\x50\x42\x45\x2d\x4d\x44\x32\x2d\x52\x43\x32\x2d\x36\x34"
#  define LN_pbeWithMD2AndRC2_CBC         "\x70\x62\x65\x57\x69\x74\x68\x4d\x44\x32\x41\x6e\x64\x52\x43\x32\x2d\x43\x42\x43"
#  define NID_pbeWithMD2AndRC2_CBC        168
#  define OBJ_pbeWithMD2AndRC2_CBC        OBJ_pkcs,5L,4L

#  define SN_pbeWithMD5AndRC2_CBC         "\x50\x42\x45\x2d\x4d\x44\x35\x2d\x52\x43\x32\x2d\x36\x34"
#  define LN_pbeWithMD5AndRC2_CBC         "\x70\x62\x65\x57\x69\x74\x68\x4d\x44\x35\x41\x6e\x64\x52\x43\x32\x2d\x43\x42\x43"
#  define NID_pbeWithMD5AndRC2_CBC        169
#  define OBJ_pbeWithMD5AndRC2_CBC        OBJ_pkcs,5L,6L

#  define SN_pbeWithSHA1AndDES_CBC        "\x50\x42\x45\x2d\x53\x48\x41\x31\x2d\x44\x45\x53"
#  define LN_pbeWithSHA1AndDES_CBC        "\x70\x62\x65\x57\x69\x74\x68\x53\x48\x41\x31\x41\x6e\x64\x44\x45\x53\x2d\x43\x42\x43"
#  define NID_pbeWithSHA1AndDES_CBC       170
#  define OBJ_pbeWithSHA1AndDES_CBC       OBJ_pkcs,5L,10L

/* Extension request OIDs */

#  define LN_ms_ext_req                   "\x4d\x69\x63\x72\x6f\x73\x6f\x66\x74\x20\x45\x78\x74\x65\x6e\x73\x69\x6f\x6e\x20\x52\x65\x71\x75\x65\x73\x74"
#  define SN_ms_ext_req                   "\x6d\x73\x45\x78\x74\x52\x65\x71"
#  define NID_ms_ext_req                  171
#  define OBJ_ms_ext_req                  1L,3L,6L,1L,4L,1L,311L,2L,1L,14L

#  define LN_ext_req                      "\x45\x78\x74\x65\x6e\x73\x69\x6f\x6e\x20\x52\x65\x71\x75\x65\x73\x74"
#  define SN_ext_req                      "\x65\x78\x74\x52\x65\x71"
#  define NID_ext_req                     172
#  define OBJ_ext_req                     OBJ_pkcs9,14L

#  define SN_name                         "\x6e\x61\x6d\x65"
#  define LN_name                         "\x6e\x61\x6d\x65"
#  define NID_name                        173
#  define OBJ_name                        OBJ_X509,41L

#  define SN_dnQualifier                  "\x64\x6e\x51\x75\x61\x6c\x69\x66\x69\x65\x72"
#  define LN_dnQualifier                  "\x64\x6e\x51\x75\x61\x6c\x69\x66\x69\x65\x72"
#  define NID_dnQualifier                 174
#  define OBJ_dnQualifier                 OBJ_X509,46L

#  define SN_id_pe                        "\x69\x64\x2d\x70\x65"
#  define NID_id_pe                       175
#  define OBJ_id_pe                       OBJ_id_pkix,1L

#  define SN_id_ad                        "\x69\x64\x2d\x61\x64"
#  define NID_id_ad                       176
#  define OBJ_id_ad                       OBJ_id_pkix,48L

#  define SN_info_access                  "\x61\x75\x74\x68\x6f\x72\x69\x74\x79\x49\x6e\x66\x6f\x41\x63\x63\x65\x73\x73"
#  define LN_info_access                  "\x41\x75\x74\x68\x6f\x72\x69\x74\x79\x20\x49\x6e\x66\x6f\x72\x6d\x61\x74\x69\x6f\x6e\x20\x41\x63\x63\x65\x73\x73"
#  define NID_info_access                 177
#  define OBJ_info_access                 OBJ_id_pe,1L

#  define SN_ad_OCSP                      "\x4f\x43\x53\x50"
#  define LN_ad_OCSP                      "\x4f\x43\x53\x50"
#  define NID_ad_OCSP                     178
#  define OBJ_ad_OCSP                     OBJ_id_ad,1L

#  define SN_ad_ca_issuers                "\x63\x61\x49\x73\x73\x75\x65\x72\x73"
#  define LN_ad_ca_issuers                "\x43\x41\x20\x49\x73\x73\x75\x65\x72\x73"
#  define NID_ad_ca_issuers               179
#  define OBJ_ad_ca_issuers               OBJ_id_ad,2L

#  define SN_OCSP_sign                    "\x4f\x43\x53\x50\x53\x69\x67\x6e\x69\x6e\x67"
#  define LN_OCSP_sign                    "\x4f\x43\x53\x50\x20\x53\x69\x67\x6e\x69\x6e\x67"
#  define NID_OCSP_sign                   180
#  define OBJ_OCSP_sign                   OBJ_id_kp,9L
# endif                         /* USE_OBJ_MAC */

# include <openssl/bio.h>
# include <openssl/asn1.h>

# define OBJ_NAME_TYPE_UNDEF             0x00
# define OBJ_NAME_TYPE_MD_METH           0x01
# define OBJ_NAME_TYPE_CIPHER_METH       0x02
# define OBJ_NAME_TYPE_PKEY_METH         0x03
# define OBJ_NAME_TYPE_COMP_METH         0x04
# define OBJ_NAME_TYPE_NUM               0x05

# define OBJ_NAME_ALIAS                  0x8000

# define OBJ_BSEARCH_VALUE_ON_NOMATCH            0x01
# define OBJ_BSEARCH_FIRST_VALUE_ON_MATCH        0x02


#ifdef  __cplusplus
extern "C" {
#endif

typedef struct obj_name_st {
    int type;
    int alias;
    const char *name;
    const char *data;
} OBJ_NAME;

# define         OBJ_create_and_add_object(a,b,c) OBJ_create(a,b,c)

int OBJ_NAME_init(void);
int OBJ_NAME_new_index(unsigned long (*hash_func) (const char *),
                       int (*cmp_func) (const char *, const char *),
                       void (*free_func) (const char *, int, const char *));
const char *OBJ_NAME_get(const char *name, int type);
int OBJ_NAME_add(const char *name, int type, const char *data);
int OBJ_NAME_remove(const char *name, int type);
void OBJ_NAME_cleanup(int type); /* -1 for everything */
void OBJ_NAME_do_all(int type, void (*fn) (const OBJ_NAME *, void *arg),
                     void *arg);
void OBJ_NAME_do_all_sorted(int type,
                            void (*fn) (const OBJ_NAME *, void *arg),
                            void *arg);

ASN1_OBJECT *OBJ_dup(const ASN1_OBJECT *o);
ASN1_OBJECT *OBJ_nid2obj(int n);
const char *OBJ_nid2ln(int n);
const char *OBJ_nid2sn(int n);
int OBJ_obj2nid(const ASN1_OBJECT *o);
ASN1_OBJECT *OBJ_txt2obj(const char *s, int no_name);
int OBJ_obj2txt(char *buf, int buf_len, const ASN1_OBJECT *a, int no_name);
int OBJ_txt2nid(const char *s);
int OBJ_ln2nid(const char *s);
int OBJ_sn2nid(const char *s);
int OBJ_cmp(const ASN1_OBJECT *a, const ASN1_OBJECT *b);
const void *OBJ_bsearch_(const void *key, const void *base, int num, int size,
                         int (*cmp) (const void *, const void *));
const void *OBJ_bsearch_ex_(const void *key, const void *base, int num,
                            int size,
                            int (*cmp) (const void *, const void *),
                            int flags);

# define _DECLARE_OBJ_BSEARCH_CMP_FN(scope, type1, type2, nm)    \
  static int nm##_cmp_BSEARCH_CMP_FN(const void *, const void *); \
  static int nm##_cmp(type1 const *, type2 const *); \
  scope type2 * OBJ_bsearch_##nm(type1 *key, type2 const *base, int num)

# define DECLARE_OBJ_BSEARCH_CMP_FN(type1, type2, cmp)   \
  _DECLARE_OBJ_BSEARCH_CMP_FN(static, type1, type2, cmp)
# define DECLARE_OBJ_BSEARCH_GLOBAL_CMP_FN(type1, type2, nm)     \
  type2 * OBJ_bsearch_##nm(type1 *key, type2 const *base, int num)

/*-
 * Unsolved problem: if a type is actually a pointer type, like
 * nid_triple is, then its impossible to get a const where you need
 * it. Consider:
 *
 * typedef int nid_triple[3];
 * const void *a_;
 * const nid_triple const *a = a_;
 *
 * The assignement discards a const because what you really want is:
 *
 * const int const * const *a = a_;
 *
 * But if you do that, you lose the fact that a is an array of 3 ints,
 * which breaks comparison functions.
 *
 * Thus we end up having to cast, sadly, or unpack the
 * declarations. Or, as I finally did in this case, delcare nid_triple
 * to be a struct, which it should have been in the first place.
 *
 * Ben, August 2008.
 *
 * Also, strictly speaking not all types need be const, but handling
 * the non-constness means a lot of complication, and in practice
 * comparison routines do always not touch their arguments.
 */

# define IMPLEMENT_OBJ_BSEARCH_CMP_FN(type1, type2, nm)  \
  static int nm##_cmp_BSEARCH_CMP_FN(const void *a_, const void *b_)    \
      { \
      type1 const *a = a_; \
      type2 const *b = b_; \
      return nm##_cmp(a,b); \
      } \
  static type2 *OBJ_bsearch_##nm(type1 *key, type2 const *base, int num) \
      { \
      return (type2 *)OBJ_bsearch_(key, base, num, sizeof(type2), \
                                        nm##_cmp_BSEARCH_CMP_FN); \
      } \
      extern void dummy_prototype(void)

# define IMPLEMENT_OBJ_BSEARCH_GLOBAL_CMP_FN(type1, type2, nm)   \
  static int nm##_cmp_BSEARCH_CMP_FN(const void *a_, const void *b_)    \
      { \
      type1 const *a = a_; \
      type2 const *b = b_; \
      return nm##_cmp(a,b); \
      } \
  type2 *OBJ_bsearch_##nm(type1 *key, type2 const *base, int num) \
      { \
      return (type2 *)OBJ_bsearch_(key, base, num, sizeof(type2), \
                                        nm##_cmp_BSEARCH_CMP_FN); \
      } \
      extern void dummy_prototype(void)

# define OBJ_bsearch(type1,key,type2,base,num,cmp)                              \
  ((type2 *)OBJ_bsearch_(CHECKED_PTR_OF(type1,key),CHECKED_PTR_OF(type2,base), \
                         num,sizeof(type2),                             \
                         ((void)CHECKED_PTR_OF(type1,cmp##_type_1),     \
                          (void)CHECKED_PTR_OF(type2,cmp##_type_2),     \
                          cmp##_BSEARCH_CMP_FN)))

# define OBJ_bsearch_ex(type1,key,type2,base,num,cmp,flags)                      \
  ((type2 *)OBJ_bsearch_ex_(CHECKED_PTR_OF(type1,key),CHECKED_PTR_OF(type2,base), \
                         num,sizeof(type2),                             \
                         ((void)CHECKED_PTR_OF(type1,cmp##_type_1),     \
                          (void)type_2=CHECKED_PTR_OF(type2,cmp##_type_2), \
                          cmp##_BSEARCH_CMP_FN)),flags)

int OBJ_new_nid(int num);
int OBJ_add_object(const ASN1_OBJECT *obj);
int OBJ_create(const char *oid, const char *sn, const char *ln);
void OBJ_cleanup(void);
int OBJ_create_objects(BIO *in);

int OBJ_find_sigid_algs(int signid, int *pdig_nid, int *ppkey_nid);
int OBJ_find_sigid_by_algs(int *psignid, int dig_nid, int pkey_nid);
int OBJ_add_sigid(int signid, int dig_id, int pkey_id);
void OBJ_sigid_free(void);

extern int obj_cleanup_defer;
void check_defer(int nid);

/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_OBJ_strings(void);

/* Error codes for the OBJ functions. */

/* Function codes. */
# define OBJ_F_OBJ_ADD_OBJECT                             105
# define OBJ_F_OBJ_CREATE                                 100
# define OBJ_F_OBJ_DUP                                    101
# define OBJ_F_OBJ_NAME_NEW_INDEX                         106
# define OBJ_F_OBJ_NID2LN                                 102
# define OBJ_F_OBJ_NID2OBJ                                103
# define OBJ_F_OBJ_NID2SN                                 104

/* Reason codes. */
# define OBJ_R_MALLOC_FAILURE                             100
# define OBJ_R_UNKNOWN_NID                                101

#ifdef  __cplusplus
}
#endif
#endif
