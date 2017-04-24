/* crypto/objects/obj_mac.h */

/*
 * THIS FILE IS GENERATED FROM objects.txt by objects.pl via the following
 * command: perl objects.pl objects.txt obj_mac.num obj_mac.h
 */

/* Copyright (C) 1995-1997 Eric Young (eay@cryptsoft.com)
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
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
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

#define SN_undef                        "\x55\x4e\x44\x45\x46"
#define LN_undef                        "\x75\x6e\x64\x65\x66\x69\x6e\x65\x64"
#define NID_undef                       0
#define OBJ_undef                       0L

#define SN_itu_t                "\x49\x54\x55\x2d\x54"
#define LN_itu_t                "\x69\x74\x75\x2d\x74"
#define NID_itu_t               645
#define OBJ_itu_t               0L

#define NID_ccitt               404
#define OBJ_ccitt               OBJ_itu_t

#define SN_iso          "\x49\x53\x4f"
#define LN_iso          "\x69\x73\x6f"
#define NID_iso         181
#define OBJ_iso         1L

#define SN_joint_iso_itu_t              "\x4a\x4f\x49\x4e\x54\x2d\x49\x53\x4f\x2d\x49\x54\x55\x2d\x54"
#define LN_joint_iso_itu_t              "\x6a\x6f\x69\x6e\x74\x2d\x69\x73\x6f\x2d\x69\x74\x75\x2d\x74"
#define NID_joint_iso_itu_t             646
#define OBJ_joint_iso_itu_t             2L

#define NID_joint_iso_ccitt             393
#define OBJ_joint_iso_ccitt             OBJ_joint_iso_itu_t

#define SN_member_body          "\x6d\x65\x6d\x62\x65\x72\x2d\x62\x6f\x64\x79"
#define LN_member_body          "\x49\x53\x4f\x20\x4d\x65\x6d\x62\x65\x72\x20\x42\x6f\x64\x79"
#define NID_member_body         182
#define OBJ_member_body         OBJ_iso,2L

#define SN_identified_organization              "\x69\x64\x65\x6e\x74\x69\x66\x69\x65\x64\x2d\x6f\x72\x67\x61\x6e\x69\x7a\x61\x74\x69\x6f\x6e"
#define NID_identified_organization             676
#define OBJ_identified_organization             OBJ_iso,3L

#define SN_hmac_md5             "\x48\x4d\x41\x43\x2d\x4d\x44\x35"
#define LN_hmac_md5             "\x68\x6d\x61\x63\x2d\x6d\x64\x35"
#define NID_hmac_md5            780
#define OBJ_hmac_md5            OBJ_identified_organization,6L,1L,5L,5L,8L,1L,1L

#define SN_hmac_sha1            "\x48\x4d\x41\x43\x2d\x53\x48\x41\x31"
#define LN_hmac_sha1            "\x68\x6d\x61\x63\x2d\x73\x68\x61\x31"
#define NID_hmac_sha1           781
#define OBJ_hmac_sha1           OBJ_identified_organization,6L,1L,5L,5L,8L,1L,2L

#define SN_certicom_arc         "\x63\x65\x72\x74\x69\x63\x6f\x6d\x2d\x61\x72\x63"
#define NID_certicom_arc                677
#define OBJ_certicom_arc                OBJ_identified_organization,132L

#define SN_international_organizations          "\x69\x6e\x74\x65\x72\x6e\x61\x74\x69\x6f\x6e\x61\x6c\x2d\x6f\x72\x67\x61\x6e\x69\x7a\x61\x74\x69\x6f\x6e\x73"
#define LN_international_organizations          "\x49\x6e\x74\x65\x72\x6e\x61\x74\x69\x6f\x6e\x61\x6c\x20\x4f\x72\x67\x61\x6e\x69\x7a\x61\x74\x69\x6f\x6e\x73"
#define NID_international_organizations         647
#define OBJ_international_organizations         OBJ_joint_iso_itu_t,23L

#define SN_wap          "\x77\x61\x70"
#define NID_wap         678
#define OBJ_wap         OBJ_international_organizations,43L

#define SN_wap_wsg              "\x77\x61\x70\x2d\x77\x73\x67"
#define NID_wap_wsg             679
#define OBJ_wap_wsg             OBJ_wap,1L

#define SN_selected_attribute_types             "\x73\x65\x6c\x65\x63\x74\x65\x64\x2d\x61\x74\x74\x72\x69\x62\x75\x74\x65\x2d\x74\x79\x70\x65\x73"
#define LN_selected_attribute_types             "\x53\x65\x6c\x65\x63\x74\x65\x64\x20\x41\x74\x74\x72\x69\x62\x75\x74\x65\x20\x54\x79\x70\x65\x73"
#define NID_selected_attribute_types            394
#define OBJ_selected_attribute_types            OBJ_joint_iso_itu_t,5L,1L,5L

#define SN_clearance            "\x63\x6c\x65\x61\x72\x61\x6e\x63\x65"
#define NID_clearance           395
#define OBJ_clearance           OBJ_selected_attribute_types,55L

#define SN_ISO_US               "\x49\x53\x4f\x2d\x55\x53"
#define LN_ISO_US               "\x49\x53\x4f\x20\x55\x53\x20\x4d\x65\x6d\x62\x65\x72\x20\x42\x6f\x64\x79"
#define NID_ISO_US              183
#define OBJ_ISO_US              OBJ_member_body,840L

#define SN_X9_57                "\x58\x39\x2d\x35\x37"
#define LN_X9_57                "\x58\x39\x2e\x35\x37"
#define NID_X9_57               184
#define OBJ_X9_57               OBJ_ISO_US,10040L

#define SN_X9cm         "\x58\x39\x63\x6d"
#define LN_X9cm         "\x58\x39\x2e\x35\x37\x20\x43\x4d\x20\x3f"
#define NID_X9cm                185
#define OBJ_X9cm                OBJ_X9_57,4L

#define SN_dsa          "\x44\x53\x41"
#define LN_dsa          "\x64\x73\x61\x45\x6e\x63\x72\x79\x70\x74\x69\x6f\x6e"
#define NID_dsa         116
#define OBJ_dsa         OBJ_X9cm,1L

#define SN_dsaWithSHA1          "\x44\x53\x41\x2d\x53\x48\x41\x31"
#define LN_dsaWithSHA1          "\x64\x73\x61\x57\x69\x74\x68\x53\x48\x41\x31"
#define NID_dsaWithSHA1         113
#define OBJ_dsaWithSHA1         OBJ_X9cm,3L

#define SN_ansi_X9_62           "\x61\x6e\x73\x69\x2d\x58\x39\x2d\x36\x32"
#define LN_ansi_X9_62           "\x41\x4e\x53\x49\x20\x58\x39\x2e\x36\x32"
#define NID_ansi_X9_62          405
#define OBJ_ansi_X9_62          OBJ_ISO_US,10045L

#define OBJ_X9_62_id_fieldType          OBJ_ansi_X9_62,1L

#define SN_X9_62_prime_field            "\x70\x72\x69\x6d\x65\x2d\x66\x69\x65\x6c\x64"
#define NID_X9_62_prime_field           406
#define OBJ_X9_62_prime_field           OBJ_X9_62_id_fieldType,1L

#define SN_X9_62_characteristic_two_field               "\x63\x68\x61\x72\x61\x63\x74\x65\x72\x69\x73\x74\x69\x63\x2d\x74\x77\x6f\x2d\x66\x69\x65\x6c\x64"
#define NID_X9_62_characteristic_two_field              407
#define OBJ_X9_62_characteristic_two_field              OBJ_X9_62_id_fieldType,2L

#define SN_X9_62_id_characteristic_two_basis            "\x69\x64\x2d\x63\x68\x61\x72\x61\x63\x74\x65\x72\x69\x73\x74\x69\x63\x2d\x74\x77\x6f\x2d\x62\x61\x73\x69\x73"
#define NID_X9_62_id_characteristic_two_basis           680
#define OBJ_X9_62_id_characteristic_two_basis           OBJ_X9_62_characteristic_two_field,3L

#define SN_X9_62_onBasis                "\x6f\x6e\x42\x61\x73\x69\x73"
#define NID_X9_62_onBasis               681
#define OBJ_X9_62_onBasis               OBJ_X9_62_id_characteristic_two_basis,1L

#define SN_X9_62_tpBasis                "\x74\x70\x42\x61\x73\x69\x73"
#define NID_X9_62_tpBasis               682
#define OBJ_X9_62_tpBasis               OBJ_X9_62_id_characteristic_two_basis,2L

#define SN_X9_62_ppBasis                "\x70\x70\x42\x61\x73\x69\x73"
#define NID_X9_62_ppBasis               683
#define OBJ_X9_62_ppBasis               OBJ_X9_62_id_characteristic_two_basis,3L

#define OBJ_X9_62_id_publicKeyType              OBJ_ansi_X9_62,2L

#define SN_X9_62_id_ecPublicKey         "\x69\x64\x2d\x65\x63\x50\x75\x62\x6c\x69\x63\x4b\x65\x79"
#define NID_X9_62_id_ecPublicKey                408
#define OBJ_X9_62_id_ecPublicKey                OBJ_X9_62_id_publicKeyType,1L

#define OBJ_X9_62_ellipticCurve         OBJ_ansi_X9_62,3L

#define OBJ_X9_62_c_TwoCurve            OBJ_X9_62_ellipticCurve,0L

#define SN_X9_62_c2pnb163v1             "\x63\x32\x70\x6e\x62\x31\x36\x33\x76\x31"
#define NID_X9_62_c2pnb163v1            684
#define OBJ_X9_62_c2pnb163v1            OBJ_X9_62_c_TwoCurve,1L

#define SN_X9_62_c2pnb163v2             "\x63\x32\x70\x6e\x62\x31\x36\x33\x76\x32"
#define NID_X9_62_c2pnb163v2            685
#define OBJ_X9_62_c2pnb163v2            OBJ_X9_62_c_TwoCurve,2L

#define SN_X9_62_c2pnb163v3             "\x63\x32\x70\x6e\x62\x31\x36\x33\x76\x33"
#define NID_X9_62_c2pnb163v3            686
#define OBJ_X9_62_c2pnb163v3            OBJ_X9_62_c_TwoCurve,3L

#define SN_X9_62_c2pnb176v1             "\x63\x32\x70\x6e\x62\x31\x37\x36\x76\x31"
#define NID_X9_62_c2pnb176v1            687
#define OBJ_X9_62_c2pnb176v1            OBJ_X9_62_c_TwoCurve,4L

#define SN_X9_62_c2tnb191v1             "\x63\x32\x74\x6e\x62\x31\x39\x31\x76\x31"
#define NID_X9_62_c2tnb191v1            688
#define OBJ_X9_62_c2tnb191v1            OBJ_X9_62_c_TwoCurve,5L

#define SN_X9_62_c2tnb191v2             "\x63\x32\x74\x6e\x62\x31\x39\x31\x76\x32"
#define NID_X9_62_c2tnb191v2            689
#define OBJ_X9_62_c2tnb191v2            OBJ_X9_62_c_TwoCurve,6L

#define SN_X9_62_c2tnb191v3             "\x63\x32\x74\x6e\x62\x31\x39\x31\x76\x33"
#define NID_X9_62_c2tnb191v3            690
#define OBJ_X9_62_c2tnb191v3            OBJ_X9_62_c_TwoCurve,7L

#define SN_X9_62_c2onb191v4             "\x63\x32\x6f\x6e\x62\x31\x39\x31\x76\x34"
#define NID_X9_62_c2onb191v4            691
#define OBJ_X9_62_c2onb191v4            OBJ_X9_62_c_TwoCurve,8L

#define SN_X9_62_c2onb191v5             "\x63\x32\x6f\x6e\x62\x31\x39\x31\x76\x35"
#define NID_X9_62_c2onb191v5            692
#define OBJ_X9_62_c2onb191v5            OBJ_X9_62_c_TwoCurve,9L

#define SN_X9_62_c2pnb208w1             "\x63\x32\x70\x6e\x62\x32\x30\x38\x77\x31"
#define NID_X9_62_c2pnb208w1            693
#define OBJ_X9_62_c2pnb208w1            OBJ_X9_62_c_TwoCurve,10L

#define SN_X9_62_c2tnb239v1             "\x63\x32\x74\x6e\x62\x32\x33\x39\x76\x31"
#define NID_X9_62_c2tnb239v1            694
#define OBJ_X9_62_c2tnb239v1            OBJ_X9_62_c_TwoCurve,11L

#define SN_X9_62_c2tnb239v2             "\x63\x32\x74\x6e\x62\x32\x33\x39\x76\x32"
#define NID_X9_62_c2tnb239v2            695
#define OBJ_X9_62_c2tnb239v2            OBJ_X9_62_c_TwoCurve,12L

#define SN_X9_62_c2tnb239v3             "\x63\x32\x74\x6e\x62\x32\x33\x39\x76\x33"
#define NID_X9_62_c2tnb239v3            696
#define OBJ_X9_62_c2tnb239v3            OBJ_X9_62_c_TwoCurve,13L

#define SN_X9_62_c2onb239v4             "\x63\x32\x6f\x6e\x62\x32\x33\x39\x76\x34"
#define NID_X9_62_c2onb239v4            697
#define OBJ_X9_62_c2onb239v4            OBJ_X9_62_c_TwoCurve,14L

#define SN_X9_62_c2onb239v5             "\x63\x32\x6f\x6e\x62\x32\x33\x39\x76\x35"
#define NID_X9_62_c2onb239v5            698
#define OBJ_X9_62_c2onb239v5            OBJ_X9_62_c_TwoCurve,15L

#define SN_X9_62_c2pnb272w1             "\x63\x32\x70\x6e\x62\x32\x37\x32\x77\x31"
#define NID_X9_62_c2pnb272w1            699
#define OBJ_X9_62_c2pnb272w1            OBJ_X9_62_c_TwoCurve,16L

#define SN_X9_62_c2pnb304w1             "\x63\x32\x70\x6e\x62\x33\x30\x34\x77\x31"
#define NID_X9_62_c2pnb304w1            700
#define OBJ_X9_62_c2pnb304w1            OBJ_X9_62_c_TwoCurve,17L

#define SN_X9_62_c2tnb359v1             "\x63\x32\x74\x6e\x62\x33\x35\x39\x76\x31"
#define NID_X9_62_c2tnb359v1            701
#define OBJ_X9_62_c2tnb359v1            OBJ_X9_62_c_TwoCurve,18L

#define SN_X9_62_c2pnb368w1             "\x63\x32\x70\x6e\x62\x33\x36\x38\x77\x31"
#define NID_X9_62_c2pnb368w1            702
#define OBJ_X9_62_c2pnb368w1            OBJ_X9_62_c_TwoCurve,19L

#define SN_X9_62_c2tnb431r1             "\x63\x32\x74\x6e\x62\x34\x33\x31\x72\x31"
#define NID_X9_62_c2tnb431r1            703
#define OBJ_X9_62_c2tnb431r1            OBJ_X9_62_c_TwoCurve,20L

#define OBJ_X9_62_primeCurve            OBJ_X9_62_ellipticCurve,1L

#define SN_X9_62_prime192v1             "\x70\x72\x69\x6d\x65\x31\x39\x32\x76\x31"
#define NID_X9_62_prime192v1            409
#define OBJ_X9_62_prime192v1            OBJ_X9_62_primeCurve,1L

#define SN_X9_62_prime192v2             "\x70\x72\x69\x6d\x65\x31\x39\x32\x76\x32"
#define NID_X9_62_prime192v2            410
#define OBJ_X9_62_prime192v2            OBJ_X9_62_primeCurve,2L

#define SN_X9_62_prime192v3             "\x70\x72\x69\x6d\x65\x31\x39\x32\x76\x33"
#define NID_X9_62_prime192v3            411
#define OBJ_X9_62_prime192v3            OBJ_X9_62_primeCurve,3L

#define SN_X9_62_prime239v1             "\x70\x72\x69\x6d\x65\x32\x33\x39\x76\x31"
#define NID_X9_62_prime239v1            412
#define OBJ_X9_62_prime239v1            OBJ_X9_62_primeCurve,4L

#define SN_X9_62_prime239v2             "\x70\x72\x69\x6d\x65\x32\x33\x39\x76\x32"
#define NID_X9_62_prime239v2            413
#define OBJ_X9_62_prime239v2            OBJ_X9_62_primeCurve,5L

#define SN_X9_62_prime239v3             "\x70\x72\x69\x6d\x65\x32\x33\x39\x76\x33"
#define NID_X9_62_prime239v3            414
#define OBJ_X9_62_prime239v3            OBJ_X9_62_primeCurve,6L

#define SN_X9_62_prime256v1             "\x70\x72\x69\x6d\x65\x32\x35\x36\x76\x31"
#define NID_X9_62_prime256v1            415
#define OBJ_X9_62_prime256v1            OBJ_X9_62_primeCurve,7L

#define OBJ_X9_62_id_ecSigType          OBJ_ansi_X9_62,4L

#define SN_ecdsa_with_SHA1              "\x65\x63\x64\x73\x61\x2d\x77\x69\x74\x68\x2d\x53\x48\x41\x31"
#define NID_ecdsa_with_SHA1             416
#define OBJ_ecdsa_with_SHA1             OBJ_X9_62_id_ecSigType,1L

#define SN_ecdsa_with_Recommended               "\x65\x63\x64\x73\x61\x2d\x77\x69\x74\x68\x2d\x52\x65\x63\x6f\x6d\x6d\x65\x6e\x64\x65\x64"
#define NID_ecdsa_with_Recommended              791
#define OBJ_ecdsa_with_Recommended              OBJ_X9_62_id_ecSigType,2L

#define SN_ecdsa_with_Specified         "\x65\x63\x64\x73\x61\x2d\x77\x69\x74\x68\x2d\x53\x70\x65\x63\x69\x66\x69\x65\x64"
#define NID_ecdsa_with_Specified                792
#define OBJ_ecdsa_with_Specified                OBJ_X9_62_id_ecSigType,3L

#define SN_ecdsa_with_SHA224            "\x65\x63\x64\x73\x61\x2d\x77\x69\x74\x68\x2d\x53\x48\x41\x32\x32\x34"
#define NID_ecdsa_with_SHA224           793
#define OBJ_ecdsa_with_SHA224           OBJ_ecdsa_with_Specified,1L

#define SN_ecdsa_with_SHA256            "\x65\x63\x64\x73\x61\x2d\x77\x69\x74\x68\x2d\x53\x48\x41\x32\x35\x36"
#define NID_ecdsa_with_SHA256           794
#define OBJ_ecdsa_with_SHA256           OBJ_ecdsa_with_Specified,2L

#define SN_ecdsa_with_SHA384            "\x65\x63\x64\x73\x61\x2d\x77\x69\x74\x68\x2d\x53\x48\x41\x33\x38\x34"
#define NID_ecdsa_with_SHA384           795
#define OBJ_ecdsa_with_SHA384           OBJ_ecdsa_with_Specified,3L

#define SN_ecdsa_with_SHA512            "\x65\x63\x64\x73\x61\x2d\x77\x69\x74\x68\x2d\x53\x48\x41\x35\x31\x32"
#define NID_ecdsa_with_SHA512           796
#define OBJ_ecdsa_with_SHA512           OBJ_ecdsa_with_Specified,4L

#define OBJ_secg_ellipticCurve          OBJ_certicom_arc,0L

#define SN_secp112r1            "\x73\x65\x63\x70\x31\x31\x32\x72\x31"
#define NID_secp112r1           704
#define OBJ_secp112r1           OBJ_secg_ellipticCurve,6L

#define SN_secp112r2            "\x73\x65\x63\x70\x31\x31\x32\x72\x32"
#define NID_secp112r2           705
#define OBJ_secp112r2           OBJ_secg_ellipticCurve,7L

#define SN_secp128r1            "\x73\x65\x63\x70\x31\x32\x38\x72\x31"
#define NID_secp128r1           706
#define OBJ_secp128r1           OBJ_secg_ellipticCurve,28L

#define SN_secp128r2            "\x73\x65\x63\x70\x31\x32\x38\x72\x32"
#define NID_secp128r2           707
#define OBJ_secp128r2           OBJ_secg_ellipticCurve,29L

#define SN_secp160k1            "\x73\x65\x63\x70\x31\x36\x30\x6b\x31"
#define NID_secp160k1           708
#define OBJ_secp160k1           OBJ_secg_ellipticCurve,9L

#define SN_secp160r1            "\x73\x65\x63\x70\x31\x36\x30\x72\x31"
#define NID_secp160r1           709
#define OBJ_secp160r1           OBJ_secg_ellipticCurve,8L

#define SN_secp160r2            "\x73\x65\x63\x70\x31\x36\x30\x72\x32"
#define NID_secp160r2           710
#define OBJ_secp160r2           OBJ_secg_ellipticCurve,30L

#define SN_secp192k1            "\x73\x65\x63\x70\x31\x39\x32\x6b\x31"
#define NID_secp192k1           711
#define OBJ_secp192k1           OBJ_secg_ellipticCurve,31L

#define SN_secp224k1            "\x73\x65\x63\x70\x32\x32\x34\x6b\x31"
#define NID_secp224k1           712
#define OBJ_secp224k1           OBJ_secg_ellipticCurve,32L

#define SN_secp224r1            "\x73\x65\x63\x70\x32\x32\x34\x72\x31"
#define NID_secp224r1           713
#define OBJ_secp224r1           OBJ_secg_ellipticCurve,33L

#define SN_secp256k1            "\x73\x65\x63\x70\x32\x35\x36\x6b\x31"
#define NID_secp256k1           714
#define OBJ_secp256k1           OBJ_secg_ellipticCurve,10L

#define SN_secp384r1            "\x73\x65\x63\x70\x33\x38\x34\x72\x31"
#define NID_secp384r1           715
#define OBJ_secp384r1           OBJ_secg_ellipticCurve,34L

#define SN_secp521r1            "\x73\x65\x63\x70\x35\x32\x31\x72\x31"
#define NID_secp521r1           716
#define OBJ_secp521r1           OBJ_secg_ellipticCurve,35L

#define SN_sect113r1            "\x73\x65\x63\x74\x31\x31\x33\x72\x31"
#define NID_sect113r1           717
#define OBJ_sect113r1           OBJ_secg_ellipticCurve,4L

#define SN_sect113r2            "\x73\x65\x63\x74\x31\x31\x33\x72\x32"
#define NID_sect113r2           718
#define OBJ_sect113r2           OBJ_secg_ellipticCurve,5L

#define SN_sect131r1            "\x73\x65\x63\x74\x31\x33\x31\x72\x31"
#define NID_sect131r1           719
#define OBJ_sect131r1           OBJ_secg_ellipticCurve,22L

#define SN_sect131r2            "\x73\x65\x63\x74\x31\x33\x31\x72\x32"
#define NID_sect131r2           720
#define OBJ_sect131r2           OBJ_secg_ellipticCurve,23L

#define SN_sect163k1            "\x73\x65\x63\x74\x31\x36\x33\x6b\x31"
#define NID_sect163k1           721
#define OBJ_sect163k1           OBJ_secg_ellipticCurve,1L

#define SN_sect163r1            "\x73\x65\x63\x74\x31\x36\x33\x72\x31"
#define NID_sect163r1           722
#define OBJ_sect163r1           OBJ_secg_ellipticCurve,2L

#define SN_sect163r2            "\x73\x65\x63\x74\x31\x36\x33\x72\x32"
#define NID_sect163r2           723
#define OBJ_sect163r2           OBJ_secg_ellipticCurve,15L

#define SN_sect193r1            "\x73\x65\x63\x74\x31\x39\x33\x72\x31"
#define NID_sect193r1           724
#define OBJ_sect193r1           OBJ_secg_ellipticCurve,24L

#define SN_sect193r2            "\x73\x65\x63\x74\x31\x39\x33\x72\x32"
#define NID_sect193r2           725
#define OBJ_sect193r2           OBJ_secg_ellipticCurve,25L

#define SN_sect233k1            "\x73\x65\x63\x74\x32\x33\x33\x6b\x31"
#define NID_sect233k1           726
#define OBJ_sect233k1           OBJ_secg_ellipticCurve,26L

#define SN_sect233r1            "\x73\x65\x63\x74\x32\x33\x33\x72\x31"
#define NID_sect233r1           727
#define OBJ_sect233r1           OBJ_secg_ellipticCurve,27L

#define SN_sect239k1            "\x73\x65\x63\x74\x32\x33\x39\x6b\x31"
#define NID_sect239k1           728
#define OBJ_sect239k1           OBJ_secg_ellipticCurve,3L

#define SN_sect283k1            "\x73\x65\x63\x74\x32\x38\x33\x6b\x31"
#define NID_sect283k1           729
#define OBJ_sect283k1           OBJ_secg_ellipticCurve,16L

#define SN_sect283r1            "\x73\x65\x63\x74\x32\x38\x33\x72\x31"
#define NID_sect283r1           730
#define OBJ_sect283r1           OBJ_secg_ellipticCurve,17L

#define SN_sect409k1            "\x73\x65\x63\x74\x34\x30\x39\x6b\x31"
#define NID_sect409k1           731
#define OBJ_sect409k1           OBJ_secg_ellipticCurve,36L

#define SN_sect409r1            "\x73\x65\x63\x74\x34\x30\x39\x72\x31"
#define NID_sect409r1           732
#define OBJ_sect409r1           OBJ_secg_ellipticCurve,37L

#define SN_sect571k1            "\x73\x65\x63\x74\x35\x37\x31\x6b\x31"
#define NID_sect571k1           733
#define OBJ_sect571k1           OBJ_secg_ellipticCurve,38L

#define SN_sect571r1            "\x73\x65\x63\x74\x35\x37\x31\x72\x31"
#define NID_sect571r1           734
#define OBJ_sect571r1           OBJ_secg_ellipticCurve,39L

#define OBJ_wap_wsg_idm_ecid            OBJ_wap_wsg,4L

#define SN_wap_wsg_idm_ecid_wtls1               "\x77\x61\x70\x2d\x77\x73\x67\x2d\x69\x64\x6d\x2d\x65\x63\x69\x64\x2d\x77\x74\x6c\x73\x31"
#define NID_wap_wsg_idm_ecid_wtls1              735
#define OBJ_wap_wsg_idm_ecid_wtls1              OBJ_wap_wsg_idm_ecid,1L

#define SN_wap_wsg_idm_ecid_wtls3               "\x77\x61\x70\x2d\x77\x73\x67\x2d\x69\x64\x6d\x2d\x65\x63\x69\x64\x2d\x77\x74\x6c\x73\x33"
#define NID_wap_wsg_idm_ecid_wtls3              736
#define OBJ_wap_wsg_idm_ecid_wtls3              OBJ_wap_wsg_idm_ecid,3L

#define SN_wap_wsg_idm_ecid_wtls4               "\x77\x61\x70\x2d\x77\x73\x67\x2d\x69\x64\x6d\x2d\x65\x63\x69\x64\x2d\x77\x74\x6c\x73\x34"
#define NID_wap_wsg_idm_ecid_wtls4              737
#define OBJ_wap_wsg_idm_ecid_wtls4              OBJ_wap_wsg_idm_ecid,4L

#define SN_wap_wsg_idm_ecid_wtls5               "\x77\x61\x70\x2d\x77\x73\x67\x2d\x69\x64\x6d\x2d\x65\x63\x69\x64\x2d\x77\x74\x6c\x73\x35"
#define NID_wap_wsg_idm_ecid_wtls5              738
#define OBJ_wap_wsg_idm_ecid_wtls5              OBJ_wap_wsg_idm_ecid,5L

#define SN_wap_wsg_idm_ecid_wtls6               "\x77\x61\x70\x2d\x77\x73\x67\x2d\x69\x64\x6d\x2d\x65\x63\x69\x64\x2d\x77\x74\x6c\x73\x36"
#define NID_wap_wsg_idm_ecid_wtls6              739
#define OBJ_wap_wsg_idm_ecid_wtls6              OBJ_wap_wsg_idm_ecid,6L

#define SN_wap_wsg_idm_ecid_wtls7               "\x77\x61\x70\x2d\x77\x73\x67\x2d\x69\x64\x6d\x2d\x65\x63\x69\x64\x2d\x77\x74\x6c\x73\x37"
#define NID_wap_wsg_idm_ecid_wtls7              740
#define OBJ_wap_wsg_idm_ecid_wtls7              OBJ_wap_wsg_idm_ecid,7L

#define SN_wap_wsg_idm_ecid_wtls8               "\x77\x61\x70\x2d\x77\x73\x67\x2d\x69\x64\x6d\x2d\x65\x63\x69\x64\x2d\x77\x74\x6c\x73\x38"
#define NID_wap_wsg_idm_ecid_wtls8              741
#define OBJ_wap_wsg_idm_ecid_wtls8              OBJ_wap_wsg_idm_ecid,8L

#define SN_wap_wsg_idm_ecid_wtls9               "\x77\x61\x70\x2d\x77\x73\x67\x2d\x69\x64\x6d\x2d\x65\x63\x69\x64\x2d\x77\x74\x6c\x73\x39"
#define NID_wap_wsg_idm_ecid_wtls9              742
#define OBJ_wap_wsg_idm_ecid_wtls9              OBJ_wap_wsg_idm_ecid,9L

#define SN_wap_wsg_idm_ecid_wtls10              "\x77\x61\x70\x2d\x77\x73\x67\x2d\x69\x64\x6d\x2d\x65\x63\x69\x64\x2d\x77\x74\x6c\x73\x31\x30"
#define NID_wap_wsg_idm_ecid_wtls10             743
#define OBJ_wap_wsg_idm_ecid_wtls10             OBJ_wap_wsg_idm_ecid,10L

#define SN_wap_wsg_idm_ecid_wtls11              "\x77\x61\x70\x2d\x77\x73\x67\x2d\x69\x64\x6d\x2d\x65\x63\x69\x64\x2d\x77\x74\x6c\x73\x31\x31"
#define NID_wap_wsg_idm_ecid_wtls11             744
#define OBJ_wap_wsg_idm_ecid_wtls11             OBJ_wap_wsg_idm_ecid,11L

#define SN_wap_wsg_idm_ecid_wtls12              "\x77\x61\x70\x2d\x77\x73\x67\x2d\x69\x64\x6d\x2d\x65\x63\x69\x64\x2d\x77\x74\x6c\x73\x31\x32"
#define NID_wap_wsg_idm_ecid_wtls12             745
#define OBJ_wap_wsg_idm_ecid_wtls12             OBJ_wap_wsg_idm_ecid,12L

#define SN_cast5_cbc            "\x43\x41\x53\x54\x35\x2d\x43\x42\x43"
#define LN_cast5_cbc            "\x63\x61\x73\x74\x35\x2d\x63\x62\x63"
#define NID_cast5_cbc           108
#define OBJ_cast5_cbc           OBJ_ISO_US,113533L,7L,66L,10L

#define SN_cast5_ecb            "\x43\x41\x53\x54\x35\x2d\x45\x43\x42"
#define LN_cast5_ecb            "\x63\x61\x73\x74\x35\x2d\x65\x63\x62"
#define NID_cast5_ecb           109

#define SN_cast5_cfb64          "\x43\x41\x53\x54\x35\x2d\x43\x46\x42"
#define LN_cast5_cfb64          "\x63\x61\x73\x74\x35\x2d\x63\x66\x62"
#define NID_cast5_cfb64         110

#define SN_cast5_ofb64          "\x43\x41\x53\x54\x35\x2d\x4f\x46\x42"
#define LN_cast5_ofb64          "\x63\x61\x73\x74\x35\x2d\x6f\x66\x62"
#define NID_cast5_ofb64         111

#define LN_pbeWithMD5AndCast5_CBC               "\x70\x62\x65\x57\x69\x74\x68\x4d\x44\x35\x41\x6e\x64\x43\x61\x73\x74\x35\x43\x42\x43"
#define NID_pbeWithMD5AndCast5_CBC              112
#define OBJ_pbeWithMD5AndCast5_CBC              OBJ_ISO_US,113533L,7L,66L,12L

#define SN_id_PasswordBasedMAC          "\x69\x64\x2d\x50\x61\x73\x73\x77\x6f\x72\x64\x42\x61\x73\x65\x64\x4d\x41\x43"
#define LN_id_PasswordBasedMAC          "\x70\x61\x73\x73\x77\x6f\x72\x64\x20\x62\x61\x73\x65\x64\x20\x4d\x41\x43"
#define NID_id_PasswordBasedMAC         782
#define OBJ_id_PasswordBasedMAC         OBJ_ISO_US,113533L,7L,66L,13L

#define SN_id_DHBasedMac                "\x69\x64\x2d\x44\x48\x42\x61\x73\x65\x64\x4d\x61\x63"
#define LN_id_DHBasedMac                "\x44\x69\x66\x66\x69\x65\x2d\x48\x65\x6c\x6c\x6d\x61\x6e\x20\x62\x61\x73\x65\x64\x20\x4d\x41\x43"
#define NID_id_DHBasedMac               783
#define OBJ_id_DHBasedMac               OBJ_ISO_US,113533L,7L,66L,30L

#define SN_rsadsi               "\x72\x73\x61\x64\x73\x69"
#define LN_rsadsi               "\x52\x53\x41\x20\x44\x61\x74\x61\x20\x53\x65\x63\x75\x72\x69\x74\x79\x2c\x20\x49\x6e\x63\x2e"
#define NID_rsadsi              1
#define OBJ_rsadsi              OBJ_ISO_US,113549L

#define SN_pkcs         "\x70\x6b\x63\x73"
#define LN_pkcs         "\x52\x53\x41\x20\x44\x61\x74\x61\x20\x53\x65\x63\x75\x72\x69\x74\x79\x2c\x20\x49\x6e\x63\x2e\x20\x50\x4b\x43\x53"
#define NID_pkcs                2
#define OBJ_pkcs                OBJ_rsadsi,1L

#define SN_pkcs1                "\x70\x6b\x63\x73\x31"
#define NID_pkcs1               186
#define OBJ_pkcs1               OBJ_pkcs,1L

#define LN_rsaEncryption                "\x72\x73\x61\x45\x6e\x63\x72\x79\x70\x74\x69\x6f\x6e"
#define NID_rsaEncryption               6
#define OBJ_rsaEncryption               OBJ_pkcs1,1L

#define SN_md2WithRSAEncryption         "\x52\x53\x41\x2d\x4d\x44\x32"
#define LN_md2WithRSAEncryption         "\x6d\x64\x32\x57\x69\x74\x68\x52\x53\x41\x45\x6e\x63\x72\x79\x70\x74\x69\x6f\x6e"
#define NID_md2WithRSAEncryption                7
#define OBJ_md2WithRSAEncryption                OBJ_pkcs1,2L

#define SN_md4WithRSAEncryption         "\x52\x53\x41\x2d\x4d\x44\x34"
#define LN_md4WithRSAEncryption         "\x6d\x64\x34\x57\x69\x74\x68\x52\x53\x41\x45\x6e\x63\x72\x79\x70\x74\x69\x6f\x6e"
#define NID_md4WithRSAEncryption                396
#define OBJ_md4WithRSAEncryption                OBJ_pkcs1,3L

#define SN_md5WithRSAEncryption         "\x52\x53\x41\x2d\x4d\x44\x35"
#define LN_md5WithRSAEncryption         "\x6d\x64\x35\x57\x69\x74\x68\x52\x53\x41\x45\x6e\x63\x72\x79\x70\x74\x69\x6f\x6e"
#define NID_md5WithRSAEncryption                8
#define OBJ_md5WithRSAEncryption                OBJ_pkcs1,4L

#define SN_sha1WithRSAEncryption                "\x52\x53\x41\x2d\x53\x48\x41\x31"
#define LN_sha1WithRSAEncryption                "\x73\x68\x61\x31\x57\x69\x74\x68\x52\x53\x41\x45\x6e\x63\x72\x79\x70\x74\x69\x6f\x6e"
#define NID_sha1WithRSAEncryption               65
#define OBJ_sha1WithRSAEncryption               OBJ_pkcs1,5L

#define SN_rsaesOaep            "\x52\x53\x41\x45\x53\x2d\x4f\x41\x45\x50"
#define LN_rsaesOaep            "\x72\x73\x61\x65\x73\x4f\x61\x65\x70"
#define NID_rsaesOaep           919
#define OBJ_rsaesOaep           OBJ_pkcs1,7L

#define SN_mgf1         "\x4d\x47\x46\x31"
#define LN_mgf1         "\x6d\x67\x66\x31"
#define NID_mgf1                911
#define OBJ_mgf1                OBJ_pkcs1,8L

#define SN_pSpecified           "\x50\x53\x50\x45\x43\x49\x46\x49\x45\x44"
#define LN_pSpecified           "\x70\x53\x70\x65\x63\x69\x66\x69\x65\x64"
#define NID_pSpecified          935
#define OBJ_pSpecified          OBJ_pkcs1,9L

#define SN_rsassaPss            "\x52\x53\x41\x53\x53\x41\x2d\x50\x53\x53"
#define LN_rsassaPss            "\x72\x73\x61\x73\x73\x61\x50\x73\x73"
#define NID_rsassaPss           912
#define OBJ_rsassaPss           OBJ_pkcs1,10L

#define SN_sha256WithRSAEncryption              "\x52\x53\x41\x2d\x53\x48\x41\x32\x35\x36"
#define LN_sha256WithRSAEncryption              "\x73\x68\x61\x32\x35\x36\x57\x69\x74\x68\x52\x53\x41\x45\x6e\x63\x72\x79\x70\x74\x69\x6f\x6e"
#define NID_sha256WithRSAEncryption             668
#define OBJ_sha256WithRSAEncryption             OBJ_pkcs1,11L

#define SN_sha384WithRSAEncryption              "\x52\x53\x41\x2d\x53\x48\x41\x33\x38\x34"
#define LN_sha384WithRSAEncryption              "\x73\x68\x61\x33\x38\x34\x57\x69\x74\x68\x52\x53\x41\x45\x6e\x63\x72\x79\x70\x74\x69\x6f\x6e"
#define NID_sha384WithRSAEncryption             669
#define OBJ_sha384WithRSAEncryption             OBJ_pkcs1,12L

#define SN_sha512WithRSAEncryption              "\x52\x53\x41\x2d\x53\x48\x41\x35\x31\x32"
#define LN_sha512WithRSAEncryption              "\x73\x68\x61\x35\x31\x32\x57\x69\x74\x68\x52\x53\x41\x45\x6e\x63\x72\x79\x70\x74\x69\x6f\x6e"
#define NID_sha512WithRSAEncryption             670
#define OBJ_sha512WithRSAEncryption             OBJ_pkcs1,13L

#define SN_sha224WithRSAEncryption              "\x52\x53\x41\x2d\x53\x48\x41\x32\x32\x34"
#define LN_sha224WithRSAEncryption              "\x73\x68\x61\x32\x32\x34\x57\x69\x74\x68\x52\x53\x41\x45\x6e\x63\x72\x79\x70\x74\x69\x6f\x6e"
#define NID_sha224WithRSAEncryption             671
#define OBJ_sha224WithRSAEncryption             OBJ_pkcs1,14L

#define SN_pkcs3                "\x70\x6b\x63\x73\x33"
#define NID_pkcs3               27
#define OBJ_pkcs3               OBJ_pkcs,3L

#define LN_dhKeyAgreement               "\x64\x68\x4b\x65\x79\x41\x67\x72\x65\x65\x6d\x65\x6e\x74"
#define NID_dhKeyAgreement              28
#define OBJ_dhKeyAgreement              OBJ_pkcs3,1L

#define SN_pkcs5                "\x70\x6b\x63\x73\x35"
#define NID_pkcs5               187
#define OBJ_pkcs5               OBJ_pkcs,5L

#define SN_pbeWithMD2AndDES_CBC         "\x50\x42\x45\x2d\x4d\x44\x32\x2d\x44\x45\x53"
#define LN_pbeWithMD2AndDES_CBC         "\x70\x62\x65\x57\x69\x74\x68\x4d\x44\x32\x41\x6e\x64\x44\x45\x53\x2d\x43\x42\x43"
#define NID_pbeWithMD2AndDES_CBC                9
#define OBJ_pbeWithMD2AndDES_CBC                OBJ_pkcs5,1L

#define SN_pbeWithMD5AndDES_CBC         "\x50\x42\x45\x2d\x4d\x44\x35\x2d\x44\x45\x53"
#define LN_pbeWithMD5AndDES_CBC         "\x70\x62\x65\x57\x69\x74\x68\x4d\x44\x35\x41\x6e\x64\x44\x45\x53\x2d\x43\x42\x43"
#define NID_pbeWithMD5AndDES_CBC                10
#define OBJ_pbeWithMD5AndDES_CBC                OBJ_pkcs5,3L

#define SN_pbeWithMD2AndRC2_CBC         "\x50\x42\x45\x2d\x4d\x44\x32\x2d\x52\x43\x32\x2d\x36\x34"
#define LN_pbeWithMD2AndRC2_CBC         "\x70\x62\x65\x57\x69\x74\x68\x4d\x44\x32\x41\x6e\x64\x52\x43\x32\x2d\x43\x42\x43"
#define NID_pbeWithMD2AndRC2_CBC                168
#define OBJ_pbeWithMD2AndRC2_CBC                OBJ_pkcs5,4L

#define SN_pbeWithMD5AndRC2_CBC         "\x50\x42\x45\x2d\x4d\x44\x35\x2d\x52\x43\x32\x2d\x36\x34"
#define LN_pbeWithMD5AndRC2_CBC         "\x70\x62\x65\x57\x69\x74\x68\x4d\x44\x35\x41\x6e\x64\x52\x43\x32\x2d\x43\x42\x43"
#define NID_pbeWithMD5AndRC2_CBC                169
#define OBJ_pbeWithMD5AndRC2_CBC                OBJ_pkcs5,6L

#define SN_pbeWithSHA1AndDES_CBC                "\x50\x42\x45\x2d\x53\x48\x41\x31\x2d\x44\x45\x53"
#define LN_pbeWithSHA1AndDES_CBC                "\x70\x62\x65\x57\x69\x74\x68\x53\x48\x41\x31\x41\x6e\x64\x44\x45\x53\x2d\x43\x42\x43"
#define NID_pbeWithSHA1AndDES_CBC               170
#define OBJ_pbeWithSHA1AndDES_CBC               OBJ_pkcs5,10L

#define SN_pbeWithSHA1AndRC2_CBC                "\x50\x42\x45\x2d\x53\x48\x41\x31\x2d\x52\x43\x32\x2d\x36\x34"
#define LN_pbeWithSHA1AndRC2_CBC                "\x70\x62\x65\x57\x69\x74\x68\x53\x48\x41\x31\x41\x6e\x64\x52\x43\x32\x2d\x43\x42\x43"
#define NID_pbeWithSHA1AndRC2_CBC               68
#define OBJ_pbeWithSHA1AndRC2_CBC               OBJ_pkcs5,11L

#define LN_id_pbkdf2            "\x50\x42\x4b\x44\x46\x32"
#define NID_id_pbkdf2           69
#define OBJ_id_pbkdf2           OBJ_pkcs5,12L

#define LN_pbes2                "\x50\x42\x45\x53\x32"
#define NID_pbes2               161
#define OBJ_pbes2               OBJ_pkcs5,13L

#define LN_pbmac1               "\x50\x42\x4d\x41\x43\x31"
#define NID_pbmac1              162
#define OBJ_pbmac1              OBJ_pkcs5,14L

#define SN_pkcs7                "\x70\x6b\x63\x73\x37"
#define NID_pkcs7               20
#define OBJ_pkcs7               OBJ_pkcs,7L

#define LN_pkcs7_data           "\x70\x6b\x63\x73\x37\x2d\x64\x61\x74\x61"
#define NID_pkcs7_data          21
#define OBJ_pkcs7_data          OBJ_pkcs7,1L

#define LN_pkcs7_signed         "\x70\x6b\x63\x73\x37\x2d\x73\x69\x67\x6e\x65\x64\x44\x61\x74\x61"
#define NID_pkcs7_signed                22
#define OBJ_pkcs7_signed                OBJ_pkcs7,2L

#define LN_pkcs7_enveloped              "\x70\x6b\x63\x73\x37\x2d\x65\x6e\x76\x65\x6c\x6f\x70\x65\x64\x44\x61\x74\x61"
#define NID_pkcs7_enveloped             23
#define OBJ_pkcs7_enveloped             OBJ_pkcs7,3L

#define LN_pkcs7_signedAndEnveloped             "\x70\x6b\x63\x73\x37\x2d\x73\x69\x67\x6e\x65\x64\x41\x6e\x64\x45\x6e\x76\x65\x6c\x6f\x70\x65\x64\x44\x61\x74\x61"
#define NID_pkcs7_signedAndEnveloped            24
#define OBJ_pkcs7_signedAndEnveloped            OBJ_pkcs7,4L

#define LN_pkcs7_digest         "\x70\x6b\x63\x73\x37\x2d\x64\x69\x67\x65\x73\x74\x44\x61\x74\x61"
#define NID_pkcs7_digest                25
#define OBJ_pkcs7_digest                OBJ_pkcs7,5L

#define LN_pkcs7_encrypted              "\x70\x6b\x63\x73\x37\x2d\x65\x6e\x63\x72\x79\x70\x74\x65\x64\x44\x61\x74\x61"
#define NID_pkcs7_encrypted             26
#define OBJ_pkcs7_encrypted             OBJ_pkcs7,6L

#define SN_pkcs9                "\x70\x6b\x63\x73\x39"
#define NID_pkcs9               47
#define OBJ_pkcs9               OBJ_pkcs,9L

#define LN_pkcs9_emailAddress           "\x65\x6d\x61\x69\x6c\x41\x64\x64\x72\x65\x73\x73"
#define NID_pkcs9_emailAddress          48
#define OBJ_pkcs9_emailAddress          OBJ_pkcs9,1L

#define LN_pkcs9_unstructuredName               "\x75\x6e\x73\x74\x72\x75\x63\x74\x75\x72\x65\x64\x4e\x61\x6d\x65"
#define NID_pkcs9_unstructuredName              49
#define OBJ_pkcs9_unstructuredName              OBJ_pkcs9,2L

#define LN_pkcs9_contentType            "\x63\x6f\x6e\x74\x65\x6e\x74\x54\x79\x70\x65"
#define NID_pkcs9_contentType           50
#define OBJ_pkcs9_contentType           OBJ_pkcs9,3L

#define LN_pkcs9_messageDigest          "\x6d\x65\x73\x73\x61\x67\x65\x44\x69\x67\x65\x73\x74"
#define NID_pkcs9_messageDigest         51
#define OBJ_pkcs9_messageDigest         OBJ_pkcs9,4L

#define LN_pkcs9_signingTime            "\x73\x69\x67\x6e\x69\x6e\x67\x54\x69\x6d\x65"
#define NID_pkcs9_signingTime           52
#define OBJ_pkcs9_signingTime           OBJ_pkcs9,5L

#define LN_pkcs9_countersignature               "\x63\x6f\x75\x6e\x74\x65\x72\x73\x69\x67\x6e\x61\x74\x75\x72\x65"
#define NID_pkcs9_countersignature              53
#define OBJ_pkcs9_countersignature              OBJ_pkcs9,6L

#define LN_pkcs9_challengePassword              "\x63\x68\x61\x6c\x6c\x65\x6e\x67\x65\x50\x61\x73\x73\x77\x6f\x72\x64"
#define NID_pkcs9_challengePassword             54
#define OBJ_pkcs9_challengePassword             OBJ_pkcs9,7L

#define LN_pkcs9_unstructuredAddress            "\x75\x6e\x73\x74\x72\x75\x63\x74\x75\x72\x65\x64\x41\x64\x64\x72\x65\x73\x73"
#define NID_pkcs9_unstructuredAddress           55
#define OBJ_pkcs9_unstructuredAddress           OBJ_pkcs9,8L

#define LN_pkcs9_extCertAttributes              "\x65\x78\x74\x65\x6e\x64\x65\x64\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x41\x74\x74\x72\x69\x62\x75\x74\x65\x73"
#define NID_pkcs9_extCertAttributes             56
#define OBJ_pkcs9_extCertAttributes             OBJ_pkcs9,9L

#define SN_ext_req              "\x65\x78\x74\x52\x65\x71"
#define LN_ext_req              "\x45\x78\x74\x65\x6e\x73\x69\x6f\x6e\x20\x52\x65\x71\x75\x65\x73\x74"
#define NID_ext_req             172
#define OBJ_ext_req             OBJ_pkcs9,14L

#define SN_SMIMECapabilities            "\x53\x4d\x49\x4d\x45\x2d\x43\x41\x50\x53"
#define LN_SMIMECapabilities            "\x53\x2f\x4d\x49\x4d\x45\x20\x43\x61\x70\x61\x62\x69\x6c\x69\x74\x69\x65\x73"
#define NID_SMIMECapabilities           167
#define OBJ_SMIMECapabilities           OBJ_pkcs9,15L

#define SN_SMIME                "\x53\x4d\x49\x4d\x45"
#define LN_SMIME                "\x53\x2f\x4d\x49\x4d\x45"
#define NID_SMIME               188
#define OBJ_SMIME               OBJ_pkcs9,16L

#define SN_id_smime_mod         "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x6d\x6f\x64"
#define NID_id_smime_mod                189
#define OBJ_id_smime_mod                OBJ_SMIME,0L

#define SN_id_smime_ct          "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x63\x74"
#define NID_id_smime_ct         190
#define OBJ_id_smime_ct         OBJ_SMIME,1L

#define SN_id_smime_aa          "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x61"
#define NID_id_smime_aa         191
#define OBJ_id_smime_aa         OBJ_SMIME,2L

#define SN_id_smime_alg         "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x6c\x67"
#define NID_id_smime_alg                192
#define OBJ_id_smime_alg                OBJ_SMIME,3L

#define SN_id_smime_cd          "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x63\x64"
#define NID_id_smime_cd         193
#define OBJ_id_smime_cd         OBJ_SMIME,4L

#define SN_id_smime_spq         "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x73\x70\x71"
#define NID_id_smime_spq                194
#define OBJ_id_smime_spq                OBJ_SMIME,5L

#define SN_id_smime_cti         "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x63\x74\x69"
#define NID_id_smime_cti                195
#define OBJ_id_smime_cti                OBJ_SMIME,6L

#define SN_id_smime_mod_cms             "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x6d\x6f\x64\x2d\x63\x6d\x73"
#define NID_id_smime_mod_cms            196
#define OBJ_id_smime_mod_cms            OBJ_id_smime_mod,1L

#define SN_id_smime_mod_ess             "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x6d\x6f\x64\x2d\x65\x73\x73"
#define NID_id_smime_mod_ess            197
#define OBJ_id_smime_mod_ess            OBJ_id_smime_mod,2L

#define SN_id_smime_mod_oid             "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x6d\x6f\x64\x2d\x6f\x69\x64"
#define NID_id_smime_mod_oid            198
#define OBJ_id_smime_mod_oid            OBJ_id_smime_mod,3L

#define SN_id_smime_mod_msg_v3          "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x6d\x6f\x64\x2d\x6d\x73\x67\x2d\x76\x33"
#define NID_id_smime_mod_msg_v3         199
#define OBJ_id_smime_mod_msg_v3         OBJ_id_smime_mod,4L

#define SN_id_smime_mod_ets_eSignature_88               "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x6d\x6f\x64\x2d\x65\x74\x73\x2d\x65\x53\x69\x67\x6e\x61\x74\x75\x72\x65\x2d\x38\x38"
#define NID_id_smime_mod_ets_eSignature_88              200
#define OBJ_id_smime_mod_ets_eSignature_88              OBJ_id_smime_mod,5L

#define SN_id_smime_mod_ets_eSignature_97               "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x6d\x6f\x64\x2d\x65\x74\x73\x2d\x65\x53\x69\x67\x6e\x61\x74\x75\x72\x65\x2d\x39\x37"
#define NID_id_smime_mod_ets_eSignature_97              201
#define OBJ_id_smime_mod_ets_eSignature_97              OBJ_id_smime_mod,6L

#define SN_id_smime_mod_ets_eSigPolicy_88               "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x6d\x6f\x64\x2d\x65\x74\x73\x2d\x65\x53\x69\x67\x50\x6f\x6c\x69\x63\x79\x2d\x38\x38"
#define NID_id_smime_mod_ets_eSigPolicy_88              202
#define OBJ_id_smime_mod_ets_eSigPolicy_88              OBJ_id_smime_mod,7L

#define SN_id_smime_mod_ets_eSigPolicy_97               "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x6d\x6f\x64\x2d\x65\x74\x73\x2d\x65\x53\x69\x67\x50\x6f\x6c\x69\x63\x79\x2d\x39\x37"
#define NID_id_smime_mod_ets_eSigPolicy_97              203
#define OBJ_id_smime_mod_ets_eSigPolicy_97              OBJ_id_smime_mod,8L

#define SN_id_smime_ct_receipt          "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x63\x74\x2d\x72\x65\x63\x65\x69\x70\x74"
#define NID_id_smime_ct_receipt         204
#define OBJ_id_smime_ct_receipt         OBJ_id_smime_ct,1L

#define SN_id_smime_ct_authData         "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x63\x74\x2d\x61\x75\x74\x68\x44\x61\x74\x61"
#define NID_id_smime_ct_authData                205
#define OBJ_id_smime_ct_authData                OBJ_id_smime_ct,2L

#define SN_id_smime_ct_publishCert              "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x63\x74\x2d\x70\x75\x62\x6c\x69\x73\x68\x43\x65\x72\x74"
#define NID_id_smime_ct_publishCert             206
#define OBJ_id_smime_ct_publishCert             OBJ_id_smime_ct,3L

#define SN_id_smime_ct_TSTInfo          "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x63\x74\x2d\x54\x53\x54\x49\x6e\x66\x6f"
#define NID_id_smime_ct_TSTInfo         207
#define OBJ_id_smime_ct_TSTInfo         OBJ_id_smime_ct,4L

#define SN_id_smime_ct_TDTInfo          "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x63\x74\x2d\x54\x44\x54\x49\x6e\x66\x6f"
#define NID_id_smime_ct_TDTInfo         208
#define OBJ_id_smime_ct_TDTInfo         OBJ_id_smime_ct,5L

#define SN_id_smime_ct_contentInfo              "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x63\x74\x2d\x63\x6f\x6e\x74\x65\x6e\x74\x49\x6e\x66\x6f"
#define NID_id_smime_ct_contentInfo             209
#define OBJ_id_smime_ct_contentInfo             OBJ_id_smime_ct,6L

#define SN_id_smime_ct_DVCSRequestData          "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x63\x74\x2d\x44\x56\x43\x53\x52\x65\x71\x75\x65\x73\x74\x44\x61\x74\x61"
#define NID_id_smime_ct_DVCSRequestData         210
#define OBJ_id_smime_ct_DVCSRequestData         OBJ_id_smime_ct,7L

#define SN_id_smime_ct_DVCSResponseData         "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x63\x74\x2d\x44\x56\x43\x53\x52\x65\x73\x70\x6f\x6e\x73\x65\x44\x61\x74\x61"
#define NID_id_smime_ct_DVCSResponseData                211
#define OBJ_id_smime_ct_DVCSResponseData                OBJ_id_smime_ct,8L

#define SN_id_smime_ct_compressedData           "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x63\x74\x2d\x63\x6f\x6d\x70\x72\x65\x73\x73\x65\x64\x44\x61\x74\x61"
#define NID_id_smime_ct_compressedData          786
#define OBJ_id_smime_ct_compressedData          OBJ_id_smime_ct,9L

#define SN_id_ct_asciiTextWithCRLF              "\x69\x64\x2d\x63\x74\x2d\x61\x73\x63\x69\x69\x54\x65\x78\x74\x57\x69\x74\x68\x43\x52\x4c\x46"
#define NID_id_ct_asciiTextWithCRLF             787
#define OBJ_id_ct_asciiTextWithCRLF             OBJ_id_smime_ct,27L

#define SN_id_smime_aa_receiptRequest           "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x61\x2d\x72\x65\x63\x65\x69\x70\x74\x52\x65\x71\x75\x65\x73\x74"
#define NID_id_smime_aa_receiptRequest          212
#define OBJ_id_smime_aa_receiptRequest          OBJ_id_smime_aa,1L

#define SN_id_smime_aa_securityLabel            "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x61\x2d\x73\x65\x63\x75\x72\x69\x74\x79\x4c\x61\x62\x65\x6c"
#define NID_id_smime_aa_securityLabel           213
#define OBJ_id_smime_aa_securityLabel           OBJ_id_smime_aa,2L

#define SN_id_smime_aa_mlExpandHistory          "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x61\x2d\x6d\x6c\x45\x78\x70\x61\x6e\x64\x48\x69\x73\x74\x6f\x72\x79"
#define NID_id_smime_aa_mlExpandHistory         214
#define OBJ_id_smime_aa_mlExpandHistory         OBJ_id_smime_aa,3L

#define SN_id_smime_aa_contentHint              "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x61\x2d\x63\x6f\x6e\x74\x65\x6e\x74\x48\x69\x6e\x74"
#define NID_id_smime_aa_contentHint             215
#define OBJ_id_smime_aa_contentHint             OBJ_id_smime_aa,4L

#define SN_id_smime_aa_msgSigDigest             "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x61\x2d\x6d\x73\x67\x53\x69\x67\x44\x69\x67\x65\x73\x74"
#define NID_id_smime_aa_msgSigDigest            216
#define OBJ_id_smime_aa_msgSigDigest            OBJ_id_smime_aa,5L

#define SN_id_smime_aa_encapContentType         "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x61\x2d\x65\x6e\x63\x61\x70\x43\x6f\x6e\x74\x65\x6e\x74\x54\x79\x70\x65"
#define NID_id_smime_aa_encapContentType                217
#define OBJ_id_smime_aa_encapContentType                OBJ_id_smime_aa,6L

#define SN_id_smime_aa_contentIdentifier                "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x61\x2d\x63\x6f\x6e\x74\x65\x6e\x74\x49\x64\x65\x6e\x74\x69\x66\x69\x65\x72"
#define NID_id_smime_aa_contentIdentifier               218
#define OBJ_id_smime_aa_contentIdentifier               OBJ_id_smime_aa,7L

#define SN_id_smime_aa_macValue         "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x61\x2d\x6d\x61\x63\x56\x61\x6c\x75\x65"
#define NID_id_smime_aa_macValue                219
#define OBJ_id_smime_aa_macValue                OBJ_id_smime_aa,8L

#define SN_id_smime_aa_equivalentLabels         "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x61\x2d\x65\x71\x75\x69\x76\x61\x6c\x65\x6e\x74\x4c\x61\x62\x65\x6c\x73"
#define NID_id_smime_aa_equivalentLabels                220
#define OBJ_id_smime_aa_equivalentLabels                OBJ_id_smime_aa,9L

#define SN_id_smime_aa_contentReference         "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x61\x2d\x63\x6f\x6e\x74\x65\x6e\x74\x52\x65\x66\x65\x72\x65\x6e\x63\x65"
#define NID_id_smime_aa_contentReference                221
#define OBJ_id_smime_aa_contentReference                OBJ_id_smime_aa,10L

#define SN_id_smime_aa_encrypKeyPref            "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x61\x2d\x65\x6e\x63\x72\x79\x70\x4b\x65\x79\x50\x72\x65\x66"
#define NID_id_smime_aa_encrypKeyPref           222
#define OBJ_id_smime_aa_encrypKeyPref           OBJ_id_smime_aa,11L

#define SN_id_smime_aa_signingCertificate               "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x61\x2d\x73\x69\x67\x6e\x69\x6e\x67\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65"
#define NID_id_smime_aa_signingCertificate              223
#define OBJ_id_smime_aa_signingCertificate              OBJ_id_smime_aa,12L

#define SN_id_smime_aa_smimeEncryptCerts                "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x61\x2d\x73\x6d\x69\x6d\x65\x45\x6e\x63\x72\x79\x70\x74\x43\x65\x72\x74\x73"
#define NID_id_smime_aa_smimeEncryptCerts               224
#define OBJ_id_smime_aa_smimeEncryptCerts               OBJ_id_smime_aa,13L

#define SN_id_smime_aa_timeStampToken           "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x61\x2d\x74\x69\x6d\x65\x53\x74\x61\x6d\x70\x54\x6f\x6b\x65\x6e"
#define NID_id_smime_aa_timeStampToken          225
#define OBJ_id_smime_aa_timeStampToken          OBJ_id_smime_aa,14L

#define SN_id_smime_aa_ets_sigPolicyId          "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x61\x2d\x65\x74\x73\x2d\x73\x69\x67\x50\x6f\x6c\x69\x63\x79\x49\x64"
#define NID_id_smime_aa_ets_sigPolicyId         226
#define OBJ_id_smime_aa_ets_sigPolicyId         OBJ_id_smime_aa,15L

#define SN_id_smime_aa_ets_commitmentType               "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x61\x2d\x65\x74\x73\x2d\x63\x6f\x6d\x6d\x69\x74\x6d\x65\x6e\x74\x54\x79\x70\x65"
#define NID_id_smime_aa_ets_commitmentType              227
#define OBJ_id_smime_aa_ets_commitmentType              OBJ_id_smime_aa,16L

#define SN_id_smime_aa_ets_signerLocation               "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x61\x2d\x65\x74\x73\x2d\x73\x69\x67\x6e\x65\x72\x4c\x6f\x63\x61\x74\x69\x6f\x6e"
#define NID_id_smime_aa_ets_signerLocation              228
#define OBJ_id_smime_aa_ets_signerLocation              OBJ_id_smime_aa,17L

#define SN_id_smime_aa_ets_signerAttr           "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x61\x2d\x65\x74\x73\x2d\x73\x69\x67\x6e\x65\x72\x41\x74\x74\x72"
#define NID_id_smime_aa_ets_signerAttr          229
#define OBJ_id_smime_aa_ets_signerAttr          OBJ_id_smime_aa,18L

#define SN_id_smime_aa_ets_otherSigCert         "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x61\x2d\x65\x74\x73\x2d\x6f\x74\x68\x65\x72\x53\x69\x67\x43\x65\x72\x74"
#define NID_id_smime_aa_ets_otherSigCert                230
#define OBJ_id_smime_aa_ets_otherSigCert                OBJ_id_smime_aa,19L

#define SN_id_smime_aa_ets_contentTimestamp             "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x61\x2d\x65\x74\x73\x2d\x63\x6f\x6e\x74\x65\x6e\x74\x54\x69\x6d\x65\x73\x74\x61\x6d\x70"
#define NID_id_smime_aa_ets_contentTimestamp            231
#define OBJ_id_smime_aa_ets_contentTimestamp            OBJ_id_smime_aa,20L

#define SN_id_smime_aa_ets_CertificateRefs              "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x61\x2d\x65\x74\x73\x2d\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x52\x65\x66\x73"
#define NID_id_smime_aa_ets_CertificateRefs             232
#define OBJ_id_smime_aa_ets_CertificateRefs             OBJ_id_smime_aa,21L

#define SN_id_smime_aa_ets_RevocationRefs               "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x61\x2d\x65\x74\x73\x2d\x52\x65\x76\x6f\x63\x61\x74\x69\x6f\x6e\x52\x65\x66\x73"
#define NID_id_smime_aa_ets_RevocationRefs              233
#define OBJ_id_smime_aa_ets_RevocationRefs              OBJ_id_smime_aa,22L

#define SN_id_smime_aa_ets_certValues           "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x61\x2d\x65\x74\x73\x2d\x63\x65\x72\x74\x56\x61\x6c\x75\x65\x73"
#define NID_id_smime_aa_ets_certValues          234
#define OBJ_id_smime_aa_ets_certValues          OBJ_id_smime_aa,23L

#define SN_id_smime_aa_ets_revocationValues             "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x61\x2d\x65\x74\x73\x2d\x72\x65\x76\x6f\x63\x61\x74\x69\x6f\x6e\x56\x61\x6c\x75\x65\x73"
#define NID_id_smime_aa_ets_revocationValues            235
#define OBJ_id_smime_aa_ets_revocationValues            OBJ_id_smime_aa,24L

#define SN_id_smime_aa_ets_escTimeStamp         "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x61\x2d\x65\x74\x73\x2d\x65\x73\x63\x54\x69\x6d\x65\x53\x74\x61\x6d\x70"
#define NID_id_smime_aa_ets_escTimeStamp                236
#define OBJ_id_smime_aa_ets_escTimeStamp                OBJ_id_smime_aa,25L

#define SN_id_smime_aa_ets_certCRLTimestamp             "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x61\x2d\x65\x74\x73\x2d\x63\x65\x72\x74\x43\x52\x4c\x54\x69\x6d\x65\x73\x74\x61\x6d\x70"
#define NID_id_smime_aa_ets_certCRLTimestamp            237
#define OBJ_id_smime_aa_ets_certCRLTimestamp            OBJ_id_smime_aa,26L

#define SN_id_smime_aa_ets_archiveTimeStamp             "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x61\x2d\x65\x74\x73\x2d\x61\x72\x63\x68\x69\x76\x65\x54\x69\x6d\x65\x53\x74\x61\x6d\x70"
#define NID_id_smime_aa_ets_archiveTimeStamp            238
#define OBJ_id_smime_aa_ets_archiveTimeStamp            OBJ_id_smime_aa,27L

#define SN_id_smime_aa_signatureType            "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x61\x2d\x73\x69\x67\x6e\x61\x74\x75\x72\x65\x54\x79\x70\x65"
#define NID_id_smime_aa_signatureType           239
#define OBJ_id_smime_aa_signatureType           OBJ_id_smime_aa,28L

#define SN_id_smime_aa_dvcs_dvc         "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x61\x2d\x64\x76\x63\x73\x2d\x64\x76\x63"
#define NID_id_smime_aa_dvcs_dvc                240
#define OBJ_id_smime_aa_dvcs_dvc                OBJ_id_smime_aa,29L

#define SN_id_smime_alg_ESDHwith3DES            "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x6c\x67\x2d\x45\x53\x44\x48\x77\x69\x74\x68\x33\x44\x45\x53"
#define NID_id_smime_alg_ESDHwith3DES           241
#define OBJ_id_smime_alg_ESDHwith3DES           OBJ_id_smime_alg,1L

#define SN_id_smime_alg_ESDHwithRC2             "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x6c\x67\x2d\x45\x53\x44\x48\x77\x69\x74\x68\x52\x43\x32"
#define NID_id_smime_alg_ESDHwithRC2            242
#define OBJ_id_smime_alg_ESDHwithRC2            OBJ_id_smime_alg,2L

#define SN_id_smime_alg_3DESwrap                "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x6c\x67\x2d\x33\x44\x45\x53\x77\x72\x61\x70"
#define NID_id_smime_alg_3DESwrap               243
#define OBJ_id_smime_alg_3DESwrap               OBJ_id_smime_alg,3L

#define SN_id_smime_alg_RC2wrap         "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x6c\x67\x2d\x52\x43\x32\x77\x72\x61\x70"
#define NID_id_smime_alg_RC2wrap                244
#define OBJ_id_smime_alg_RC2wrap                OBJ_id_smime_alg,4L

#define SN_id_smime_alg_ESDH            "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x6c\x67\x2d\x45\x53\x44\x48"
#define NID_id_smime_alg_ESDH           245
#define OBJ_id_smime_alg_ESDH           OBJ_id_smime_alg,5L

#define SN_id_smime_alg_CMS3DESwrap             "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x6c\x67\x2d\x43\x4d\x53\x33\x44\x45\x53\x77\x72\x61\x70"
#define NID_id_smime_alg_CMS3DESwrap            246
#define OBJ_id_smime_alg_CMS3DESwrap            OBJ_id_smime_alg,6L

#define SN_id_smime_alg_CMSRC2wrap              "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x61\x6c\x67\x2d\x43\x4d\x53\x52\x43\x32\x77\x72\x61\x70"
#define NID_id_smime_alg_CMSRC2wrap             247
#define OBJ_id_smime_alg_CMSRC2wrap             OBJ_id_smime_alg,7L

#define SN_id_alg_PWRI_KEK              "\x69\x64\x2d\x61\x6c\x67\x2d\x50\x57\x52\x49\x2d\x4b\x45\x4b"
#define NID_id_alg_PWRI_KEK             893
#define OBJ_id_alg_PWRI_KEK             OBJ_id_smime_alg,9L

#define SN_id_smime_cd_ldap             "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x63\x64\x2d\x6c\x64\x61\x70"
#define NID_id_smime_cd_ldap            248
#define OBJ_id_smime_cd_ldap            OBJ_id_smime_cd,1L

#define SN_id_smime_spq_ets_sqt_uri             "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x73\x70\x71\x2d\x65\x74\x73\x2d\x73\x71\x74\x2d\x75\x72\x69"
#define NID_id_smime_spq_ets_sqt_uri            249
#define OBJ_id_smime_spq_ets_sqt_uri            OBJ_id_smime_spq,1L

#define SN_id_smime_spq_ets_sqt_unotice         "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x73\x70\x71\x2d\x65\x74\x73\x2d\x73\x71\x74\x2d\x75\x6e\x6f\x74\x69\x63\x65"
#define NID_id_smime_spq_ets_sqt_unotice                250
#define OBJ_id_smime_spq_ets_sqt_unotice                OBJ_id_smime_spq,2L

#define SN_id_smime_cti_ets_proofOfOrigin               "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x63\x74\x69\x2d\x65\x74\x73\x2d\x70\x72\x6f\x6f\x66\x4f\x66\x4f\x72\x69\x67\x69\x6e"
#define NID_id_smime_cti_ets_proofOfOrigin              251
#define OBJ_id_smime_cti_ets_proofOfOrigin              OBJ_id_smime_cti,1L

#define SN_id_smime_cti_ets_proofOfReceipt              "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x63\x74\x69\x2d\x65\x74\x73\x2d\x70\x72\x6f\x6f\x66\x4f\x66\x52\x65\x63\x65\x69\x70\x74"
#define NID_id_smime_cti_ets_proofOfReceipt             252
#define OBJ_id_smime_cti_ets_proofOfReceipt             OBJ_id_smime_cti,2L

#define SN_id_smime_cti_ets_proofOfDelivery             "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x63\x74\x69\x2d\x65\x74\x73\x2d\x70\x72\x6f\x6f\x66\x4f\x66\x44\x65\x6c\x69\x76\x65\x72\x79"
#define NID_id_smime_cti_ets_proofOfDelivery            253
#define OBJ_id_smime_cti_ets_proofOfDelivery            OBJ_id_smime_cti,3L

#define SN_id_smime_cti_ets_proofOfSender               "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x63\x74\x69\x2d\x65\x74\x73\x2d\x70\x72\x6f\x6f\x66\x4f\x66\x53\x65\x6e\x64\x65\x72"
#define NID_id_smime_cti_ets_proofOfSender              254
#define OBJ_id_smime_cti_ets_proofOfSender              OBJ_id_smime_cti,4L

#define SN_id_smime_cti_ets_proofOfApproval             "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x63\x74\x69\x2d\x65\x74\x73\x2d\x70\x72\x6f\x6f\x66\x4f\x66\x41\x70\x70\x72\x6f\x76\x61\x6c"
#define NID_id_smime_cti_ets_proofOfApproval            255
#define OBJ_id_smime_cti_ets_proofOfApproval            OBJ_id_smime_cti,5L

#define SN_id_smime_cti_ets_proofOfCreation             "\x69\x64\x2d\x73\x6d\x69\x6d\x65\x2d\x63\x74\x69\x2d\x65\x74\x73\x2d\x70\x72\x6f\x6f\x66\x4f\x66\x43\x72\x65\x61\x74\x69\x6f\x6e"
#define NID_id_smime_cti_ets_proofOfCreation            256
#define OBJ_id_smime_cti_ets_proofOfCreation            OBJ_id_smime_cti,6L

#define LN_friendlyName         "\x66\x72\x69\x65\x6e\x64\x6c\x79\x4e\x61\x6d\x65"
#define NID_friendlyName                156
#define OBJ_friendlyName                OBJ_pkcs9,20L

#define LN_localKeyID           "\x6c\x6f\x63\x61\x6c\x4b\x65\x79\x49\x44"
#define NID_localKeyID          157
#define OBJ_localKeyID          OBJ_pkcs9,21L

#define SN_ms_csp_name          "\x43\x53\x50\x4e\x61\x6d\x65"
#define LN_ms_csp_name          "\x4d\x69\x63\x72\x6f\x73\x6f\x66\x74\x20\x43\x53\x50\x20\x4e\x61\x6d\x65"
#define NID_ms_csp_name         417
#define OBJ_ms_csp_name         1L,3L,6L,1L,4L,1L,311L,17L,1L

#define SN_LocalKeySet          "\x4c\x6f\x63\x61\x6c\x4b\x65\x79\x53\x65\x74"
#define LN_LocalKeySet          "\x4d\x69\x63\x72\x6f\x73\x6f\x66\x74\x20\x4c\x6f\x63\x61\x6c\x20\x4b\x65\x79\x20\x73\x65\x74"
#define NID_LocalKeySet         856
#define OBJ_LocalKeySet         1L,3L,6L,1L,4L,1L,311L,17L,2L

#define OBJ_certTypes           OBJ_pkcs9,22L

#define LN_x509Certificate              "\x78\x35\x30\x39\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65"
#define NID_x509Certificate             158
#define OBJ_x509Certificate             OBJ_certTypes,1L

#define LN_sdsiCertificate              "\x73\x64\x73\x69\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65"
#define NID_sdsiCertificate             159
#define OBJ_sdsiCertificate             OBJ_certTypes,2L

#define OBJ_crlTypes            OBJ_pkcs9,23L

#define LN_x509Crl              "\x78\x35\x30\x39\x43\x72\x6c"
#define NID_x509Crl             160
#define OBJ_x509Crl             OBJ_crlTypes,1L

#define OBJ_pkcs12              OBJ_pkcs,12L

#define OBJ_pkcs12_pbeids               OBJ_pkcs12,1L

#define SN_pbe_WithSHA1And128BitRC4             "\x50\x42\x45\x2d\x53\x48\x41\x31\x2d\x52\x43\x34\x2d\x31\x32\x38"
#define LN_pbe_WithSHA1And128BitRC4             "\x70\x62\x65\x57\x69\x74\x68\x53\x48\x41\x31\x41\x6e\x64\x31\x32\x38\x42\x69\x74\x52\x43\x34"
#define NID_pbe_WithSHA1And128BitRC4            144
#define OBJ_pbe_WithSHA1And128BitRC4            OBJ_pkcs12_pbeids,1L

#define SN_pbe_WithSHA1And40BitRC4              "\x50\x42\x45\x2d\x53\x48\x41\x31\x2d\x52\x43\x34\x2d\x34\x30"
#define LN_pbe_WithSHA1And40BitRC4              "\x70\x62\x65\x57\x69\x74\x68\x53\x48\x41\x31\x41\x6e\x64\x34\x30\x42\x69\x74\x52\x43\x34"
#define NID_pbe_WithSHA1And40BitRC4             145
#define OBJ_pbe_WithSHA1And40BitRC4             OBJ_pkcs12_pbeids,2L

#define SN_pbe_WithSHA1And3_Key_TripleDES_CBC           "\x50\x42\x45\x2d\x53\x48\x41\x31\x2d\x33\x44\x45\x53"
#define LN_pbe_WithSHA1And3_Key_TripleDES_CBC           "\x70\x62\x65\x57\x69\x74\x68\x53\x48\x41\x31\x41\x6e\x64\x33\x2d\x4b\x65\x79\x54\x72\x69\x70\x6c\x65\x44\x45\x53\x2d\x43\x42\x43"
#define NID_pbe_WithSHA1And3_Key_TripleDES_CBC          146
#define OBJ_pbe_WithSHA1And3_Key_TripleDES_CBC          OBJ_pkcs12_pbeids,3L

#define SN_pbe_WithSHA1And2_Key_TripleDES_CBC           "\x50\x42\x45\x2d\x53\x48\x41\x31\x2d\x32\x44\x45\x53"
#define LN_pbe_WithSHA1And2_Key_TripleDES_CBC           "\x70\x62\x65\x57\x69\x74\x68\x53\x48\x41\x31\x41\x6e\x64\x32\x2d\x4b\x65\x79\x54\x72\x69\x70\x6c\x65\x44\x45\x53\x2d\x43\x42\x43"
#define NID_pbe_WithSHA1And2_Key_TripleDES_CBC          147
#define OBJ_pbe_WithSHA1And2_Key_TripleDES_CBC          OBJ_pkcs12_pbeids,4L

#define SN_pbe_WithSHA1And128BitRC2_CBC         "\x50\x42\x45\x2d\x53\x48\x41\x31\x2d\x52\x43\x32\x2d\x31\x32\x38"
#define LN_pbe_WithSHA1And128BitRC2_CBC         "\x70\x62\x65\x57\x69\x74\x68\x53\x48\x41\x31\x41\x6e\x64\x31\x32\x38\x42\x69\x74\x52\x43\x32\x2d\x43\x42\x43"
#define NID_pbe_WithSHA1And128BitRC2_CBC                148
#define OBJ_pbe_WithSHA1And128BitRC2_CBC                OBJ_pkcs12_pbeids,5L

#define SN_pbe_WithSHA1And40BitRC2_CBC          "\x50\x42\x45\x2d\x53\x48\x41\x31\x2d\x52\x43\x32\x2d\x34\x30"
#define LN_pbe_WithSHA1And40BitRC2_CBC          "\x70\x62\x65\x57\x69\x74\x68\x53\x48\x41\x31\x41\x6e\x64\x34\x30\x42\x69\x74\x52\x43\x32\x2d\x43\x42\x43"
#define NID_pbe_WithSHA1And40BitRC2_CBC         149
#define OBJ_pbe_WithSHA1And40BitRC2_CBC         OBJ_pkcs12_pbeids,6L

#define OBJ_pkcs12_Version1             OBJ_pkcs12,10L

#define OBJ_pkcs12_BagIds               OBJ_pkcs12_Version1,1L

#define LN_keyBag               "\x6b\x65\x79\x42\x61\x67"
#define NID_keyBag              150
#define OBJ_keyBag              OBJ_pkcs12_BagIds,1L

#define LN_pkcs8ShroudedKeyBag          "\x70\x6b\x63\x73\x38\x53\x68\x72\x6f\x75\x64\x65\x64\x4b\x65\x79\x42\x61\x67"
#define NID_pkcs8ShroudedKeyBag         151
#define OBJ_pkcs8ShroudedKeyBag         OBJ_pkcs12_BagIds,2L

#define LN_certBag              "\x63\x65\x72\x74\x42\x61\x67"
#define NID_certBag             152
#define OBJ_certBag             OBJ_pkcs12_BagIds,3L

#define LN_crlBag               "\x63\x72\x6c\x42\x61\x67"
#define NID_crlBag              153
#define OBJ_crlBag              OBJ_pkcs12_BagIds,4L

#define LN_secretBag            "\x73\x65\x63\x72\x65\x74\x42\x61\x67"
#define NID_secretBag           154
#define OBJ_secretBag           OBJ_pkcs12_BagIds,5L

#define LN_safeContentsBag              "\x73\x61\x66\x65\x43\x6f\x6e\x74\x65\x6e\x74\x73\x42\x61\x67"
#define NID_safeContentsBag             155
#define OBJ_safeContentsBag             OBJ_pkcs12_BagIds,6L

#define SN_md2          "\x4d\x44\x32"
#define LN_md2          "\x6d\x64\x32"
#define NID_md2         3
#define OBJ_md2         OBJ_rsadsi,2L,2L

#define SN_md4          "\x4d\x44\x34"
#define LN_md4          "\x6d\x64\x34"
#define NID_md4         257
#define OBJ_md4         OBJ_rsadsi,2L,4L

#define SN_md5          "\x4d\x44\x35"
#define LN_md5          "\x6d\x64\x35"
#define NID_md5         4
#define OBJ_md5         OBJ_rsadsi,2L,5L

#define SN_md5_sha1             "\x4d\x44\x35\x2d\x53\x48\x41\x31"
#define LN_md5_sha1             "\x6d\x64\x35\x2d\x73\x68\x61\x31"
#define NID_md5_sha1            114

#define LN_hmacWithMD5          "\x68\x6d\x61\x63\x57\x69\x74\x68\x4d\x44\x35"
#define NID_hmacWithMD5         797
#define OBJ_hmacWithMD5         OBJ_rsadsi,2L,6L

#define LN_hmacWithSHA1         "\x68\x6d\x61\x63\x57\x69\x74\x68\x53\x48\x41\x31"
#define NID_hmacWithSHA1                163
#define OBJ_hmacWithSHA1                OBJ_rsadsi,2L,7L

#define LN_hmacWithSHA224               "\x68\x6d\x61\x63\x57\x69\x74\x68\x53\x48\x41\x32\x32\x34"
#define NID_hmacWithSHA224              798
#define OBJ_hmacWithSHA224              OBJ_rsadsi,2L,8L

#define LN_hmacWithSHA256               "\x68\x6d\x61\x63\x57\x69\x74\x68\x53\x48\x41\x32\x35\x36"
#define NID_hmacWithSHA256              799
#define OBJ_hmacWithSHA256              OBJ_rsadsi,2L,9L

#define LN_hmacWithSHA384               "\x68\x6d\x61\x63\x57\x69\x74\x68\x53\x48\x41\x33\x38\x34"
#define NID_hmacWithSHA384              800
#define OBJ_hmacWithSHA384              OBJ_rsadsi,2L,10L

#define LN_hmacWithSHA512               "\x68\x6d\x61\x63\x57\x69\x74\x68\x53\x48\x41\x35\x31\x32"
#define NID_hmacWithSHA512              801
#define OBJ_hmacWithSHA512              OBJ_rsadsi,2L,11L

#define SN_rc2_cbc              "\x52\x43\x32\x2d\x43\x42\x43"
#define LN_rc2_cbc              "\x72\x63\x32\x2d\x63\x62\x63"
#define NID_rc2_cbc             37
#define OBJ_rc2_cbc             OBJ_rsadsi,3L,2L

#define SN_rc2_ecb              "\x52\x43\x32\x2d\x45\x43\x42"
#define LN_rc2_ecb              "\x72\x63\x32\x2d\x65\x63\x62"
#define NID_rc2_ecb             38

#define SN_rc2_cfb64            "\x52\x43\x32\x2d\x43\x46\x42"
#define LN_rc2_cfb64            "\x72\x63\x32\x2d\x63\x66\x62"
#define NID_rc2_cfb64           39

#define SN_rc2_ofb64            "\x52\x43\x32\x2d\x4f\x46\x42"
#define LN_rc2_ofb64            "\x72\x63\x32\x2d\x6f\x66\x62"
#define NID_rc2_ofb64           40

#define SN_rc2_40_cbc           "\x52\x43\x32\x2d\x34\x30\x2d\x43\x42\x43"
#define LN_rc2_40_cbc           "\x72\x63\x32\x2d\x34\x30\x2d\x63\x62\x63"
#define NID_rc2_40_cbc          98

#define SN_rc2_64_cbc           "\x52\x43\x32\x2d\x36\x34\x2d\x43\x42\x43"
#define LN_rc2_64_cbc           "\x72\x63\x32\x2d\x36\x34\x2d\x63\x62\x63"
#define NID_rc2_64_cbc          166

#define SN_rc4          "\x52\x43\x34"
#define LN_rc4          "\x72\x63\x34"
#define NID_rc4         5
#define OBJ_rc4         OBJ_rsadsi,3L,4L

#define SN_rc4_40               "\x52\x43\x34\x2d\x34\x30"
#define LN_rc4_40               "\x72\x63\x34\x2d\x34\x30"
#define NID_rc4_40              97

#define SN_des_ede3_cbc         "\x44\x45\x53\x2d\x45\x44\x45\x33\x2d\x43\x42\x43"
#define LN_des_ede3_cbc         "\x64\x65\x73\x2d\x65\x64\x65\x33\x2d\x63\x62\x63"
#define NID_des_ede3_cbc                44
#define OBJ_des_ede3_cbc                OBJ_rsadsi,3L,7L

#define SN_rc5_cbc              "\x52\x43\x35\x2d\x43\x42\x43"
#define LN_rc5_cbc              "\x72\x63\x35\x2d\x63\x62\x63"
#define NID_rc5_cbc             120
#define OBJ_rc5_cbc             OBJ_rsadsi,3L,8L

#define SN_rc5_ecb              "\x52\x43\x35\x2d\x45\x43\x42"
#define LN_rc5_ecb              "\x72\x63\x35\x2d\x65\x63\x62"
#define NID_rc5_ecb             121

#define SN_rc5_cfb64            "\x52\x43\x35\x2d\x43\x46\x42"
#define LN_rc5_cfb64            "\x72\x63\x35\x2d\x63\x66\x62"
#define NID_rc5_cfb64           122

#define SN_rc5_ofb64            "\x52\x43\x35\x2d\x4f\x46\x42"
#define LN_rc5_ofb64            "\x72\x63\x35\x2d\x6f\x66\x62"
#define NID_rc5_ofb64           123

#define SN_ms_ext_req           "\x6d\x73\x45\x78\x74\x52\x65\x71"
#define LN_ms_ext_req           "\x4d\x69\x63\x72\x6f\x73\x6f\x66\x74\x20\x45\x78\x74\x65\x6e\x73\x69\x6f\x6e\x20\x52\x65\x71\x75\x65\x73\x74"
#define NID_ms_ext_req          171
#define OBJ_ms_ext_req          1L,3L,6L,1L,4L,1L,311L,2L,1L,14L

#define SN_ms_code_ind          "\x6d\x73\x43\x6f\x64\x65\x49\x6e\x64"
#define LN_ms_code_ind          "\x4d\x69\x63\x72\x6f\x73\x6f\x66\x74\x20\x49\x6e\x64\x69\x76\x69\x64\x75\x61\x6c\x20\x43\x6f\x64\x65\x20\x53\x69\x67\x6e\x69\x6e\x67"
#define NID_ms_code_ind         134
#define OBJ_ms_code_ind         1L,3L,6L,1L,4L,1L,311L,2L,1L,21L

#define SN_ms_code_com          "\x6d\x73\x43\x6f\x64\x65\x43\x6f\x6d"
#define LN_ms_code_com          "\x4d\x69\x63\x72\x6f\x73\x6f\x66\x74\x20\x43\x6f\x6d\x6d\x65\x72\x63\x69\x61\x6c\x20\x43\x6f\x64\x65\x20\x53\x69\x67\x6e\x69\x6e\x67"
#define NID_ms_code_com         135
#define OBJ_ms_code_com         1L,3L,6L,1L,4L,1L,311L,2L,1L,22L

#define SN_ms_ctl_sign          "\x6d\x73\x43\x54\x4c\x53\x69\x67\x6e"
#define LN_ms_ctl_sign          "\x4d\x69\x63\x72\x6f\x73\x6f\x66\x74\x20\x54\x72\x75\x73\x74\x20\x4c\x69\x73\x74\x20\x53\x69\x67\x6e\x69\x6e\x67"
#define NID_ms_ctl_sign         136
#define OBJ_ms_ctl_sign         1L,3L,6L,1L,4L,1L,311L,10L,3L,1L

#define SN_ms_sgc               "\x6d\x73\x53\x47\x43"
#define LN_ms_sgc               "\x4d\x69\x63\x72\x6f\x73\x6f\x66\x74\x20\x53\x65\x72\x76\x65\x72\x20\x47\x61\x74\x65\x64\x20\x43\x72\x79\x70\x74\x6f"
#define NID_ms_sgc              137
#define OBJ_ms_sgc              1L,3L,6L,1L,4L,1L,311L,10L,3L,3L

#define SN_ms_efs               "\x6d\x73\x45\x46\x53"
#define LN_ms_efs               "\x4d\x69\x63\x72\x6f\x73\x6f\x66\x74\x20\x45\x6e\x63\x72\x79\x70\x74\x65\x64\x20\x46\x69\x6c\x65\x20\x53\x79\x73\x74\x65\x6d"
#define NID_ms_efs              138
#define OBJ_ms_efs              1L,3L,6L,1L,4L,1L,311L,10L,3L,4L

#define SN_ms_smartcard_login           "\x6d\x73\x53\x6d\x61\x72\x74\x63\x61\x72\x64\x4c\x6f\x67\x69\x6e"
#define LN_ms_smartcard_login           "\x4d\x69\x63\x72\x6f\x73\x6f\x66\x74\x20\x53\x6d\x61\x72\x74\x63\x61\x72\x64\x6c\x6f\x67\x69\x6e"
#define NID_ms_smartcard_login          648
#define OBJ_ms_smartcard_login          1L,3L,6L,1L,4L,1L,311L,20L,2L,2L

#define SN_ms_upn               "\x6d\x73\x55\x50\x4e"
#define LN_ms_upn               "\x4d\x69\x63\x72\x6f\x73\x6f\x66\x74\x20\x55\x6e\x69\x76\x65\x72\x73\x61\x6c\x20\x50\x72\x69\x6e\x63\x69\x70\x61\x6c\x20\x4e\x61\x6d\x65"
#define NID_ms_upn              649
#define OBJ_ms_upn              1L,3L,6L,1L,4L,1L,311L,20L,2L,3L

#define SN_idea_cbc             "\x49\x44\x45\x41\x2d\x43\x42\x43"
#define LN_idea_cbc             "\x69\x64\x65\x61\x2d\x63\x62\x63"
#define NID_idea_cbc            34
#define OBJ_idea_cbc            1L,3L,6L,1L,4L,1L,188L,7L,1L,1L,2L

#define SN_idea_ecb             "\x49\x44\x45\x41\x2d\x45\x43\x42"
#define LN_idea_ecb             "\x69\x64\x65\x61\x2d\x65\x63\x62"
#define NID_idea_ecb            36

#define SN_idea_cfb64           "\x49\x44\x45\x41\x2d\x43\x46\x42"
#define LN_idea_cfb64           "\x69\x64\x65\x61\x2d\x63\x66\x62"
#define NID_idea_cfb64          35

#define SN_idea_ofb64           "\x49\x44\x45\x41\x2d\x4f\x46\x42"
#define LN_idea_ofb64           "\x69\x64\x65\x61\x2d\x6f\x66\x62"
#define NID_idea_ofb64          46

#define SN_bf_cbc               "\x42\x46\x2d\x43\x42\x43"
#define LN_bf_cbc               "\x62\x66\x2d\x63\x62\x63"
#define NID_bf_cbc              91
#define OBJ_bf_cbc              1L,3L,6L,1L,4L,1L,3029L,1L,2L

#define SN_bf_ecb               "\x42\x46\x2d\x45\x43\x42"
#define LN_bf_ecb               "\x62\x66\x2d\x65\x63\x62"
#define NID_bf_ecb              92

#define SN_bf_cfb64             "\x42\x46\x2d\x43\x46\x42"
#define LN_bf_cfb64             "\x62\x66\x2d\x63\x66\x62"
#define NID_bf_cfb64            93

#define SN_bf_ofb64             "\x42\x46\x2d\x4f\x46\x42"
#define LN_bf_ofb64             "\x62\x66\x2d\x6f\x66\x62"
#define NID_bf_ofb64            94

#define SN_id_pkix              "\x50\x4b\x49\x58"
#define NID_id_pkix             127
#define OBJ_id_pkix             1L,3L,6L,1L,5L,5L,7L

#define SN_id_pkix_mod          "\x69\x64\x2d\x70\x6b\x69\x78\x2d\x6d\x6f\x64"
#define NID_id_pkix_mod         258
#define OBJ_id_pkix_mod         OBJ_id_pkix,0L

#define SN_id_pe                "\x69\x64\x2d\x70\x65"
#define NID_id_pe               175
#define OBJ_id_pe               OBJ_id_pkix,1L

#define SN_id_qt                "\x69\x64\x2d\x71\x74"
#define NID_id_qt               259
#define OBJ_id_qt               OBJ_id_pkix,2L

#define SN_id_kp                "\x69\x64\x2d\x6b\x70"
#define NID_id_kp               128
#define OBJ_id_kp               OBJ_id_pkix,3L

#define SN_id_it                "\x69\x64\x2d\x69\x74"
#define NID_id_it               260
#define OBJ_id_it               OBJ_id_pkix,4L

#define SN_id_pkip              "\x69\x64\x2d\x70\x6b\x69\x70"
#define NID_id_pkip             261
#define OBJ_id_pkip             OBJ_id_pkix,5L

#define SN_id_alg               "\x69\x64\x2d\x61\x6c\x67"
#define NID_id_alg              262
#define OBJ_id_alg              OBJ_id_pkix,6L

#define SN_id_cmc               "\x69\x64\x2d\x63\x6d\x63"
#define NID_id_cmc              263
#define OBJ_id_cmc              OBJ_id_pkix,7L

#define SN_id_on                "\x69\x64\x2d\x6f\x6e"
#define NID_id_on               264
#define OBJ_id_on               OBJ_id_pkix,8L

#define SN_id_pda               "\x69\x64\x2d\x70\x64\x61"
#define NID_id_pda              265
#define OBJ_id_pda              OBJ_id_pkix,9L

#define SN_id_aca               "\x69\x64\x2d\x61\x63\x61"
#define NID_id_aca              266
#define OBJ_id_aca              OBJ_id_pkix,10L

#define SN_id_qcs               "\x69\x64\x2d\x71\x63\x73"
#define NID_id_qcs              267
#define OBJ_id_qcs              OBJ_id_pkix,11L

#define SN_id_cct               "\x69\x64\x2d\x63\x63\x74"
#define NID_id_cct              268
#define OBJ_id_cct              OBJ_id_pkix,12L

#define SN_id_ppl               "\x69\x64\x2d\x70\x70\x6c"
#define NID_id_ppl              662
#define OBJ_id_ppl              OBJ_id_pkix,21L

#define SN_id_ad                "\x69\x64\x2d\x61\x64"
#define NID_id_ad               176
#define OBJ_id_ad               OBJ_id_pkix,48L

#define SN_id_pkix1_explicit_88         "\x69\x64\x2d\x70\x6b\x69\x78\x31\x2d\x65\x78\x70\x6c\x69\x63\x69\x74\x2d\x38\x38"
#define NID_id_pkix1_explicit_88                269
#define OBJ_id_pkix1_explicit_88                OBJ_id_pkix_mod,1L

#define SN_id_pkix1_implicit_88         "\x69\x64\x2d\x70\x6b\x69\x78\x31\x2d\x69\x6d\x70\x6c\x69\x63\x69\x74\x2d\x38\x38"
#define NID_id_pkix1_implicit_88                270
#define OBJ_id_pkix1_implicit_88                OBJ_id_pkix_mod,2L

#define SN_id_pkix1_explicit_93         "\x69\x64\x2d\x70\x6b\x69\x78\x31\x2d\x65\x78\x70\x6c\x69\x63\x69\x74\x2d\x39\x33"
#define NID_id_pkix1_explicit_93                271
#define OBJ_id_pkix1_explicit_93                OBJ_id_pkix_mod,3L

#define SN_id_pkix1_implicit_93         "\x69\x64\x2d\x70\x6b\x69\x78\x31\x2d\x69\x6d\x70\x6c\x69\x63\x69\x74\x2d\x39\x33"
#define NID_id_pkix1_implicit_93                272
#define OBJ_id_pkix1_implicit_93                OBJ_id_pkix_mod,4L

#define SN_id_mod_crmf          "\x69\x64\x2d\x6d\x6f\x64\x2d\x63\x72\x6d\x66"
#define NID_id_mod_crmf         273
#define OBJ_id_mod_crmf         OBJ_id_pkix_mod,5L

#define SN_id_mod_cmc           "\x69\x64\x2d\x6d\x6f\x64\x2d\x63\x6d\x63"
#define NID_id_mod_cmc          274
#define OBJ_id_mod_cmc          OBJ_id_pkix_mod,6L

#define SN_id_mod_kea_profile_88                "\x69\x64\x2d\x6d\x6f\x64\x2d\x6b\x65\x61\x2d\x70\x72\x6f\x66\x69\x6c\x65\x2d\x38\x38"
#define NID_id_mod_kea_profile_88               275
#define OBJ_id_mod_kea_profile_88               OBJ_id_pkix_mod,7L

#define SN_id_mod_kea_profile_93                "\x69\x64\x2d\x6d\x6f\x64\x2d\x6b\x65\x61\x2d\x70\x72\x6f\x66\x69\x6c\x65\x2d\x39\x33"
#define NID_id_mod_kea_profile_93               276
#define OBJ_id_mod_kea_profile_93               OBJ_id_pkix_mod,8L

#define SN_id_mod_cmp           "\x69\x64\x2d\x6d\x6f\x64\x2d\x63\x6d\x70"
#define NID_id_mod_cmp          277
#define OBJ_id_mod_cmp          OBJ_id_pkix_mod,9L

#define SN_id_mod_qualified_cert_88             "\x69\x64\x2d\x6d\x6f\x64\x2d\x71\x75\x61\x6c\x69\x66\x69\x65\x64\x2d\x63\x65\x72\x74\x2d\x38\x38"
#define NID_id_mod_qualified_cert_88            278
#define OBJ_id_mod_qualified_cert_88            OBJ_id_pkix_mod,10L

#define SN_id_mod_qualified_cert_93             "\x69\x64\x2d\x6d\x6f\x64\x2d\x71\x75\x61\x6c\x69\x66\x69\x65\x64\x2d\x63\x65\x72\x74\x2d\x39\x33"
#define NID_id_mod_qualified_cert_93            279
#define OBJ_id_mod_qualified_cert_93            OBJ_id_pkix_mod,11L

#define SN_id_mod_attribute_cert                "\x69\x64\x2d\x6d\x6f\x64\x2d\x61\x74\x74\x72\x69\x62\x75\x74\x65\x2d\x63\x65\x72\x74"
#define NID_id_mod_attribute_cert               280
#define OBJ_id_mod_attribute_cert               OBJ_id_pkix_mod,12L

#define SN_id_mod_timestamp_protocol            "\x69\x64\x2d\x6d\x6f\x64\x2d\x74\x69\x6d\x65\x73\x74\x61\x6d\x70\x2d\x70\x72\x6f\x74\x6f\x63\x6f\x6c"
#define NID_id_mod_timestamp_protocol           281
#define OBJ_id_mod_timestamp_protocol           OBJ_id_pkix_mod,13L

#define SN_id_mod_ocsp          "\x69\x64\x2d\x6d\x6f\x64\x2d\x6f\x63\x73\x70"
#define NID_id_mod_ocsp         282
#define OBJ_id_mod_ocsp         OBJ_id_pkix_mod,14L

#define SN_id_mod_dvcs          "\x69\x64\x2d\x6d\x6f\x64\x2d\x64\x76\x63\x73"
#define NID_id_mod_dvcs         283
#define OBJ_id_mod_dvcs         OBJ_id_pkix_mod,15L

#define SN_id_mod_cmp2000               "\x69\x64\x2d\x6d\x6f\x64\x2d\x63\x6d\x70\x32\x30\x30\x30"
#define NID_id_mod_cmp2000              284
#define OBJ_id_mod_cmp2000              OBJ_id_pkix_mod,16L

#define SN_info_access          "\x61\x75\x74\x68\x6f\x72\x69\x74\x79\x49\x6e\x66\x6f\x41\x63\x63\x65\x73\x73"
#define LN_info_access          "\x41\x75\x74\x68\x6f\x72\x69\x74\x79\x20\x49\x6e\x66\x6f\x72\x6d\x61\x74\x69\x6f\x6e\x20\x41\x63\x63\x65\x73\x73"
#define NID_info_access         177
#define OBJ_info_access         OBJ_id_pe,1L

#define SN_biometricInfo                "\x62\x69\x6f\x6d\x65\x74\x72\x69\x63\x49\x6e\x66\x6f"
#define LN_biometricInfo                "\x42\x69\x6f\x6d\x65\x74\x72\x69\x63\x20\x49\x6e\x66\x6f"
#define NID_biometricInfo               285
#define OBJ_biometricInfo               OBJ_id_pe,2L

#define SN_qcStatements         "\x71\x63\x53\x74\x61\x74\x65\x6d\x65\x6e\x74\x73"
#define NID_qcStatements                286
#define OBJ_qcStatements                OBJ_id_pe,3L

#define SN_ac_auditEntity               "\x61\x63\x2d\x61\x75\x64\x69\x74\x45\x6e\x74\x69\x74\x79"
#define NID_ac_auditEntity              287
#define OBJ_ac_auditEntity              OBJ_id_pe,4L

#define SN_ac_targeting         "\x61\x63\x2d\x74\x61\x72\x67\x65\x74\x69\x6e\x67"
#define NID_ac_targeting                288
#define OBJ_ac_targeting                OBJ_id_pe,5L

#define SN_aaControls           "\x61\x61\x43\x6f\x6e\x74\x72\x6f\x6c\x73"
#define NID_aaControls          289
#define OBJ_aaControls          OBJ_id_pe,6L

#define SN_sbgp_ipAddrBlock             "\x73\x62\x67\x70\x2d\x69\x70\x41\x64\x64\x72\x42\x6c\x6f\x63\x6b"
#define NID_sbgp_ipAddrBlock            290
#define OBJ_sbgp_ipAddrBlock            OBJ_id_pe,7L

#define SN_sbgp_autonomousSysNum                "\x73\x62\x67\x70\x2d\x61\x75\x74\x6f\x6e\x6f\x6d\x6f\x75\x73\x53\x79\x73\x4e\x75\x6d"
#define NID_sbgp_autonomousSysNum               291
#define OBJ_sbgp_autonomousSysNum               OBJ_id_pe,8L

#define SN_sbgp_routerIdentifier                "\x73\x62\x67\x70\x2d\x72\x6f\x75\x74\x65\x72\x49\x64\x65\x6e\x74\x69\x66\x69\x65\x72"
#define NID_sbgp_routerIdentifier               292
#define OBJ_sbgp_routerIdentifier               OBJ_id_pe,9L

#define SN_ac_proxying          "\x61\x63\x2d\x70\x72\x6f\x78\x79\x69\x6e\x67"
#define NID_ac_proxying         397
#define OBJ_ac_proxying         OBJ_id_pe,10L

#define SN_sinfo_access         "\x73\x75\x62\x6a\x65\x63\x74\x49\x6e\x66\x6f\x41\x63\x63\x65\x73\x73"
#define LN_sinfo_access         "\x53\x75\x62\x6a\x65\x63\x74\x20\x49\x6e\x66\x6f\x72\x6d\x61\x74\x69\x6f\x6e\x20\x41\x63\x63\x65\x73\x73"
#define NID_sinfo_access                398
#define OBJ_sinfo_access                OBJ_id_pe,11L

#define SN_proxyCertInfo                "\x70\x72\x6f\x78\x79\x43\x65\x72\x74\x49\x6e\x66\x6f"
#define LN_proxyCertInfo                "\x50\x72\x6f\x78\x79\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x49\x6e\x66\x6f\x72\x6d\x61\x74\x69\x6f\x6e"
#define NID_proxyCertInfo               663
#define OBJ_proxyCertInfo               OBJ_id_pe,14L

#define SN_id_qt_cps            "\x69\x64\x2d\x71\x74\x2d\x63\x70\x73"
#define LN_id_qt_cps            "\x50\x6f\x6c\x69\x63\x79\x20\x51\x75\x61\x6c\x69\x66\x69\x65\x72\x20\x43\x50\x53"
#define NID_id_qt_cps           164
#define OBJ_id_qt_cps           OBJ_id_qt,1L

#define SN_id_qt_unotice                "\x69\x64\x2d\x71\x74\x2d\x75\x6e\x6f\x74\x69\x63\x65"
#define LN_id_qt_unotice                "\x50\x6f\x6c\x69\x63\x79\x20\x51\x75\x61\x6c\x69\x66\x69\x65\x72\x20\x55\x73\x65\x72\x20\x4e\x6f\x74\x69\x63\x65"
#define NID_id_qt_unotice               165
#define OBJ_id_qt_unotice               OBJ_id_qt,2L

#define SN_textNotice           "\x74\x65\x78\x74\x4e\x6f\x74\x69\x63\x65"
#define NID_textNotice          293
#define OBJ_textNotice          OBJ_id_qt,3L

#define SN_server_auth          "\x73\x65\x72\x76\x65\x72\x41\x75\x74\x68"
#define LN_server_auth          "\x54\x4c\x53\x20\x57\x65\x62\x20\x53\x65\x72\x76\x65\x72\x20\x41\x75\x74\x68\x65\x6e\x74\x69\x63\x61\x74\x69\x6f\x6e"
#define NID_server_auth         129
#define OBJ_server_auth         OBJ_id_kp,1L

#define SN_client_auth          "\x63\x6c\x69\x65\x6e\x74\x41\x75\x74\x68"
#define LN_client_auth          "\x54\x4c\x53\x20\x57\x65\x62\x20\x43\x6c\x69\x65\x6e\x74\x20\x41\x75\x74\x68\x65\x6e\x74\x69\x63\x61\x74\x69\x6f\x6e"
#define NID_client_auth         130
#define OBJ_client_auth         OBJ_id_kp,2L

#define SN_code_sign            "\x63\x6f\x64\x65\x53\x69\x67\x6e\x69\x6e\x67"
#define LN_code_sign            "\x43\x6f\x64\x65\x20\x53\x69\x67\x6e\x69\x6e\x67"
#define NID_code_sign           131
#define OBJ_code_sign           OBJ_id_kp,3L

#define SN_email_protect                "\x65\x6d\x61\x69\x6c\x50\x72\x6f\x74\x65\x63\x74\x69\x6f\x6e"
#define LN_email_protect                "\x45\x2d\x6d\x61\x69\x6c\x20\x50\x72\x6f\x74\x65\x63\x74\x69\x6f\x6e"
#define NID_email_protect               132
#define OBJ_email_protect               OBJ_id_kp,4L

#define SN_ipsecEndSystem               "\x69\x70\x73\x65\x63\x45\x6e\x64\x53\x79\x73\x74\x65\x6d"
#define LN_ipsecEndSystem               "\x49\x50\x53\x65\x63\x20\x45\x6e\x64\x20\x53\x79\x73\x74\x65\x6d"
#define NID_ipsecEndSystem              294
#define OBJ_ipsecEndSystem              OBJ_id_kp,5L

#define SN_ipsecTunnel          "\x69\x70\x73\x65\x63\x54\x75\x6e\x6e\x65\x6c"
#define LN_ipsecTunnel          "\x49\x50\x53\x65\x63\x20\x54\x75\x6e\x6e\x65\x6c"
#define NID_ipsecTunnel         295
#define OBJ_ipsecTunnel         OBJ_id_kp,6L

#define SN_ipsecUser            "\x69\x70\x73\x65\x63\x55\x73\x65\x72"
#define LN_ipsecUser            "\x49\x50\x53\x65\x63\x20\x55\x73\x65\x72"
#define NID_ipsecUser           296
#define OBJ_ipsecUser           OBJ_id_kp,7L

#define SN_time_stamp           "\x74\x69\x6d\x65\x53\x74\x61\x6d\x70\x69\x6e\x67"
#define LN_time_stamp           "\x54\x69\x6d\x65\x20\x53\x74\x61\x6d\x70\x69\x6e\x67"
#define NID_time_stamp          133
#define OBJ_time_stamp          OBJ_id_kp,8L

#define SN_OCSP_sign            "\x4f\x43\x53\x50\x53\x69\x67\x6e\x69\x6e\x67"
#define LN_OCSP_sign            "\x4f\x43\x53\x50\x20\x53\x69\x67\x6e\x69\x6e\x67"
#define NID_OCSP_sign           180
#define OBJ_OCSP_sign           OBJ_id_kp,9L

#define SN_dvcs         "\x44\x56\x43\x53"
#define LN_dvcs         "\x64\x76\x63\x73"
#define NID_dvcs                297
#define OBJ_dvcs                OBJ_id_kp,10L

#define SN_id_it_caProtEncCert          "\x69\x64\x2d\x69\x74\x2d\x63\x61\x50\x72\x6f\x74\x45\x6e\x63\x43\x65\x72\x74"
#define NID_id_it_caProtEncCert         298
#define OBJ_id_it_caProtEncCert         OBJ_id_it,1L

#define SN_id_it_signKeyPairTypes               "\x69\x64\x2d\x69\x74\x2d\x73\x69\x67\x6e\x4b\x65\x79\x50\x61\x69\x72\x54\x79\x70\x65\x73"
#define NID_id_it_signKeyPairTypes              299
#define OBJ_id_it_signKeyPairTypes              OBJ_id_it,2L

#define SN_id_it_encKeyPairTypes                "\x69\x64\x2d\x69\x74\x2d\x65\x6e\x63\x4b\x65\x79\x50\x61\x69\x72\x54\x79\x70\x65\x73"
#define NID_id_it_encKeyPairTypes               300
#define OBJ_id_it_encKeyPairTypes               OBJ_id_it,3L

#define SN_id_it_preferredSymmAlg               "\x69\x64\x2d\x69\x74\x2d\x70\x72\x65\x66\x65\x72\x72\x65\x64\x53\x79\x6d\x6d\x41\x6c\x67"
#define NID_id_it_preferredSymmAlg              301
#define OBJ_id_it_preferredSymmAlg              OBJ_id_it,4L

#define SN_id_it_caKeyUpdateInfo                "\x69\x64\x2d\x69\x74\x2d\x63\x61\x4b\x65\x79\x55\x70\x64\x61\x74\x65\x49\x6e\x66\x6f"
#define NID_id_it_caKeyUpdateInfo               302
#define OBJ_id_it_caKeyUpdateInfo               OBJ_id_it,5L

#define SN_id_it_currentCRL             "\x69\x64\x2d\x69\x74\x2d\x63\x75\x72\x72\x65\x6e\x74\x43\x52\x4c"
#define NID_id_it_currentCRL            303
#define OBJ_id_it_currentCRL            OBJ_id_it,6L

#define SN_id_it_unsupportedOIDs                "\x69\x64\x2d\x69\x74\x2d\x75\x6e\x73\x75\x70\x70\x6f\x72\x74\x65\x64\x4f\x49\x44\x73"
#define NID_id_it_unsupportedOIDs               304
#define OBJ_id_it_unsupportedOIDs               OBJ_id_it,7L

#define SN_id_it_subscriptionRequest            "\x69\x64\x2d\x69\x74\x2d\x73\x75\x62\x73\x63\x72\x69\x70\x74\x69\x6f\x6e\x52\x65\x71\x75\x65\x73\x74"
#define NID_id_it_subscriptionRequest           305
#define OBJ_id_it_subscriptionRequest           OBJ_id_it,8L

#define SN_id_it_subscriptionResponse           "\x69\x64\x2d\x69\x74\x2d\x73\x75\x62\x73\x63\x72\x69\x70\x74\x69\x6f\x6e\x52\x65\x73\x70\x6f\x6e\x73\x65"
#define NID_id_it_subscriptionResponse          306
#define OBJ_id_it_subscriptionResponse          OBJ_id_it,9L

#define SN_id_it_keyPairParamReq                "\x69\x64\x2d\x69\x74\x2d\x6b\x65\x79\x50\x61\x69\x72\x50\x61\x72\x61\x6d\x52\x65\x71"
#define NID_id_it_keyPairParamReq               307
#define OBJ_id_it_keyPairParamReq               OBJ_id_it,10L

#define SN_id_it_keyPairParamRep                "\x69\x64\x2d\x69\x74\x2d\x6b\x65\x79\x50\x61\x69\x72\x50\x61\x72\x61\x6d\x52\x65\x70"
#define NID_id_it_keyPairParamRep               308
#define OBJ_id_it_keyPairParamRep               OBJ_id_it,11L

#define SN_id_it_revPassphrase          "\x69\x64\x2d\x69\x74\x2d\x72\x65\x76\x50\x61\x73\x73\x70\x68\x72\x61\x73\x65"
#define NID_id_it_revPassphrase         309
#define OBJ_id_it_revPassphrase         OBJ_id_it,12L

#define SN_id_it_implicitConfirm                "\x69\x64\x2d\x69\x74\x2d\x69\x6d\x70\x6c\x69\x63\x69\x74\x43\x6f\x6e\x66\x69\x72\x6d"
#define NID_id_it_implicitConfirm               310
#define OBJ_id_it_implicitConfirm               OBJ_id_it,13L

#define SN_id_it_confirmWaitTime                "\x69\x64\x2d\x69\x74\x2d\x63\x6f\x6e\x66\x69\x72\x6d\x57\x61\x69\x74\x54\x69\x6d\x65"
#define NID_id_it_confirmWaitTime               311
#define OBJ_id_it_confirmWaitTime               OBJ_id_it,14L

#define SN_id_it_origPKIMessage         "\x69\x64\x2d\x69\x74\x2d\x6f\x72\x69\x67\x50\x4b\x49\x4d\x65\x73\x73\x61\x67\x65"
#define NID_id_it_origPKIMessage                312
#define OBJ_id_it_origPKIMessage                OBJ_id_it,15L

#define SN_id_it_suppLangTags           "\x69\x64\x2d\x69\x74\x2d\x73\x75\x70\x70\x4c\x61\x6e\x67\x54\x61\x67\x73"
#define NID_id_it_suppLangTags          784
#define OBJ_id_it_suppLangTags          OBJ_id_it,16L

#define SN_id_regCtrl           "\x69\x64\x2d\x72\x65\x67\x43\x74\x72\x6c"
#define NID_id_regCtrl          313
#define OBJ_id_regCtrl          OBJ_id_pkip,1L

#define SN_id_regInfo           "\x69\x64\x2d\x72\x65\x67\x49\x6e\x66\x6f"
#define NID_id_regInfo          314
#define OBJ_id_regInfo          OBJ_id_pkip,2L

#define SN_id_regCtrl_regToken          "\x69\x64\x2d\x72\x65\x67\x43\x74\x72\x6c\x2d\x72\x65\x67\x54\x6f\x6b\x65\x6e"
#define NID_id_regCtrl_regToken         315
#define OBJ_id_regCtrl_regToken         OBJ_id_regCtrl,1L

#define SN_id_regCtrl_authenticator             "\x69\x64\x2d\x72\x65\x67\x43\x74\x72\x6c\x2d\x61\x75\x74\x68\x65\x6e\x74\x69\x63\x61\x74\x6f\x72"
#define NID_id_regCtrl_authenticator            316
#define OBJ_id_regCtrl_authenticator            OBJ_id_regCtrl,2L

#define SN_id_regCtrl_pkiPublicationInfo                "\x69\x64\x2d\x72\x65\x67\x43\x74\x72\x6c\x2d\x70\x6b\x69\x50\x75\x62\x6c\x69\x63\x61\x74\x69\x6f\x6e\x49\x6e\x66\x6f"
#define NID_id_regCtrl_pkiPublicationInfo               317
#define OBJ_id_regCtrl_pkiPublicationInfo               OBJ_id_regCtrl,3L

#define SN_id_regCtrl_pkiArchiveOptions         "\x69\x64\x2d\x72\x65\x67\x43\x74\x72\x6c\x2d\x70\x6b\x69\x41\x72\x63\x68\x69\x76\x65\x4f\x70\x74\x69\x6f\x6e\x73"
#define NID_id_regCtrl_pkiArchiveOptions                318
#define OBJ_id_regCtrl_pkiArchiveOptions                OBJ_id_regCtrl,4L

#define SN_id_regCtrl_oldCertID         "\x69\x64\x2d\x72\x65\x67\x43\x74\x72\x6c\x2d\x6f\x6c\x64\x43\x65\x72\x74\x49\x44"
#define NID_id_regCtrl_oldCertID                319
#define OBJ_id_regCtrl_oldCertID                OBJ_id_regCtrl,5L

#define SN_id_regCtrl_protocolEncrKey           "\x69\x64\x2d\x72\x65\x67\x43\x74\x72\x6c\x2d\x70\x72\x6f\x74\x6f\x63\x6f\x6c\x45\x6e\x63\x72\x4b\x65\x79"
#define NID_id_regCtrl_protocolEncrKey          320
#define OBJ_id_regCtrl_protocolEncrKey          OBJ_id_regCtrl,6L

#define SN_id_regInfo_utf8Pairs         "\x69\x64\x2d\x72\x65\x67\x49\x6e\x66\x6f\x2d\x75\x74\x66\x38\x50\x61\x69\x72\x73"
#define NID_id_regInfo_utf8Pairs                321
#define OBJ_id_regInfo_utf8Pairs                OBJ_id_regInfo,1L

#define SN_id_regInfo_certReq           "\x69\x64\x2d\x72\x65\x67\x49\x6e\x66\x6f\x2d\x63\x65\x72\x74\x52\x65\x71"
#define NID_id_regInfo_certReq          322
#define OBJ_id_regInfo_certReq          OBJ_id_regInfo,2L

#define SN_id_alg_des40         "\x69\x64\x2d\x61\x6c\x67\x2d\x64\x65\x73\x34\x30"
#define NID_id_alg_des40                323
#define OBJ_id_alg_des40                OBJ_id_alg,1L

#define SN_id_alg_noSignature           "\x69\x64\x2d\x61\x6c\x67\x2d\x6e\x6f\x53\x69\x67\x6e\x61\x74\x75\x72\x65"
#define NID_id_alg_noSignature          324
#define OBJ_id_alg_noSignature          OBJ_id_alg,2L

#define SN_id_alg_dh_sig_hmac_sha1              "\x69\x64\x2d\x61\x6c\x67\x2d\x64\x68\x2d\x73\x69\x67\x2d\x68\x6d\x61\x63\x2d\x73\x68\x61\x31"
#define NID_id_alg_dh_sig_hmac_sha1             325
#define OBJ_id_alg_dh_sig_hmac_sha1             OBJ_id_alg,3L

#define SN_id_alg_dh_pop                "\x69\x64\x2d\x61\x6c\x67\x2d\x64\x68\x2d\x70\x6f\x70"
#define NID_id_alg_dh_pop               326
#define OBJ_id_alg_dh_pop               OBJ_id_alg,4L

#define SN_id_cmc_statusInfo            "\x69\x64\x2d\x63\x6d\x63\x2d\x73\x74\x61\x74\x75\x73\x49\x6e\x66\x6f"
#define NID_id_cmc_statusInfo           327
#define OBJ_id_cmc_statusInfo           OBJ_id_cmc,1L

#define SN_id_cmc_identification                "\x69\x64\x2d\x63\x6d\x63\x2d\x69\x64\x65\x6e\x74\x69\x66\x69\x63\x61\x74\x69\x6f\x6e"
#define NID_id_cmc_identification               328
#define OBJ_id_cmc_identification               OBJ_id_cmc,2L

#define SN_id_cmc_identityProof         "\x69\x64\x2d\x63\x6d\x63\x2d\x69\x64\x65\x6e\x74\x69\x74\x79\x50\x72\x6f\x6f\x66"
#define NID_id_cmc_identityProof                329
#define OBJ_id_cmc_identityProof                OBJ_id_cmc,3L

#define SN_id_cmc_dataReturn            "\x69\x64\x2d\x63\x6d\x63\x2d\x64\x61\x74\x61\x52\x65\x74\x75\x72\x6e"
#define NID_id_cmc_dataReturn           330
#define OBJ_id_cmc_dataReturn           OBJ_id_cmc,4L

#define SN_id_cmc_transactionId         "\x69\x64\x2d\x63\x6d\x63\x2d\x74\x72\x61\x6e\x73\x61\x63\x74\x69\x6f\x6e\x49\x64"
#define NID_id_cmc_transactionId                331
#define OBJ_id_cmc_transactionId                OBJ_id_cmc,5L

#define SN_id_cmc_senderNonce           "\x69\x64\x2d\x63\x6d\x63\x2d\x73\x65\x6e\x64\x65\x72\x4e\x6f\x6e\x63\x65"
#define NID_id_cmc_senderNonce          332
#define OBJ_id_cmc_senderNonce          OBJ_id_cmc,6L

#define SN_id_cmc_recipientNonce                "\x69\x64\x2d\x63\x6d\x63\x2d\x72\x65\x63\x69\x70\x69\x65\x6e\x74\x4e\x6f\x6e\x63\x65"
#define NID_id_cmc_recipientNonce               333
#define OBJ_id_cmc_recipientNonce               OBJ_id_cmc,7L

#define SN_id_cmc_addExtensions         "\x69\x64\x2d\x63\x6d\x63\x2d\x61\x64\x64\x45\x78\x74\x65\x6e\x73\x69\x6f\x6e\x73"
#define NID_id_cmc_addExtensions                334
#define OBJ_id_cmc_addExtensions                OBJ_id_cmc,8L

#define SN_id_cmc_encryptedPOP          "\x69\x64\x2d\x63\x6d\x63\x2d\x65\x6e\x63\x72\x79\x70\x74\x65\x64\x50\x4f\x50"
#define NID_id_cmc_encryptedPOP         335
#define OBJ_id_cmc_encryptedPOP         OBJ_id_cmc,9L

#define SN_id_cmc_decryptedPOP          "\x69\x64\x2d\x63\x6d\x63\x2d\x64\x65\x63\x72\x79\x70\x74\x65\x64\x50\x4f\x50"
#define NID_id_cmc_decryptedPOP         336
#define OBJ_id_cmc_decryptedPOP         OBJ_id_cmc,10L

#define SN_id_cmc_lraPOPWitness         "\x69\x64\x2d\x63\x6d\x63\x2d\x6c\x72\x61\x50\x4f\x50\x57\x69\x74\x6e\x65\x73\x73"
#define NID_id_cmc_lraPOPWitness                337
#define OBJ_id_cmc_lraPOPWitness                OBJ_id_cmc,11L

#define SN_id_cmc_getCert               "\x69\x64\x2d\x63\x6d\x63\x2d\x67\x65\x74\x43\x65\x72\x74"
#define NID_id_cmc_getCert              338
#define OBJ_id_cmc_getCert              OBJ_id_cmc,15L

#define SN_id_cmc_getCRL                "\x69\x64\x2d\x63\x6d\x63\x2d\x67\x65\x74\x43\x52\x4c"
#define NID_id_cmc_getCRL               339
#define OBJ_id_cmc_getCRL               OBJ_id_cmc,16L

#define SN_id_cmc_revokeRequest         "\x69\x64\x2d\x63\x6d\x63\x2d\x72\x65\x76\x6f\x6b\x65\x52\x65\x71\x75\x65\x73\x74"
#define NID_id_cmc_revokeRequest                340
#define OBJ_id_cmc_revokeRequest                OBJ_id_cmc,17L

#define SN_id_cmc_regInfo               "\x69\x64\x2d\x63\x6d\x63\x2d\x72\x65\x67\x49\x6e\x66\x6f"
#define NID_id_cmc_regInfo              341
#define OBJ_id_cmc_regInfo              OBJ_id_cmc,18L

#define SN_id_cmc_responseInfo          "\x69\x64\x2d\x63\x6d\x63\x2d\x72\x65\x73\x70\x6f\x6e\x73\x65\x49\x6e\x66\x6f"
#define NID_id_cmc_responseInfo         342
#define OBJ_id_cmc_responseInfo         OBJ_id_cmc,19L

#define SN_id_cmc_queryPending          "\x69\x64\x2d\x63\x6d\x63\x2d\x71\x75\x65\x72\x79\x50\x65\x6e\x64\x69\x6e\x67"
#define NID_id_cmc_queryPending         343
#define OBJ_id_cmc_queryPending         OBJ_id_cmc,21L

#define SN_id_cmc_popLinkRandom         "\x69\x64\x2d\x63\x6d\x63\x2d\x70\x6f\x70\x4c\x69\x6e\x6b\x52\x61\x6e\x64\x6f\x6d"
#define NID_id_cmc_popLinkRandom                344
#define OBJ_id_cmc_popLinkRandom                OBJ_id_cmc,22L

#define SN_id_cmc_popLinkWitness                "\x69\x64\x2d\x63\x6d\x63\x2d\x70\x6f\x70\x4c\x69\x6e\x6b\x57\x69\x74\x6e\x65\x73\x73"
#define NID_id_cmc_popLinkWitness               345
#define OBJ_id_cmc_popLinkWitness               OBJ_id_cmc,23L

#define SN_id_cmc_confirmCertAcceptance         "\x69\x64\x2d\x63\x6d\x63\x2d\x63\x6f\x6e\x66\x69\x72\x6d\x43\x65\x72\x74\x41\x63\x63\x65\x70\x74\x61\x6e\x63\x65"
#define NID_id_cmc_confirmCertAcceptance                346
#define OBJ_id_cmc_confirmCertAcceptance                OBJ_id_cmc,24L

#define SN_id_on_personalData           "\x69\x64\x2d\x6f\x6e\x2d\x70\x65\x72\x73\x6f\x6e\x61\x6c\x44\x61\x74\x61"
#define NID_id_on_personalData          347
#define OBJ_id_on_personalData          OBJ_id_on,1L

#define SN_id_on_permanentIdentifier            "\x69\x64\x2d\x6f\x6e\x2d\x70\x65\x72\x6d\x61\x6e\x65\x6e\x74\x49\x64\x65\x6e\x74\x69\x66\x69\x65\x72"
#define LN_id_on_permanentIdentifier            "\x50\x65\x72\x6d\x61\x6e\x65\x6e\x74\x20\x49\x64\x65\x6e\x74\x69\x66\x69\x65\x72"
#define NID_id_on_permanentIdentifier           858
#define OBJ_id_on_permanentIdentifier           OBJ_id_on,3L

#define SN_id_pda_dateOfBirth           "\x69\x64\x2d\x70\x64\x61\x2d\x64\x61\x74\x65\x4f\x66\x42\x69\x72\x74\x68"
#define NID_id_pda_dateOfBirth          348
#define OBJ_id_pda_dateOfBirth          OBJ_id_pda,1L

#define SN_id_pda_placeOfBirth          "\x69\x64\x2d\x70\x64\x61\x2d\x70\x6c\x61\x63\x65\x4f\x66\x42\x69\x72\x74\x68"
#define NID_id_pda_placeOfBirth         349
#define OBJ_id_pda_placeOfBirth         OBJ_id_pda,2L

#define SN_id_pda_gender                "\x69\x64\x2d\x70\x64\x61\x2d\x67\x65\x6e\x64\x65\x72"
#define NID_id_pda_gender               351
#define OBJ_id_pda_gender               OBJ_id_pda,3L

#define SN_id_pda_countryOfCitizenship          "\x69\x64\x2d\x70\x64\x61\x2d\x63\x6f\x75\x6e\x74\x72\x79\x4f\x66\x43\x69\x74\x69\x7a\x65\x6e\x73\x68\x69\x70"
#define NID_id_pda_countryOfCitizenship         352
#define OBJ_id_pda_countryOfCitizenship         OBJ_id_pda,4L

#define SN_id_pda_countryOfResidence            "\x69\x64\x2d\x70\x64\x61\x2d\x63\x6f\x75\x6e\x74\x72\x79\x4f\x66\x52\x65\x73\x69\x64\x65\x6e\x63\x65"
#define NID_id_pda_countryOfResidence           353
#define OBJ_id_pda_countryOfResidence           OBJ_id_pda,5L

#define SN_id_aca_authenticationInfo            "\x69\x64\x2d\x61\x63\x61\x2d\x61\x75\x74\x68\x65\x6e\x74\x69\x63\x61\x74\x69\x6f\x6e\x49\x6e\x66\x6f"
#define NID_id_aca_authenticationInfo           354
#define OBJ_id_aca_authenticationInfo           OBJ_id_aca,1L

#define SN_id_aca_accessIdentity                "\x69\x64\x2d\x61\x63\x61\x2d\x61\x63\x63\x65\x73\x73\x49\x64\x65\x6e\x74\x69\x74\x79"
#define NID_id_aca_accessIdentity               355
#define OBJ_id_aca_accessIdentity               OBJ_id_aca,2L

#define SN_id_aca_chargingIdentity              "\x69\x64\x2d\x61\x63\x61\x2d\x63\x68\x61\x72\x67\x69\x6e\x67\x49\x64\x65\x6e\x74\x69\x74\x79"
#define NID_id_aca_chargingIdentity             356
#define OBJ_id_aca_chargingIdentity             OBJ_id_aca,3L

#define SN_id_aca_group         "\x69\x64\x2d\x61\x63\x61\x2d\x67\x72\x6f\x75\x70"
#define NID_id_aca_group                357
#define OBJ_id_aca_group                OBJ_id_aca,4L

#define SN_id_aca_role          "\x69\x64\x2d\x61\x63\x61\x2d\x72\x6f\x6c\x65"
#define NID_id_aca_role         358
#define OBJ_id_aca_role         OBJ_id_aca,5L

#define SN_id_aca_encAttrs              "\x69\x64\x2d\x61\x63\x61\x2d\x65\x6e\x63\x41\x74\x74\x72\x73"
#define NID_id_aca_encAttrs             399
#define OBJ_id_aca_encAttrs             OBJ_id_aca,6L

#define SN_id_qcs_pkixQCSyntax_v1               "\x69\x64\x2d\x71\x63\x73\x2d\x70\x6b\x69\x78\x51\x43\x53\x79\x6e\x74\x61\x78\x2d\x76\x31"
#define NID_id_qcs_pkixQCSyntax_v1              359
#define OBJ_id_qcs_pkixQCSyntax_v1              OBJ_id_qcs,1L

#define SN_id_cct_crs           "\x69\x64\x2d\x63\x63\x74\x2d\x63\x72\x73"
#define NID_id_cct_crs          360
#define OBJ_id_cct_crs          OBJ_id_cct,1L

#define SN_id_cct_PKIData               "\x69\x64\x2d\x63\x63\x74\x2d\x50\x4b\x49\x44\x61\x74\x61"
#define NID_id_cct_PKIData              361
#define OBJ_id_cct_PKIData              OBJ_id_cct,2L

#define SN_id_cct_PKIResponse           "\x69\x64\x2d\x63\x63\x74\x2d\x50\x4b\x49\x52\x65\x73\x70\x6f\x6e\x73\x65"
#define NID_id_cct_PKIResponse          362
#define OBJ_id_cct_PKIResponse          OBJ_id_cct,3L

#define SN_id_ppl_anyLanguage           "\x69\x64\x2d\x70\x70\x6c\x2d\x61\x6e\x79\x4c\x61\x6e\x67\x75\x61\x67\x65"
#define LN_id_ppl_anyLanguage           "\x41\x6e\x79\x20\x6c\x61\x6e\x67\x75\x61\x67\x65"
#define NID_id_ppl_anyLanguage          664
#define OBJ_id_ppl_anyLanguage          OBJ_id_ppl,0L

#define SN_id_ppl_inheritAll            "\x69\x64\x2d\x70\x70\x6c\x2d\x69\x6e\x68\x65\x72\x69\x74\x41\x6c\x6c"
#define LN_id_ppl_inheritAll            "\x49\x6e\x68\x65\x72\x69\x74\x20\x61\x6c\x6c"
#define NID_id_ppl_inheritAll           665
#define OBJ_id_ppl_inheritAll           OBJ_id_ppl,1L

#define SN_Independent          "\x69\x64\x2d\x70\x70\x6c\x2d\x69\x6e\x64\x65\x70\x65\x6e\x64\x65\x6e\x74"
#define LN_Independent          "\x49\x6e\x64\x65\x70\x65\x6e\x64\x65\x6e\x74"
#define NID_Independent         667
#define OBJ_Independent         OBJ_id_ppl,2L

#define SN_ad_OCSP              "\x4f\x43\x53\x50"
#define LN_ad_OCSP              "\x4f\x43\x53\x50"
#define NID_ad_OCSP             178
#define OBJ_ad_OCSP             OBJ_id_ad,1L

#define SN_ad_ca_issuers                "\x63\x61\x49\x73\x73\x75\x65\x72\x73"
#define LN_ad_ca_issuers                "\x43\x41\x20\x49\x73\x73\x75\x65\x72\x73"
#define NID_ad_ca_issuers               179
#define OBJ_ad_ca_issuers               OBJ_id_ad,2L

#define SN_ad_timeStamping              "\x61\x64\x5f\x74\x69\x6d\x65\x73\x74\x61\x6d\x70\x69\x6e\x67"
#define LN_ad_timeStamping              "\x41\x44\x20\x54\x69\x6d\x65\x20\x53\x74\x61\x6d\x70\x69\x6e\x67"
#define NID_ad_timeStamping             363
#define OBJ_ad_timeStamping             OBJ_id_ad,3L

#define SN_ad_dvcs              "\x41\x44\x5f\x44\x56\x43\x53"
#define LN_ad_dvcs              "\x61\x64\x20\x64\x76\x63\x73"
#define NID_ad_dvcs             364
#define OBJ_ad_dvcs             OBJ_id_ad,4L

#define SN_caRepository         "\x63\x61\x52\x65\x70\x6f\x73\x69\x74\x6f\x72\x79"
#define LN_caRepository         "\x43\x41\x20\x52\x65\x70\x6f\x73\x69\x74\x6f\x72\x79"
#define NID_caRepository                785
#define OBJ_caRepository                OBJ_id_ad,5L

#define OBJ_id_pkix_OCSP                OBJ_ad_OCSP

#define SN_id_pkix_OCSP_basic           "\x62\x61\x73\x69\x63\x4f\x43\x53\x50\x52\x65\x73\x70\x6f\x6e\x73\x65"
#define LN_id_pkix_OCSP_basic           "\x42\x61\x73\x69\x63\x20\x4f\x43\x53\x50\x20\x52\x65\x73\x70\x6f\x6e\x73\x65"
#define NID_id_pkix_OCSP_basic          365
#define OBJ_id_pkix_OCSP_basic          OBJ_id_pkix_OCSP,1L

#define SN_id_pkix_OCSP_Nonce           "\x4e\x6f\x6e\x63\x65"
#define LN_id_pkix_OCSP_Nonce           "\x4f\x43\x53\x50\x20\x4e\x6f\x6e\x63\x65"
#define NID_id_pkix_OCSP_Nonce          366
#define OBJ_id_pkix_OCSP_Nonce          OBJ_id_pkix_OCSP,2L

#define SN_id_pkix_OCSP_CrlID           "\x43\x72\x6c\x49\x44"
#define LN_id_pkix_OCSP_CrlID           "\x4f\x43\x53\x50\x20\x43\x52\x4c\x20\x49\x44"
#define NID_id_pkix_OCSP_CrlID          367
#define OBJ_id_pkix_OCSP_CrlID          OBJ_id_pkix_OCSP,3L

#define SN_id_pkix_OCSP_acceptableResponses             "\x61\x63\x63\x65\x70\x74\x61\x62\x6c\x65\x52\x65\x73\x70\x6f\x6e\x73\x65\x73"
#define LN_id_pkix_OCSP_acceptableResponses             "\x41\x63\x63\x65\x70\x74\x61\x62\x6c\x65\x20\x4f\x43\x53\x50\x20\x52\x65\x73\x70\x6f\x6e\x73\x65\x73"
#define NID_id_pkix_OCSP_acceptableResponses            368
#define OBJ_id_pkix_OCSP_acceptableResponses            OBJ_id_pkix_OCSP,4L

#define SN_id_pkix_OCSP_noCheck         "\x6e\x6f\x43\x68\x65\x63\x6b"
#define LN_id_pkix_OCSP_noCheck         "\x4f\x43\x53\x50\x20\x4e\x6f\x20\x43\x68\x65\x63\x6b"
#define NID_id_pkix_OCSP_noCheck                369
#define OBJ_id_pkix_OCSP_noCheck                OBJ_id_pkix_OCSP,5L

#define SN_id_pkix_OCSP_archiveCutoff           "\x61\x72\x63\x68\x69\x76\x65\x43\x75\x74\x6f\x66\x66"
#define LN_id_pkix_OCSP_archiveCutoff           "\x4f\x43\x53\x50\x20\x41\x72\x63\x68\x69\x76\x65\x20\x43\x75\x74\x6f\x66\x66"
#define NID_id_pkix_OCSP_archiveCutoff          370
#define OBJ_id_pkix_OCSP_archiveCutoff          OBJ_id_pkix_OCSP,6L

#define SN_id_pkix_OCSP_serviceLocator          "\x73\x65\x72\x76\x69\x63\x65\x4c\x6f\x63\x61\x74\x6f\x72"
#define LN_id_pkix_OCSP_serviceLocator          "\x4f\x43\x53\x50\x20\x53\x65\x72\x76\x69\x63\x65\x20\x4c\x6f\x63\x61\x74\x6f\x72"
#define NID_id_pkix_OCSP_serviceLocator         371
#define OBJ_id_pkix_OCSP_serviceLocator         OBJ_id_pkix_OCSP,7L

#define SN_id_pkix_OCSP_extendedStatus          "\x65\x78\x74\x65\x6e\x64\x65\x64\x53\x74\x61\x74\x75\x73"
#define LN_id_pkix_OCSP_extendedStatus          "\x45\x78\x74\x65\x6e\x64\x65\x64\x20\x4f\x43\x53\x50\x20\x53\x74\x61\x74\x75\x73"
#define NID_id_pkix_OCSP_extendedStatus         372
#define OBJ_id_pkix_OCSP_extendedStatus         OBJ_id_pkix_OCSP,8L

#define SN_id_pkix_OCSP_valid           "\x76\x61\x6c\x69\x64"
#define NID_id_pkix_OCSP_valid          373
#define OBJ_id_pkix_OCSP_valid          OBJ_id_pkix_OCSP,9L

#define SN_id_pkix_OCSP_path            "\x70\x61\x74\x68"
#define NID_id_pkix_OCSP_path           374
#define OBJ_id_pkix_OCSP_path           OBJ_id_pkix_OCSP,10L

#define SN_id_pkix_OCSP_trustRoot               "\x74\x72\x75\x73\x74\x52\x6f\x6f\x74"
#define LN_id_pkix_OCSP_trustRoot               "\x54\x72\x75\x73\x74\x20\x52\x6f\x6f\x74"
#define NID_id_pkix_OCSP_trustRoot              375
#define OBJ_id_pkix_OCSP_trustRoot              OBJ_id_pkix_OCSP,11L

#define SN_algorithm            "\x61\x6c\x67\x6f\x72\x69\x74\x68\x6d"
#define LN_algorithm            "\x61\x6c\x67\x6f\x72\x69\x74\x68\x6d"
#define NID_algorithm           376
#define OBJ_algorithm           1L,3L,14L,3L,2L

#define SN_md5WithRSA           "\x52\x53\x41\x2d\x4e\x50\x2d\x4d\x44\x35"
#define LN_md5WithRSA           "\x6d\x64\x35\x57\x69\x74\x68\x52\x53\x41"
#define NID_md5WithRSA          104
#define OBJ_md5WithRSA          OBJ_algorithm,3L

#define SN_des_ecb              "\x44\x45\x53\x2d\x45\x43\x42"
#define LN_des_ecb              "\x64\x65\x73\x2d\x65\x63\x62"
#define NID_des_ecb             29
#define OBJ_des_ecb             OBJ_algorithm,6L

#define SN_des_cbc              "\x44\x45\x53\x2d\x43\x42\x43"
#define LN_des_cbc              "\x64\x65\x73\x2d\x63\x62\x63"
#define NID_des_cbc             31
#define OBJ_des_cbc             OBJ_algorithm,7L

#define SN_des_ofb64            "\x44\x45\x53\x2d\x4f\x46\x42"
#define LN_des_ofb64            "\x64\x65\x73\x2d\x6f\x66\x62"
#define NID_des_ofb64           45
#define OBJ_des_ofb64           OBJ_algorithm,8L

#define SN_des_cfb64            "\x44\x45\x53\x2d\x43\x46\x42"
#define LN_des_cfb64            "\x64\x65\x73\x2d\x63\x66\x62"
#define NID_des_cfb64           30
#define OBJ_des_cfb64           OBJ_algorithm,9L

#define SN_rsaSignature         "\x72\x73\x61\x53\x69\x67\x6e\x61\x74\x75\x72\x65"
#define NID_rsaSignature                377
#define OBJ_rsaSignature                OBJ_algorithm,11L

#define SN_dsa_2                "\x44\x53\x41\x2d\x6f\x6c\x64"
#define LN_dsa_2                "\x64\x73\x61\x45\x6e\x63\x72\x79\x70\x74\x69\x6f\x6e\x2d\x6f\x6c\x64"
#define NID_dsa_2               67
#define OBJ_dsa_2               OBJ_algorithm,12L

#define SN_dsaWithSHA           "\x44\x53\x41\x2d\x53\x48\x41"
#define LN_dsaWithSHA           "\x64\x73\x61\x57\x69\x74\x68\x53\x48\x41"
#define NID_dsaWithSHA          66
#define OBJ_dsaWithSHA          OBJ_algorithm,13L

#define SN_shaWithRSAEncryption         "\x52\x53\x41\x2d\x53\x48\x41"
#define LN_shaWithRSAEncryption         "\x73\x68\x61\x57\x69\x74\x68\x52\x53\x41\x45\x6e\x63\x72\x79\x70\x74\x69\x6f\x6e"
#define NID_shaWithRSAEncryption                42
#define OBJ_shaWithRSAEncryption                OBJ_algorithm,15L

#define SN_des_ede_ecb          "\x44\x45\x53\x2d\x45\x44\x45"
#define LN_des_ede_ecb          "\x64\x65\x73\x2d\x65\x64\x65"
#define NID_des_ede_ecb         32
#define OBJ_des_ede_ecb         OBJ_algorithm,17L

#define SN_des_ede3_ecb         "\x44\x45\x53\x2d\x45\x44\x45\x33"
#define LN_des_ede3_ecb         "\x64\x65\x73\x2d\x65\x64\x65\x33"
#define NID_des_ede3_ecb                33

#define SN_des_ede_cbc          "\x44\x45\x53\x2d\x45\x44\x45\x2d\x43\x42\x43"
#define LN_des_ede_cbc          "\x64\x65\x73\x2d\x65\x64\x65\x2d\x63\x62\x63"
#define NID_des_ede_cbc         43

#define SN_des_ede_cfb64                "\x44\x45\x53\x2d\x45\x44\x45\x2d\x43\x46\x42"
#define LN_des_ede_cfb64                "\x64\x65\x73\x2d\x65\x64\x65\x2d\x63\x66\x62"
#define NID_des_ede_cfb64               60

#define SN_des_ede3_cfb64               "\x44\x45\x53\x2d\x45\x44\x45\x33\x2d\x43\x46\x42"
#define LN_des_ede3_cfb64               "\x64\x65\x73\x2d\x65\x64\x65\x33\x2d\x63\x66\x62"
#define NID_des_ede3_cfb64              61

#define SN_des_ede_ofb64                "\x44\x45\x53\x2d\x45\x44\x45\x2d\x4f\x46\x42"
#define LN_des_ede_ofb64                "\x64\x65\x73\x2d\x65\x64\x65\x2d\x6f\x66\x62"
#define NID_des_ede_ofb64               62

#define SN_des_ede3_ofb64               "\x44\x45\x53\x2d\x45\x44\x45\x33\x2d\x4f\x46\x42"
#define LN_des_ede3_ofb64               "\x64\x65\x73\x2d\x65\x64\x65\x33\x2d\x6f\x66\x62"
#define NID_des_ede3_ofb64              63

#define SN_desx_cbc             "\x44\x45\x53\x58\x2d\x43\x42\x43"
#define LN_desx_cbc             "\x64\x65\x73\x78\x2d\x63\x62\x63"
#define NID_desx_cbc            80

#define SN_sha          "\x53\x48\x41"
#define LN_sha          "\x73\x68\x61"
#define NID_sha         41
#define OBJ_sha         OBJ_algorithm,18L

#define SN_sha1         "\x53\x48\x41\x31"
#define LN_sha1         "\x73\x68\x61\x31"
#define NID_sha1                64
#define OBJ_sha1                OBJ_algorithm,26L

#define SN_dsaWithSHA1_2                "\x44\x53\x41\x2d\x53\x48\x41\x31\x2d\x6f\x6c\x64"
#define LN_dsaWithSHA1_2                "\x64\x73\x61\x57\x69\x74\x68\x53\x48\x41\x31\x2d\x6f\x6c\x64"
#define NID_dsaWithSHA1_2               70
#define OBJ_dsaWithSHA1_2               OBJ_algorithm,27L

#define SN_sha1WithRSA          "\x52\x53\x41\x2d\x53\x48\x41\x31\x2d\x32"
#define LN_sha1WithRSA          "\x73\x68\x61\x31\x57\x69\x74\x68\x52\x53\x41"
#define NID_sha1WithRSA         115
#define OBJ_sha1WithRSA         OBJ_algorithm,29L

#define SN_ripemd160            "\x52\x49\x50\x45\x4d\x44\x31\x36\x30"
#define LN_ripemd160            "\x72\x69\x70\x65\x6d\x64\x31\x36\x30"
#define NID_ripemd160           117
#define OBJ_ripemd160           1L,3L,36L,3L,2L,1L

#define SN_ripemd160WithRSA             "\x52\x53\x41\x2d\x52\x49\x50\x45\x4d\x44\x31\x36\x30"
#define LN_ripemd160WithRSA             "\x72\x69\x70\x65\x6d\x64\x31\x36\x30\x57\x69\x74\x68\x52\x53\x41"
#define NID_ripemd160WithRSA            119
#define OBJ_ripemd160WithRSA            1L,3L,36L,3L,3L,1L,2L

#define SN_sxnet                "\x53\x58\x4e\x65\x74\x49\x44"
#define LN_sxnet                "\x53\x74\x72\x6f\x6e\x67\x20\x45\x78\x74\x72\x61\x6e\x65\x74\x20\x49\x44"
#define NID_sxnet               143
#define OBJ_sxnet               1L,3L,101L,1L,4L,1L

#define SN_X500         "\x58\x35\x30\x30"
#define LN_X500         "\x64\x69\x72\x65\x63\x74\x6f\x72\x79\x20\x73\x65\x72\x76\x69\x63\x65\x73\x20\x28\x58\x2e\x35\x30\x30\x29"
#define NID_X500                11
#define OBJ_X500                2L,5L

#define SN_X509         "\x58\x35\x30\x39"
#define NID_X509                12
#define OBJ_X509                OBJ_X500,4L

#define SN_commonName           "\x43\x4e"
#define LN_commonName           "\x63\x6f\x6d\x6d\x6f\x6e\x4e\x61\x6d\x65"
#define NID_commonName          13
#define OBJ_commonName          OBJ_X509,3L

#define SN_surname              "\x53\x4e"
#define LN_surname              "\x73\x75\x72\x6e\x61\x6d\x65"
#define NID_surname             100
#define OBJ_surname             OBJ_X509,4L

#define LN_serialNumber         "\x73\x65\x72\x69\x61\x6c\x4e\x75\x6d\x62\x65\x72"
#define NID_serialNumber                105
#define OBJ_serialNumber                OBJ_X509,5L

#define SN_countryName          "\x43"
#define LN_countryName          "\x63\x6f\x75\x6e\x74\x72\x79\x4e\x61\x6d\x65"
#define NID_countryName         14
#define OBJ_countryName         OBJ_X509,6L

#define SN_localityName         "\x4c"
#define LN_localityName         "\x6c\x6f\x63\x61\x6c\x69\x74\x79\x4e\x61\x6d\x65"
#define NID_localityName                15
#define OBJ_localityName                OBJ_X509,7L

#define SN_stateOrProvinceName          "\x53\x54"
#define LN_stateOrProvinceName          "\x73\x74\x61\x74\x65\x4f\x72\x50\x72\x6f\x76\x69\x6e\x63\x65\x4e\x61\x6d\x65"
#define NID_stateOrProvinceName         16
#define OBJ_stateOrProvinceName         OBJ_X509,8L

#define SN_streetAddress                "\x73\x74\x72\x65\x65\x74"
#define LN_streetAddress                "\x73\x74\x72\x65\x65\x74\x41\x64\x64\x72\x65\x73\x73"
#define NID_streetAddress               660
#define OBJ_streetAddress               OBJ_X509,9L

#define SN_organizationName             "\x4f"
#define LN_organizationName             "\x6f\x72\x67\x61\x6e\x69\x7a\x61\x74\x69\x6f\x6e\x4e\x61\x6d\x65"
#define NID_organizationName            17
#define OBJ_organizationName            OBJ_X509,10L

#define SN_organizationalUnitName               "\x4f\x55"
#define LN_organizationalUnitName               "\x6f\x72\x67\x61\x6e\x69\x7a\x61\x74\x69\x6f\x6e\x61\x6c\x55\x6e\x69\x74\x4e\x61\x6d\x65"
#define NID_organizationalUnitName              18
#define OBJ_organizationalUnitName              OBJ_X509,11L

#define SN_title                "\x74\x69\x74\x6c\x65"
#define LN_title                "\x74\x69\x74\x6c\x65"
#define NID_title               106
#define OBJ_title               OBJ_X509,12L

#define LN_description          "\x64\x65\x73\x63\x72\x69\x70\x74\x69\x6f\x6e"
#define NID_description         107
#define OBJ_description         OBJ_X509,13L

#define LN_searchGuide          "\x73\x65\x61\x72\x63\x68\x47\x75\x69\x64\x65"
#define NID_searchGuide         859
#define OBJ_searchGuide         OBJ_X509,14L

#define LN_businessCategory             "\x62\x75\x73\x69\x6e\x65\x73\x73\x43\x61\x74\x65\x67\x6f\x72\x79"
#define NID_businessCategory            860
#define OBJ_businessCategory            OBJ_X509,15L

#define LN_postalAddress                "\x70\x6f\x73\x74\x61\x6c\x41\x64\x64\x72\x65\x73\x73"
#define NID_postalAddress               861
#define OBJ_postalAddress               OBJ_X509,16L

#define LN_postalCode           "\x70\x6f\x73\x74\x61\x6c\x43\x6f\x64\x65"
#define NID_postalCode          661
#define OBJ_postalCode          OBJ_X509,17L

#define LN_postOfficeBox                "\x70\x6f\x73\x74\x4f\x66\x66\x69\x63\x65\x42\x6f\x78"
#define NID_postOfficeBox               862
#define OBJ_postOfficeBox               OBJ_X509,18L

#define LN_physicalDeliveryOfficeName           "\x70\x68\x79\x73\x69\x63\x61\x6c\x44\x65\x6c\x69\x76\x65\x72\x79\x4f\x66\x66\x69\x63\x65\x4e\x61\x6d\x65"
#define NID_physicalDeliveryOfficeName          863
#define OBJ_physicalDeliveryOfficeName          OBJ_X509,19L

#define LN_telephoneNumber              "\x74\x65\x6c\x65\x70\x68\x6f\x6e\x65\x4e\x75\x6d\x62\x65\x72"
#define NID_telephoneNumber             864
#define OBJ_telephoneNumber             OBJ_X509,20L

#define LN_telexNumber          "\x74\x65\x6c\x65\x78\x4e\x75\x6d\x62\x65\x72"
#define NID_telexNumber         865
#define OBJ_telexNumber         OBJ_X509,21L

#define LN_teletexTerminalIdentifier            "\x74\x65\x6c\x65\x74\x65\x78\x54\x65\x72\x6d\x69\x6e\x61\x6c\x49\x64\x65\x6e\x74\x69\x66\x69\x65\x72"
#define NID_teletexTerminalIdentifier           866
#define OBJ_teletexTerminalIdentifier           OBJ_X509,22L

#define LN_facsimileTelephoneNumber             "\x66\x61\x63\x73\x69\x6d\x69\x6c\x65\x54\x65\x6c\x65\x70\x68\x6f\x6e\x65\x4e\x75\x6d\x62\x65\x72"
#define NID_facsimileTelephoneNumber            867
#define OBJ_facsimileTelephoneNumber            OBJ_X509,23L

#define LN_x121Address          "\x78\x31\x32\x31\x41\x64\x64\x72\x65\x73\x73"
#define NID_x121Address         868
#define OBJ_x121Address         OBJ_X509,24L

#define LN_internationaliSDNNumber              "\x69\x6e\x74\x65\x72\x6e\x61\x74\x69\x6f\x6e\x61\x6c\x69\x53\x44\x4e\x4e\x75\x6d\x62\x65\x72"
#define NID_internationaliSDNNumber             869
#define OBJ_internationaliSDNNumber             OBJ_X509,25L

#define LN_registeredAddress            "\x72\x65\x67\x69\x73\x74\x65\x72\x65\x64\x41\x64\x64\x72\x65\x73\x73"
#define NID_registeredAddress           870
#define OBJ_registeredAddress           OBJ_X509,26L

#define LN_destinationIndicator         "\x64\x65\x73\x74\x69\x6e\x61\x74\x69\x6f\x6e\x49\x6e\x64\x69\x63\x61\x74\x6f\x72"
#define NID_destinationIndicator                871
#define OBJ_destinationIndicator                OBJ_X509,27L

#define LN_preferredDeliveryMethod              "\x70\x72\x65\x66\x65\x72\x72\x65\x64\x44\x65\x6c\x69\x76\x65\x72\x79\x4d\x65\x74\x68\x6f\x64"
#define NID_preferredDeliveryMethod             872
#define OBJ_preferredDeliveryMethod             OBJ_X509,28L

#define LN_presentationAddress          "\x70\x72\x65\x73\x65\x6e\x74\x61\x74\x69\x6f\x6e\x41\x64\x64\x72\x65\x73\x73"
#define NID_presentationAddress         873
#define OBJ_presentationAddress         OBJ_X509,29L

#define LN_supportedApplicationContext          "\x73\x75\x70\x70\x6f\x72\x74\x65\x64\x41\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x43\x6f\x6e\x74\x65\x78\x74"
#define NID_supportedApplicationContext         874
#define OBJ_supportedApplicationContext         OBJ_X509,30L

#define SN_member               "\x6d\x65\x6d\x62\x65\x72"
#define NID_member              875
#define OBJ_member              OBJ_X509,31L

#define SN_owner                "\x6f\x77\x6e\x65\x72"
#define NID_owner               876
#define OBJ_owner               OBJ_X509,32L

#define LN_roleOccupant         "\x72\x6f\x6c\x65\x4f\x63\x63\x75\x70\x61\x6e\x74"
#define NID_roleOccupant                877
#define OBJ_roleOccupant                OBJ_X509,33L

#define SN_seeAlso              "\x73\x65\x65\x41\x6c\x73\x6f"
#define NID_seeAlso             878
#define OBJ_seeAlso             OBJ_X509,34L

#define LN_userPassword         "\x75\x73\x65\x72\x50\x61\x73\x73\x77\x6f\x72\x64"
#define NID_userPassword                879
#define OBJ_userPassword                OBJ_X509,35L

#define LN_userCertificate              "\x75\x73\x65\x72\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65"
#define NID_userCertificate             880
#define OBJ_userCertificate             OBJ_X509,36L

#define LN_cACertificate                "\x63\x41\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65"
#define NID_cACertificate               881
#define OBJ_cACertificate               OBJ_X509,37L

#define LN_authorityRevocationList              "\x61\x75\x74\x68\x6f\x72\x69\x74\x79\x52\x65\x76\x6f\x63\x61\x74\x69\x6f\x6e\x4c\x69\x73\x74"
#define NID_authorityRevocationList             882
#define OBJ_authorityRevocationList             OBJ_X509,38L

#define LN_certificateRevocationList            "\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x52\x65\x76\x6f\x63\x61\x74\x69\x6f\x6e\x4c\x69\x73\x74"
#define NID_certificateRevocationList           883
#define OBJ_certificateRevocationList           OBJ_X509,39L

#define LN_crossCertificatePair         "\x63\x72\x6f\x73\x73\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x50\x61\x69\x72"
#define NID_crossCertificatePair                884
#define OBJ_crossCertificatePair                OBJ_X509,40L

#define SN_name         "\x6e\x61\x6d\x65"
#define LN_name         "\x6e\x61\x6d\x65"
#define NID_name                173
#define OBJ_name                OBJ_X509,41L

#define SN_givenName            "\x47\x4e"
#define LN_givenName            "\x67\x69\x76\x65\x6e\x4e\x61\x6d\x65"
#define NID_givenName           99
#define OBJ_givenName           OBJ_X509,42L

#define SN_initials             "\x69\x6e\x69\x74\x69\x61\x6c\x73"
#define LN_initials             "\x69\x6e\x69\x74\x69\x61\x6c\x73"
#define NID_initials            101
#define OBJ_initials            OBJ_X509,43L

#define LN_generationQualifier          "\x67\x65\x6e\x65\x72\x61\x74\x69\x6f\x6e\x51\x75\x61\x6c\x69\x66\x69\x65\x72"
#define NID_generationQualifier         509
#define OBJ_generationQualifier         OBJ_X509,44L

#define LN_x500UniqueIdentifier         "\x78\x35\x30\x30\x55\x6e\x69\x71\x75\x65\x49\x64\x65\x6e\x74\x69\x66\x69\x65\x72"
#define NID_x500UniqueIdentifier                503
#define OBJ_x500UniqueIdentifier                OBJ_X509,45L

#define SN_dnQualifier          "\x64\x6e\x51\x75\x61\x6c\x69\x66\x69\x65\x72"
#define LN_dnQualifier          "\x64\x6e\x51\x75\x61\x6c\x69\x66\x69\x65\x72"
#define NID_dnQualifier         174
#define OBJ_dnQualifier         OBJ_X509,46L

#define LN_enhancedSearchGuide          "\x65\x6e\x68\x61\x6e\x63\x65\x64\x53\x65\x61\x72\x63\x68\x47\x75\x69\x64\x65"
#define NID_enhancedSearchGuide         885
#define OBJ_enhancedSearchGuide         OBJ_X509,47L

#define LN_protocolInformation          "\x70\x72\x6f\x74\x6f\x63\x6f\x6c\x49\x6e\x66\x6f\x72\x6d\x61\x74\x69\x6f\x6e"
#define NID_protocolInformation         886
#define OBJ_protocolInformation         OBJ_X509,48L

#define LN_distinguishedName            "\x64\x69\x73\x74\x69\x6e\x67\x75\x69\x73\x68\x65\x64\x4e\x61\x6d\x65"
#define NID_distinguishedName           887
#define OBJ_distinguishedName           OBJ_X509,49L

#define LN_uniqueMember         "\x75\x6e\x69\x71\x75\x65\x4d\x65\x6d\x62\x65\x72"
#define NID_uniqueMember                888
#define OBJ_uniqueMember                OBJ_X509,50L

#define LN_houseIdentifier              "\x68\x6f\x75\x73\x65\x49\x64\x65\x6e\x74\x69\x66\x69\x65\x72"
#define NID_houseIdentifier             889
#define OBJ_houseIdentifier             OBJ_X509,51L

#define LN_supportedAlgorithms          "\x73\x75\x70\x70\x6f\x72\x74\x65\x64\x41\x6c\x67\x6f\x72\x69\x74\x68\x6d\x73"
#define NID_supportedAlgorithms         890
#define OBJ_supportedAlgorithms         OBJ_X509,52L

#define LN_deltaRevocationList          "\x64\x65\x6c\x74\x61\x52\x65\x76\x6f\x63\x61\x74\x69\x6f\x6e\x4c\x69\x73\x74"
#define NID_deltaRevocationList         891
#define OBJ_deltaRevocationList         OBJ_X509,53L

#define SN_dmdName              "\x64\x6d\x64\x4e\x61\x6d\x65"
#define NID_dmdName             892
#define OBJ_dmdName             OBJ_X509,54L

#define LN_pseudonym            "\x70\x73\x65\x75\x64\x6f\x6e\x79\x6d"
#define NID_pseudonym           510
#define OBJ_pseudonym           OBJ_X509,65L

#define SN_role         "\x72\x6f\x6c\x65"
#define LN_role         "\x72\x6f\x6c\x65"
#define NID_role                400
#define OBJ_role                OBJ_X509,72L

#define SN_X500algorithms               "\x58\x35\x30\x30\x61\x6c\x67\x6f\x72\x69\x74\x68\x6d\x73"
#define LN_X500algorithms               "\x64\x69\x72\x65\x63\x74\x6f\x72\x79\x20\x73\x65\x72\x76\x69\x63\x65\x73\x20\x2d\x20\x61\x6c\x67\x6f\x72\x69\x74\x68\x6d\x73"
#define NID_X500algorithms              378
#define OBJ_X500algorithms              OBJ_X500,8L

#define SN_rsa          "\x52\x53\x41"
#define LN_rsa          "\x72\x73\x61"
#define NID_rsa         19
#define OBJ_rsa         OBJ_X500algorithms,1L,1L

#define SN_mdc2WithRSA          "\x52\x53\x41\x2d\x4d\x44\x43\x32"
#define LN_mdc2WithRSA          "\x6d\x64\x63\x32\x57\x69\x74\x68\x52\x53\x41"
#define NID_mdc2WithRSA         96
#define OBJ_mdc2WithRSA         OBJ_X500algorithms,3L,100L

#define SN_mdc2         "\x4d\x44\x43\x32"
#define LN_mdc2         "\x6d\x64\x63\x32"
#define NID_mdc2                95
#define OBJ_mdc2                OBJ_X500algorithms,3L,101L

#define SN_id_ce                "\x69\x64\x2d\x63\x65"
#define NID_id_ce               81
#define OBJ_id_ce               OBJ_X500,29L

#define SN_subject_directory_attributes         "\x73\x75\x62\x6a\x65\x63\x74\x44\x69\x72\x65\x63\x74\x6f\x72\x79\x41\x74\x74\x72\x69\x62\x75\x74\x65\x73"
#define LN_subject_directory_attributes         "\x58\x35\x30\x39\x76\x33\x20\x53\x75\x62\x6a\x65\x63\x74\x20\x44\x69\x72\x65\x63\x74\x6f\x72\x79\x20\x41\x74\x74\x72\x69\x62\x75\x74\x65\x73"
#define NID_subject_directory_attributes                769
#define OBJ_subject_directory_attributes                OBJ_id_ce,9L

#define SN_subject_key_identifier               "\x73\x75\x62\x6a\x65\x63\x74\x4b\x65\x79\x49\x64\x65\x6e\x74\x69\x66\x69\x65\x72"
#define LN_subject_key_identifier               "\x58\x35\x30\x39\x76\x33\x20\x53\x75\x62\x6a\x65\x63\x74\x20\x4b\x65\x79\x20\x49\x64\x65\x6e\x74\x69\x66\x69\x65\x72"
#define NID_subject_key_identifier              82
#define OBJ_subject_key_identifier              OBJ_id_ce,14L

#define SN_key_usage            "\x6b\x65\x79\x55\x73\x61\x67\x65"
#define LN_key_usage            "\x58\x35\x30\x39\x76\x33\x20\x4b\x65\x79\x20\x55\x73\x61\x67\x65"
#define NID_key_usage           83
#define OBJ_key_usage           OBJ_id_ce,15L

#define SN_private_key_usage_period             "\x70\x72\x69\x76\x61\x74\x65\x4b\x65\x79\x55\x73\x61\x67\x65\x50\x65\x72\x69\x6f\x64"
#define LN_private_key_usage_period             "\x58\x35\x30\x39\x76\x33\x20\x50\x72\x69\x76\x61\x74\x65\x20\x4b\x65\x79\x20\x55\x73\x61\x67\x65\x20\x50\x65\x72\x69\x6f\x64"
#define NID_private_key_usage_period            84
#define OBJ_private_key_usage_period            OBJ_id_ce,16L

#define SN_subject_alt_name             "\x73\x75\x62\x6a\x65\x63\x74\x41\x6c\x74\x4e\x61\x6d\x65"
#define LN_subject_alt_name             "\x58\x35\x30\x39\x76\x33\x20\x53\x75\x62\x6a\x65\x63\x74\x20\x41\x6c\x74\x65\x72\x6e\x61\x74\x69\x76\x65\x20\x4e\x61\x6d\x65"
#define NID_subject_alt_name            85
#define OBJ_subject_alt_name            OBJ_id_ce,17L

#define SN_issuer_alt_name              "\x69\x73\x73\x75\x65\x72\x41\x6c\x74\x4e\x61\x6d\x65"
#define LN_issuer_alt_name              "\x58\x35\x30\x39\x76\x33\x20\x49\x73\x73\x75\x65\x72\x20\x41\x6c\x74\x65\x72\x6e\x61\x74\x69\x76\x65\x20\x4e\x61\x6d\x65"
#define NID_issuer_alt_name             86
#define OBJ_issuer_alt_name             OBJ_id_ce,18L

#define SN_basic_constraints            "\x62\x61\x73\x69\x63\x43\x6f\x6e\x73\x74\x72\x61\x69\x6e\x74\x73"
#define LN_basic_constraints            "\x58\x35\x30\x39\x76\x33\x20\x42\x61\x73\x69\x63\x20\x43\x6f\x6e\x73\x74\x72\x61\x69\x6e\x74\x73"
#define NID_basic_constraints           87
#define OBJ_basic_constraints           OBJ_id_ce,19L

#define SN_crl_number           "\x63\x72\x6c\x4e\x75\x6d\x62\x65\x72"
#define LN_crl_number           "\x58\x35\x30\x39\x76\x33\x20\x43\x52\x4c\x20\x4e\x75\x6d\x62\x65\x72"
#define NID_crl_number          88
#define OBJ_crl_number          OBJ_id_ce,20L

#define SN_crl_reason           "\x43\x52\x4c\x52\x65\x61\x73\x6f\x6e"
#define LN_crl_reason           "\x58\x35\x30\x39\x76\x33\x20\x43\x52\x4c\x20\x52\x65\x61\x73\x6f\x6e\x20\x43\x6f\x64\x65"
#define NID_crl_reason          141
#define OBJ_crl_reason          OBJ_id_ce,21L

#define SN_invalidity_date              "\x69\x6e\x76\x61\x6c\x69\x64\x69\x74\x79\x44\x61\x74\x65"
#define LN_invalidity_date              "\x49\x6e\x76\x61\x6c\x69\x64\x69\x74\x79\x20\x44\x61\x74\x65"
#define NID_invalidity_date             142
#define OBJ_invalidity_date             OBJ_id_ce,24L

#define SN_delta_crl            "\x64\x65\x6c\x74\x61\x43\x52\x4c"
#define LN_delta_crl            "\x58\x35\x30\x39\x76\x33\x20\x44\x65\x6c\x74\x61\x20\x43\x52\x4c\x20\x49\x6e\x64\x69\x63\x61\x74\x6f\x72"
#define NID_delta_crl           140
#define OBJ_delta_crl           OBJ_id_ce,27L

#define SN_issuing_distribution_point           "\x69\x73\x73\x75\x69\x6e\x67\x44\x69\x73\x74\x72\x69\x62\x75\x74\x69\x6f\x6e\x50\x6f\x69\x6e\x74"
#define LN_issuing_distribution_point           "\x58\x35\x30\x39\x76\x33\x20\x49\x73\x73\x75\x69\x6e\x67\x20\x44\x69\x73\x74\x72\x75\x62\x75\x74\x69\x6f\x6e\x20\x50\x6f\x69\x6e\x74"
#define NID_issuing_distribution_point          770
#define OBJ_issuing_distribution_point          OBJ_id_ce,28L

#define SN_certificate_issuer           "\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x49\x73\x73\x75\x65\x72"
#define LN_certificate_issuer           "\x58\x35\x30\x39\x76\x33\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x49\x73\x73\x75\x65\x72"
#define NID_certificate_issuer          771
#define OBJ_certificate_issuer          OBJ_id_ce,29L

#define SN_name_constraints             "\x6e\x61\x6d\x65\x43\x6f\x6e\x73\x74\x72\x61\x69\x6e\x74\x73"
#define LN_name_constraints             "\x58\x35\x30\x39\x76\x33\x20\x4e\x61\x6d\x65\x20\x43\x6f\x6e\x73\x74\x72\x61\x69\x6e\x74\x73"
#define NID_name_constraints            666
#define OBJ_name_constraints            OBJ_id_ce,30L

#define SN_crl_distribution_points              "\x63\x72\x6c\x44\x69\x73\x74\x72\x69\x62\x75\x74\x69\x6f\x6e\x50\x6f\x69\x6e\x74\x73"
#define LN_crl_distribution_points              "\x58\x35\x30\x39\x76\x33\x20\x43\x52\x4c\x20\x44\x69\x73\x74\x72\x69\x62\x75\x74\x69\x6f\x6e\x20\x50\x6f\x69\x6e\x74\x73"
#define NID_crl_distribution_points             103
#define OBJ_crl_distribution_points             OBJ_id_ce,31L

#define SN_certificate_policies         "\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x50\x6f\x6c\x69\x63\x69\x65\x73"
#define LN_certificate_policies         "\x58\x35\x30\x39\x76\x33\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x50\x6f\x6c\x69\x63\x69\x65\x73"
#define NID_certificate_policies                89
#define OBJ_certificate_policies                OBJ_id_ce,32L

#define SN_any_policy           "\x61\x6e\x79\x50\x6f\x6c\x69\x63\x79"
#define LN_any_policy           "\x58\x35\x30\x39\x76\x33\x20\x41\x6e\x79\x20\x50\x6f\x6c\x69\x63\x79"
#define NID_any_policy          746
#define OBJ_any_policy          OBJ_certificate_policies,0L

#define SN_policy_mappings              "\x70\x6f\x6c\x69\x63\x79\x4d\x61\x70\x70\x69\x6e\x67\x73"
#define LN_policy_mappings              "\x58\x35\x30\x39\x76\x33\x20\x50\x6f\x6c\x69\x63\x79\x20\x4d\x61\x70\x70\x69\x6e\x67\x73"
#define NID_policy_mappings             747
#define OBJ_policy_mappings             OBJ_id_ce,33L

#define SN_authority_key_identifier             "\x61\x75\x74\x68\x6f\x72\x69\x74\x79\x4b\x65\x79\x49\x64\x65\x6e\x74\x69\x66\x69\x65\x72"
#define LN_authority_key_identifier             "\x58\x35\x30\x39\x76\x33\x20\x41\x75\x74\x68\x6f\x72\x69\x74\x79\x20\x4b\x65\x79\x20\x49\x64\x65\x6e\x74\x69\x66\x69\x65\x72"
#define NID_authority_key_identifier            90
#define OBJ_authority_key_identifier            OBJ_id_ce,35L

#define SN_policy_constraints           "\x70\x6f\x6c\x69\x63\x79\x43\x6f\x6e\x73\x74\x72\x61\x69\x6e\x74\x73"
#define LN_policy_constraints           "\x58\x35\x30\x39\x76\x33\x20\x50\x6f\x6c\x69\x63\x79\x20\x43\x6f\x6e\x73\x74\x72\x61\x69\x6e\x74\x73"
#define NID_policy_constraints          401
#define OBJ_policy_constraints          OBJ_id_ce,36L

#define SN_ext_key_usage                "\x65\x78\x74\x65\x6e\x64\x65\x64\x4b\x65\x79\x55\x73\x61\x67\x65"
#define LN_ext_key_usage                "\x58\x35\x30\x39\x76\x33\x20\x45\x78\x74\x65\x6e\x64\x65\x64\x20\x4b\x65\x79\x20\x55\x73\x61\x67\x65"
#define NID_ext_key_usage               126
#define OBJ_ext_key_usage               OBJ_id_ce,37L

#define SN_freshest_crl         "\x66\x72\x65\x73\x68\x65\x73\x74\x43\x52\x4c"
#define LN_freshest_crl         "\x58\x35\x30\x39\x76\x33\x20\x46\x72\x65\x73\x68\x65\x73\x74\x20\x43\x52\x4c"
#define NID_freshest_crl                857
#define OBJ_freshest_crl                OBJ_id_ce,46L

#define SN_inhibit_any_policy           "\x69\x6e\x68\x69\x62\x69\x74\x41\x6e\x79\x50\x6f\x6c\x69\x63\x79"
#define LN_inhibit_any_policy           "\x58\x35\x30\x39\x76\x33\x20\x49\x6e\x68\x69\x62\x69\x74\x20\x41\x6e\x79\x20\x50\x6f\x6c\x69\x63\x79"
#define NID_inhibit_any_policy          748
#define OBJ_inhibit_any_policy          OBJ_id_ce,54L

#define SN_target_information           "\x74\x61\x72\x67\x65\x74\x49\x6e\x66\x6f\x72\x6d\x61\x74\x69\x6f\x6e"
#define LN_target_information           "\x58\x35\x30\x39\x76\x33\x20\x41\x43\x20\x54\x61\x72\x67\x65\x74\x69\x6e\x67"
#define NID_target_information          402
#define OBJ_target_information          OBJ_id_ce,55L

#define SN_no_rev_avail         "\x6e\x6f\x52\x65\x76\x41\x76\x61\x69\x6c"
#define LN_no_rev_avail         "\x58\x35\x30\x39\x76\x33\x20\x4e\x6f\x20\x52\x65\x76\x6f\x63\x61\x74\x69\x6f\x6e\x20\x41\x76\x61\x69\x6c\x61\x62\x6c\x65"
#define NID_no_rev_avail                403
#define OBJ_no_rev_avail                OBJ_id_ce,56L

#define SN_anyExtendedKeyUsage          "\x61\x6e\x79\x45\x78\x74\x65\x6e\x64\x65\x64\x4b\x65\x79\x55\x73\x61\x67\x65"
#define LN_anyExtendedKeyUsage          "\x41\x6e\x79\x20\x45\x78\x74\x65\x6e\x64\x65\x64\x20\x4b\x65\x79\x20\x55\x73\x61\x67\x65"
#define NID_anyExtendedKeyUsage         910
#define OBJ_anyExtendedKeyUsage         OBJ_ext_key_usage,0L

#define SN_netscape             "\x4e\x65\x74\x73\x63\x61\x70\x65"
#define LN_netscape             "\x4e\x65\x74\x73\x63\x61\x70\x65\x20\x43\x6f\x6d\x6d\x75\x6e\x69\x63\x61\x74\x69\x6f\x6e\x73\x20\x43\x6f\x72\x70\x2e"
#define NID_netscape            57
#define OBJ_netscape            2L,16L,840L,1L,113730L

#define SN_netscape_cert_extension              "\x6e\x73\x43\x65\x72\x74\x45\x78\x74"
#define LN_netscape_cert_extension              "\x4e\x65\x74\x73\x63\x61\x70\x65\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x45\x78\x74\x65\x6e\x73\x69\x6f\x6e"
#define NID_netscape_cert_extension             58
#define OBJ_netscape_cert_extension             OBJ_netscape,1L

#define SN_netscape_data_type           "\x6e\x73\x44\x61\x74\x61\x54\x79\x70\x65"
#define LN_netscape_data_type           "\x4e\x65\x74\x73\x63\x61\x70\x65\x20\x44\x61\x74\x61\x20\x54\x79\x70\x65"
#define NID_netscape_data_type          59
#define OBJ_netscape_data_type          OBJ_netscape,2L

#define SN_netscape_cert_type           "\x6e\x73\x43\x65\x72\x74\x54\x79\x70\x65"
#define LN_netscape_cert_type           "\x4e\x65\x74\x73\x63\x61\x70\x65\x20\x43\x65\x72\x74\x20\x54\x79\x70\x65"
#define NID_netscape_cert_type          71
#define OBJ_netscape_cert_type          OBJ_netscape_cert_extension,1L

#define SN_netscape_base_url            "\x6e\x73\x42\x61\x73\x65\x55\x72\x6c"
#define LN_netscape_base_url            "\x4e\x65\x74\x73\x63\x61\x70\x65\x20\x42\x61\x73\x65\x20\x55\x72\x6c"
#define NID_netscape_base_url           72
#define OBJ_netscape_base_url           OBJ_netscape_cert_extension,2L

#define SN_netscape_revocation_url              "\x6e\x73\x52\x65\x76\x6f\x63\x61\x74\x69\x6f\x6e\x55\x72\x6c"
#define LN_netscape_revocation_url              "\x4e\x65\x74\x73\x63\x61\x70\x65\x20\x52\x65\x76\x6f\x63\x61\x74\x69\x6f\x6e\x20\x55\x72\x6c"
#define NID_netscape_revocation_url             73
#define OBJ_netscape_revocation_url             OBJ_netscape_cert_extension,3L

#define SN_netscape_ca_revocation_url           "\x6e\x73\x43\x61\x52\x65\x76\x6f\x63\x61\x74\x69\x6f\x6e\x55\x72\x6c"
#define LN_netscape_ca_revocation_url           "\x4e\x65\x74\x73\x63\x61\x70\x65\x20\x43\x41\x20\x52\x65\x76\x6f\x63\x61\x74\x69\x6f\x6e\x20\x55\x72\x6c"
#define NID_netscape_ca_revocation_url          74
#define OBJ_netscape_ca_revocation_url          OBJ_netscape_cert_extension,4L

#define SN_netscape_renewal_url         "\x6e\x73\x52\x65\x6e\x65\x77\x61\x6c\x55\x72\x6c"
#define LN_netscape_renewal_url         "\x4e\x65\x74\x73\x63\x61\x70\x65\x20\x52\x65\x6e\x65\x77\x61\x6c\x20\x55\x72\x6c"
#define NID_netscape_renewal_url                75
#define OBJ_netscape_renewal_url                OBJ_netscape_cert_extension,7L

#define SN_netscape_ca_policy_url               "\x6e\x73\x43\x61\x50\x6f\x6c\x69\x63\x79\x55\x72\x6c"
#define LN_netscape_ca_policy_url               "\x4e\x65\x74\x73\x63\x61\x70\x65\x20\x43\x41\x20\x50\x6f\x6c\x69\x63\x79\x20\x55\x72\x6c"
#define NID_netscape_ca_policy_url              76
#define OBJ_netscape_ca_policy_url              OBJ_netscape_cert_extension,8L

#define SN_netscape_ssl_server_name             "\x6e\x73\x53\x73\x6c\x53\x65\x72\x76\x65\x72\x4e\x61\x6d\x65"
#define LN_netscape_ssl_server_name             "\x4e\x65\x74\x73\x63\x61\x70\x65\x20\x53\x53\x4c\x20\x53\x65\x72\x76\x65\x72\x20\x4e\x61\x6d\x65"
#define NID_netscape_ssl_server_name            77
#define OBJ_netscape_ssl_server_name            OBJ_netscape_cert_extension,12L

#define SN_netscape_comment             "\x6e\x73\x43\x6f\x6d\x6d\x65\x6e\x74"
#define LN_netscape_comment             "\x4e\x65\x74\x73\x63\x61\x70\x65\x20\x43\x6f\x6d\x6d\x65\x6e\x74"
#define NID_netscape_comment            78
#define OBJ_netscape_comment            OBJ_netscape_cert_extension,13L

#define SN_netscape_cert_sequence               "\x6e\x73\x43\x65\x72\x74\x53\x65\x71\x75\x65\x6e\x63\x65"
#define LN_netscape_cert_sequence               "\x4e\x65\x74\x73\x63\x61\x70\x65\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x53\x65\x71\x75\x65\x6e\x63\x65"
#define NID_netscape_cert_sequence              79
#define OBJ_netscape_cert_sequence              OBJ_netscape_data_type,5L

#define SN_ns_sgc               "\x6e\x73\x53\x47\x43"
#define LN_ns_sgc               "\x4e\x65\x74\x73\x63\x61\x70\x65\x20\x53\x65\x72\x76\x65\x72\x20\x47\x61\x74\x65\x64\x20\x43\x72\x79\x70\x74\x6f"
#define NID_ns_sgc              139
#define OBJ_ns_sgc              OBJ_netscape,4L,1L

#define SN_org          "\x4f\x52\x47"
#define LN_org          "\x6f\x72\x67"
#define NID_org         379
#define OBJ_org         OBJ_iso,3L

#define SN_dod          "\x44\x4f\x44"
#define LN_dod          "\x64\x6f\x64"
#define NID_dod         380
#define OBJ_dod         OBJ_org,6L

#define SN_iana         "\x49\x41\x4e\x41"
#define LN_iana         "\x69\x61\x6e\x61"
#define NID_iana                381
#define OBJ_iana                OBJ_dod,1L

#define OBJ_internet            OBJ_iana

#define SN_Directory            "\x64\x69\x72\x65\x63\x74\x6f\x72\x79"
#define LN_Directory            "\x44\x69\x72\x65\x63\x74\x6f\x72\x79"
#define NID_Directory           382
#define OBJ_Directory           OBJ_internet,1L

#define SN_Management           "\x6d\x67\x6d\x74"
#define LN_Management           "\x4d\x61\x6e\x61\x67\x65\x6d\x65\x6e\x74"
#define NID_Management          383
#define OBJ_Management          OBJ_internet,2L

#define SN_Experimental         "\x65\x78\x70\x65\x72\x69\x6d\x65\x6e\x74\x61\x6c"
#define LN_Experimental         "\x45\x78\x70\x65\x72\x69\x6d\x65\x6e\x74\x61\x6c"
#define NID_Experimental                384
#define OBJ_Experimental                OBJ_internet,3L

#define SN_Private              "\x70\x72\x69\x76\x61\x74\x65"
#define LN_Private              "\x50\x72\x69\x76\x61\x74\x65"
#define NID_Private             385
#define OBJ_Private             OBJ_internet,4L

#define SN_Security             "\x73\x65\x63\x75\x72\x69\x74\x79"
#define LN_Security             "\x53\x65\x63\x75\x72\x69\x74\x79"
#define NID_Security            386
#define OBJ_Security            OBJ_internet,5L

#define SN_SNMPv2               "\x73\x6e\x6d\x70\x76\x32"
#define LN_SNMPv2               "\x53\x4e\x4d\x50\x76\x32"
#define NID_SNMPv2              387
#define OBJ_SNMPv2              OBJ_internet,6L

#define LN_Mail         "\x4d\x61\x69\x6c"
#define NID_Mail                388
#define OBJ_Mail                OBJ_internet,7L

#define SN_Enterprises          "\x65\x6e\x74\x65\x72\x70\x72\x69\x73\x65\x73"
#define LN_Enterprises          "\x45\x6e\x74\x65\x72\x70\x72\x69\x73\x65\x73"
#define NID_Enterprises         389
#define OBJ_Enterprises         OBJ_Private,1L

#define SN_dcObject             "\x64\x63\x6f\x62\x6a\x65\x63\x74"
#define LN_dcObject             "\x64\x63\x4f\x62\x6a\x65\x63\x74"
#define NID_dcObject            390
#define OBJ_dcObject            OBJ_Enterprises,1466L,344L

#define SN_mime_mhs             "\x6d\x69\x6d\x65\x2d\x6d\x68\x73"
#define LN_mime_mhs             "\x4d\x49\x4d\x45\x20\x4d\x48\x53"
#define NID_mime_mhs            504
#define OBJ_mime_mhs            OBJ_Mail,1L

#define SN_mime_mhs_headings            "\x6d\x69\x6d\x65\x2d\x6d\x68\x73\x2d\x68\x65\x61\x64\x69\x6e\x67\x73"
#define LN_mime_mhs_headings            "\x6d\x69\x6d\x65\x2d\x6d\x68\x73\x2d\x68\x65\x61\x64\x69\x6e\x67\x73"
#define NID_mime_mhs_headings           505
#define OBJ_mime_mhs_headings           OBJ_mime_mhs,1L

#define SN_mime_mhs_bodies              "\x6d\x69\x6d\x65\x2d\x6d\x68\x73\x2d\x62\x6f\x64\x69\x65\x73"
#define LN_mime_mhs_bodies              "\x6d\x69\x6d\x65\x2d\x6d\x68\x73\x2d\x62\x6f\x64\x69\x65\x73"
#define NID_mime_mhs_bodies             506
#define OBJ_mime_mhs_bodies             OBJ_mime_mhs,2L

#define SN_id_hex_partial_message               "\x69\x64\x2d\x68\x65\x78\x2d\x70\x61\x72\x74\x69\x61\x6c\x2d\x6d\x65\x73\x73\x61\x67\x65"
#define LN_id_hex_partial_message               "\x69\x64\x2d\x68\x65\x78\x2d\x70\x61\x72\x74\x69\x61\x6c\x2d\x6d\x65\x73\x73\x61\x67\x65"
#define NID_id_hex_partial_message              507
#define OBJ_id_hex_partial_message              OBJ_mime_mhs_headings,1L

#define SN_id_hex_multipart_message             "\x69\x64\x2d\x68\x65\x78\x2d\x6d\x75\x6c\x74\x69\x70\x61\x72\x74\x2d\x6d\x65\x73\x73\x61\x67\x65"
#define LN_id_hex_multipart_message             "\x69\x64\x2d\x68\x65\x78\x2d\x6d\x75\x6c\x74\x69\x70\x61\x72\x74\x2d\x6d\x65\x73\x73\x61\x67\x65"
#define NID_id_hex_multipart_message            508
#define OBJ_id_hex_multipart_message            OBJ_mime_mhs_headings,2L

#define SN_rle_compression              "\x52\x4c\x45"
#define LN_rle_compression              "\x72\x75\x6e\x20\x6c\x65\x6e\x67\x74\x68\x20\x63\x6f\x6d\x70\x72\x65\x73\x73\x69\x6f\x6e"
#define NID_rle_compression             124
#define OBJ_rle_compression             1L,1L,1L,1L,666L,1L

#define SN_zlib_compression             "\x5a\x4c\x49\x42"
#define LN_zlib_compression             "\x7a\x6c\x69\x62\x20\x63\x6f\x6d\x70\x72\x65\x73\x73\x69\x6f\x6e"
#define NID_zlib_compression            125
#define OBJ_zlib_compression            OBJ_id_smime_alg,8L

#define OBJ_csor                2L,16L,840L,1L,101L,3L

#define OBJ_nistAlgorithms              OBJ_csor,4L

#define OBJ_aes         OBJ_nistAlgorithms,1L

#define SN_aes_128_ecb          "\x41\x45\x53\x2d\x31\x32\x38\x2d\x45\x43\x42"
#define LN_aes_128_ecb          "\x61\x65\x73\x2d\x31\x32\x38\x2d\x65\x63\x62"
#define NID_aes_128_ecb         418
#define OBJ_aes_128_ecb         OBJ_aes,1L

#define SN_aes_128_cbc          "\x41\x45\x53\x2d\x31\x32\x38\x2d\x43\x42\x43"
#define LN_aes_128_cbc          "\x61\x65\x73\x2d\x31\x32\x38\x2d\x63\x62\x63"
#define NID_aes_128_cbc         419
#define OBJ_aes_128_cbc         OBJ_aes,2L

#define SN_aes_128_ofb128               "\x41\x45\x53\x2d\x31\x32\x38\x2d\x4f\x46\x42"
#define LN_aes_128_ofb128               "\x61\x65\x73\x2d\x31\x32\x38\x2d\x6f\x66\x62"
#define NID_aes_128_ofb128              420
#define OBJ_aes_128_ofb128              OBJ_aes,3L

#define SN_aes_128_cfb128               "\x41\x45\x53\x2d\x31\x32\x38\x2d\x43\x46\x42"
#define LN_aes_128_cfb128               "\x61\x65\x73\x2d\x31\x32\x38\x2d\x63\x66\x62"
#define NID_aes_128_cfb128              421
#define OBJ_aes_128_cfb128              OBJ_aes,4L

#define SN_id_aes128_wrap               "\x69\x64\x2d\x61\x65\x73\x31\x32\x38\x2d\x77\x72\x61\x70"
#define NID_id_aes128_wrap              788
#define OBJ_id_aes128_wrap              OBJ_aes,5L

#define SN_aes_128_gcm          "\x69\x64\x2d\x61\x65\x73\x31\x32\x38\x2d\x47\x43\x4d"
#define LN_aes_128_gcm          "\x61\x65\x73\x2d\x31\x32\x38\x2d\x67\x63\x6d"
#define NID_aes_128_gcm         895
#define OBJ_aes_128_gcm         OBJ_aes,6L

#define SN_aes_128_ccm          "\x69\x64\x2d\x61\x65\x73\x31\x32\x38\x2d\x43\x43\x4d"
#define LN_aes_128_ccm          "\x61\x65\x73\x2d\x31\x32\x38\x2d\x63\x63\x6d"
#define NID_aes_128_ccm         896
#define OBJ_aes_128_ccm         OBJ_aes,7L

#define SN_id_aes128_wrap_pad           "\x69\x64\x2d\x61\x65\x73\x31\x32\x38\x2d\x77\x72\x61\x70\x2d\x70\x61\x64"
#define NID_id_aes128_wrap_pad          897
#define OBJ_id_aes128_wrap_pad          OBJ_aes,8L

#define SN_aes_192_ecb          "\x41\x45\x53\x2d\x31\x39\x32\x2d\x45\x43\x42"
#define LN_aes_192_ecb          "\x61\x65\x73\x2d\x31\x39\x32\x2d\x65\x63\x62"
#define NID_aes_192_ecb         422
#define OBJ_aes_192_ecb         OBJ_aes,21L

#define SN_aes_192_cbc          "\x41\x45\x53\x2d\x31\x39\x32\x2d\x43\x42\x43"
#define LN_aes_192_cbc          "\x61\x65\x73\x2d\x31\x39\x32\x2d\x63\x62\x63"
#define NID_aes_192_cbc         423
#define OBJ_aes_192_cbc         OBJ_aes,22L

#define SN_aes_192_ofb128               "\x41\x45\x53\x2d\x31\x39\x32\x2d\x4f\x46\x42"
#define LN_aes_192_ofb128               "\x61\x65\x73\x2d\x31\x39\x32\x2d\x6f\x66\x62"
#define NID_aes_192_ofb128              424
#define OBJ_aes_192_ofb128              OBJ_aes,23L

#define SN_aes_192_cfb128               "\x41\x45\x53\x2d\x31\x39\x32\x2d\x43\x46\x42"
#define LN_aes_192_cfb128               "\x61\x65\x73\x2d\x31\x39\x32\x2d\x63\x66\x62"
#define NID_aes_192_cfb128              425
#define OBJ_aes_192_cfb128              OBJ_aes,24L

#define SN_id_aes192_wrap               "\x69\x64\x2d\x61\x65\x73\x31\x39\x32\x2d\x77\x72\x61\x70"
#define NID_id_aes192_wrap              789
#define OBJ_id_aes192_wrap              OBJ_aes,25L

#define SN_aes_192_gcm          "\x69\x64\x2d\x61\x65\x73\x31\x39\x32\x2d\x47\x43\x4d"
#define LN_aes_192_gcm          "\x61\x65\x73\x2d\x31\x39\x32\x2d\x67\x63\x6d"
#define NID_aes_192_gcm         898
#define OBJ_aes_192_gcm         OBJ_aes,26L

#define SN_aes_192_ccm          "\x69\x64\x2d\x61\x65\x73\x31\x39\x32\x2d\x43\x43\x4d"
#define LN_aes_192_ccm          "\x61\x65\x73\x2d\x31\x39\x32\x2d\x63\x63\x6d"
#define NID_aes_192_ccm         899
#define OBJ_aes_192_ccm         OBJ_aes,27L

#define SN_id_aes192_wrap_pad           "\x69\x64\x2d\x61\x65\x73\x31\x39\x32\x2d\x77\x72\x61\x70\x2d\x70\x61\x64"
#define NID_id_aes192_wrap_pad          900
#define OBJ_id_aes192_wrap_pad          OBJ_aes,28L

#define SN_aes_256_ecb          "\x41\x45\x53\x2d\x32\x35\x36\x2d\x45\x43\x42"
#define LN_aes_256_ecb          "\x61\x65\x73\x2d\x32\x35\x36\x2d\x65\x63\x62"
#define NID_aes_256_ecb         426
#define OBJ_aes_256_ecb         OBJ_aes,41L

#define SN_aes_256_cbc          "\x41\x45\x53\x2d\x32\x35\x36\x2d\x43\x42\x43"
#define LN_aes_256_cbc          "\x61\x65\x73\x2d\x32\x35\x36\x2d\x63\x62\x63"
#define NID_aes_256_cbc         427
#define OBJ_aes_256_cbc         OBJ_aes,42L

#define SN_aes_256_ofb128               "\x41\x45\x53\x2d\x32\x35\x36\x2d\x4f\x46\x42"
#define LN_aes_256_ofb128               "\x61\x65\x73\x2d\x32\x35\x36\x2d\x6f\x66\x62"
#define NID_aes_256_ofb128              428
#define OBJ_aes_256_ofb128              OBJ_aes,43L

#define SN_aes_256_cfb128               "\x41\x45\x53\x2d\x32\x35\x36\x2d\x43\x46\x42"
#define LN_aes_256_cfb128               "\x61\x65\x73\x2d\x32\x35\x36\x2d\x63\x66\x62"
#define NID_aes_256_cfb128              429
#define OBJ_aes_256_cfb128              OBJ_aes,44L

#define SN_id_aes256_wrap               "\x69\x64\x2d\x61\x65\x73\x32\x35\x36\x2d\x77\x72\x61\x70"
#define NID_id_aes256_wrap              790
#define OBJ_id_aes256_wrap              OBJ_aes,45L

#define SN_aes_256_gcm          "\x69\x64\x2d\x61\x65\x73\x32\x35\x36\x2d\x47\x43\x4d"
#define LN_aes_256_gcm          "\x61\x65\x73\x2d\x32\x35\x36\x2d\x67\x63\x6d"
#define NID_aes_256_gcm         901
#define OBJ_aes_256_gcm         OBJ_aes,46L

#define SN_aes_256_ccm          "\x69\x64\x2d\x61\x65\x73\x32\x35\x36\x2d\x43\x43\x4d"
#define LN_aes_256_ccm          "\x61\x65\x73\x2d\x32\x35\x36\x2d\x63\x63\x6d"
#define NID_aes_256_ccm         902
#define OBJ_aes_256_ccm         OBJ_aes,47L

#define SN_id_aes256_wrap_pad           "\x69\x64\x2d\x61\x65\x73\x32\x35\x36\x2d\x77\x72\x61\x70\x2d\x70\x61\x64"
#define NID_id_aes256_wrap_pad          903
#define OBJ_id_aes256_wrap_pad          OBJ_aes,48L

#define SN_aes_128_cfb1         "\x41\x45\x53\x2d\x31\x32\x38\x2d\x43\x46\x42\x31"
#define LN_aes_128_cfb1         "\x61\x65\x73\x2d\x31\x32\x38\x2d\x63\x66\x62\x31"
#define NID_aes_128_cfb1                650

#define SN_aes_192_cfb1         "\x41\x45\x53\x2d\x31\x39\x32\x2d\x43\x46\x42\x31"
#define LN_aes_192_cfb1         "\x61\x65\x73\x2d\x31\x39\x32\x2d\x63\x66\x62\x31"
#define NID_aes_192_cfb1                651

#define SN_aes_256_cfb1         "\x41\x45\x53\x2d\x32\x35\x36\x2d\x43\x46\x42\x31"
#define LN_aes_256_cfb1         "\x61\x65\x73\x2d\x32\x35\x36\x2d\x63\x66\x62\x31"
#define NID_aes_256_cfb1                652

#define SN_aes_128_cfb8         "\x41\x45\x53\x2d\x31\x32\x38\x2d\x43\x46\x42\x38"
#define LN_aes_128_cfb8         "\x61\x65\x73\x2d\x31\x32\x38\x2d\x63\x66\x62\x38"
#define NID_aes_128_cfb8                653

#define SN_aes_192_cfb8         "\x41\x45\x53\x2d\x31\x39\x32\x2d\x43\x46\x42\x38"
#define LN_aes_192_cfb8         "\x61\x65\x73\x2d\x31\x39\x32\x2d\x63\x66\x62\x38"
#define NID_aes_192_cfb8                654

#define SN_aes_256_cfb8         "\x41\x45\x53\x2d\x32\x35\x36\x2d\x43\x46\x42\x38"
#define LN_aes_256_cfb8         "\x61\x65\x73\x2d\x32\x35\x36\x2d\x63\x66\x62\x38"
#define NID_aes_256_cfb8                655

#define SN_aes_128_ctr          "\x41\x45\x53\x2d\x31\x32\x38\x2d\x43\x54\x52"
#define LN_aes_128_ctr          "\x61\x65\x73\x2d\x31\x32\x38\x2d\x63\x74\x72"
#define NID_aes_128_ctr         904

#define SN_aes_192_ctr          "\x41\x45\x53\x2d\x31\x39\x32\x2d\x43\x54\x52"
#define LN_aes_192_ctr          "\x61\x65\x73\x2d\x31\x39\x32\x2d\x63\x74\x72"
#define NID_aes_192_ctr         905

#define SN_aes_256_ctr          "\x41\x45\x53\x2d\x32\x35\x36\x2d\x43\x54\x52"
#define LN_aes_256_ctr          "\x61\x65\x73\x2d\x32\x35\x36\x2d\x63\x74\x72"
#define NID_aes_256_ctr         906

#define SN_aes_128_xts          "\x41\x45\x53\x2d\x31\x32\x38\x2d\x58\x54\x53"
#define LN_aes_128_xts          "\x61\x65\x73\x2d\x31\x32\x38\x2d\x78\x74\x73"
#define NID_aes_128_xts         913

#define SN_aes_256_xts          "\x41\x45\x53\x2d\x32\x35\x36\x2d\x58\x54\x53"
#define LN_aes_256_xts          "\x61\x65\x73\x2d\x32\x35\x36\x2d\x78\x74\x73"
#define NID_aes_256_xts         914

#define SN_des_cfb1             "\x44\x45\x53\x2d\x43\x46\x42\x31"
#define LN_des_cfb1             "\x64\x65\x73\x2d\x63\x66\x62\x31"
#define NID_des_cfb1            656

#define SN_des_cfb8             "\x44\x45\x53\x2d\x43\x46\x42\x38"
#define LN_des_cfb8             "\x64\x65\x73\x2d\x63\x66\x62\x38"
#define NID_des_cfb8            657

#define SN_des_ede3_cfb1                "\x44\x45\x53\x2d\x45\x44\x45\x33\x2d\x43\x46\x42\x31"
#define LN_des_ede3_cfb1                "\x64\x65\x73\x2d\x65\x64\x65\x33\x2d\x63\x66\x62\x31"
#define NID_des_ede3_cfb1               658

#define SN_des_ede3_cfb8                "\x44\x45\x53\x2d\x45\x44\x45\x33\x2d\x43\x46\x42\x38"
#define LN_des_ede3_cfb8                "\x64\x65\x73\x2d\x65\x64\x65\x33\x2d\x63\x66\x62\x38"
#define NID_des_ede3_cfb8               659

#define OBJ_nist_hashalgs               OBJ_nistAlgorithms,2L

#define SN_sha256               "\x53\x48\x41\x32\x35\x36"
#define LN_sha256               "\x73\x68\x61\x32\x35\x36"
#define NID_sha256              672
#define OBJ_sha256              OBJ_nist_hashalgs,1L

#define SN_sha384               "\x53\x48\x41\x33\x38\x34"
#define LN_sha384               "\x73\x68\x61\x33\x38\x34"
#define NID_sha384              673
#define OBJ_sha384              OBJ_nist_hashalgs,2L

#define SN_sha512               "\x53\x48\x41\x35\x31\x32"
#define LN_sha512               "\x73\x68\x61\x35\x31\x32"
#define NID_sha512              674
#define OBJ_sha512              OBJ_nist_hashalgs,3L

#define SN_sha224               "\x53\x48\x41\x32\x32\x34"
#define LN_sha224               "\x73\x68\x61\x32\x32\x34"
#define NID_sha224              675
#define OBJ_sha224              OBJ_nist_hashalgs,4L

#define OBJ_dsa_with_sha2               OBJ_nistAlgorithms,3L

#define SN_dsa_with_SHA224              "\x64\x73\x61\x5f\x77\x69\x74\x68\x5f\x53\x48\x41\x32\x32\x34"
#define NID_dsa_with_SHA224             802
#define OBJ_dsa_with_SHA224             OBJ_dsa_with_sha2,1L

#define SN_dsa_with_SHA256              "\x64\x73\x61\x5f\x77\x69\x74\x68\x5f\x53\x48\x41\x32\x35\x36"
#define NID_dsa_with_SHA256             803
#define OBJ_dsa_with_SHA256             OBJ_dsa_with_sha2,2L

#define SN_hold_instruction_code                "\x68\x6f\x6c\x64\x49\x6e\x73\x74\x72\x75\x63\x74\x69\x6f\x6e\x43\x6f\x64\x65"
#define LN_hold_instruction_code                "\x48\x6f\x6c\x64\x20\x49\x6e\x73\x74\x72\x75\x63\x74\x69\x6f\x6e\x20\x43\x6f\x64\x65"
#define NID_hold_instruction_code               430
#define OBJ_hold_instruction_code               OBJ_id_ce,23L

#define OBJ_holdInstruction             OBJ_X9_57,2L

#define SN_hold_instruction_none                "\x68\x6f\x6c\x64\x49\x6e\x73\x74\x72\x75\x63\x74\x69\x6f\x6e\x4e\x6f\x6e\x65"
#define LN_hold_instruction_none                "\x48\x6f\x6c\x64\x20\x49\x6e\x73\x74\x72\x75\x63\x74\x69\x6f\x6e\x20\x4e\x6f\x6e\x65"
#define NID_hold_instruction_none               431
#define OBJ_hold_instruction_none               OBJ_holdInstruction,1L

#define SN_hold_instruction_call_issuer         "\x68\x6f\x6c\x64\x49\x6e\x73\x74\x72\x75\x63\x74\x69\x6f\x6e\x43\x61\x6c\x6c\x49\x73\x73\x75\x65\x72"
#define LN_hold_instruction_call_issuer         "\x48\x6f\x6c\x64\x20\x49\x6e\x73\x74\x72\x75\x63\x74\x69\x6f\x6e\x20\x43\x61\x6c\x6c\x20\x49\x73\x73\x75\x65\x72"
#define NID_hold_instruction_call_issuer                432
#define OBJ_hold_instruction_call_issuer                OBJ_holdInstruction,2L

#define SN_hold_instruction_reject              "\x68\x6f\x6c\x64\x49\x6e\x73\x74\x72\x75\x63\x74\x69\x6f\x6e\x52\x65\x6a\x65\x63\x74"
#define LN_hold_instruction_reject              "\x48\x6f\x6c\x64\x20\x49\x6e\x73\x74\x72\x75\x63\x74\x69\x6f\x6e\x20\x52\x65\x6a\x65\x63\x74"
#define NID_hold_instruction_reject             433
#define OBJ_hold_instruction_reject             OBJ_holdInstruction,3L

#define SN_data         "\x64\x61\x74\x61"
#define NID_data                434
#define OBJ_data                OBJ_itu_t,9L

#define SN_pss          "\x70\x73\x73"
#define NID_pss         435
#define OBJ_pss         OBJ_data,2342L

#define SN_ucl          "\x75\x63\x6c"
#define NID_ucl         436
#define OBJ_ucl         OBJ_pss,19200300L

#define SN_pilot                "\x70\x69\x6c\x6f\x74"
#define NID_pilot               437
#define OBJ_pilot               OBJ_ucl,100L

#define LN_pilotAttributeType           "\x70\x69\x6c\x6f\x74\x41\x74\x74\x72\x69\x62\x75\x74\x65\x54\x79\x70\x65"
#define NID_pilotAttributeType          438
#define OBJ_pilotAttributeType          OBJ_pilot,1L

#define LN_pilotAttributeSyntax         "\x70\x69\x6c\x6f\x74\x41\x74\x74\x72\x69\x62\x75\x74\x65\x53\x79\x6e\x74\x61\x78"
#define NID_pilotAttributeSyntax                439
#define OBJ_pilotAttributeSyntax                OBJ_pilot,3L

#define LN_pilotObjectClass             "\x70\x69\x6c\x6f\x74\x4f\x62\x6a\x65\x63\x74\x43\x6c\x61\x73\x73"
#define NID_pilotObjectClass            440
#define OBJ_pilotObjectClass            OBJ_pilot,4L

#define LN_pilotGroups          "\x70\x69\x6c\x6f\x74\x47\x72\x6f\x75\x70\x73"
#define NID_pilotGroups         441
#define OBJ_pilotGroups         OBJ_pilot,10L

#define LN_iA5StringSyntax              "\x69\x41\x35\x53\x74\x72\x69\x6e\x67\x53\x79\x6e\x74\x61\x78"
#define NID_iA5StringSyntax             442
#define OBJ_iA5StringSyntax             OBJ_pilotAttributeSyntax,4L

#define LN_caseIgnoreIA5StringSyntax            "\x63\x61\x73\x65\x49\x67\x6e\x6f\x72\x65\x49\x41\x35\x53\x74\x72\x69\x6e\x67\x53\x79\x6e\x74\x61\x78"
#define NID_caseIgnoreIA5StringSyntax           443
#define OBJ_caseIgnoreIA5StringSyntax           OBJ_pilotAttributeSyntax,5L

#define LN_pilotObject          "\x70\x69\x6c\x6f\x74\x4f\x62\x6a\x65\x63\x74"
#define NID_pilotObject         444
#define OBJ_pilotObject         OBJ_pilotObjectClass,3L

#define LN_pilotPerson          "\x70\x69\x6c\x6f\x74\x50\x65\x72\x73\x6f\x6e"
#define NID_pilotPerson         445
#define OBJ_pilotPerson         OBJ_pilotObjectClass,4L

#define SN_account              "\x61\x63\x63\x6f\x75\x6e\x74"
#define NID_account             446
#define OBJ_account             OBJ_pilotObjectClass,5L

#define SN_document             "\x64\x6f\x63\x75\x6d\x65\x6e\x74"
#define NID_document            447
#define OBJ_document            OBJ_pilotObjectClass,6L

#define SN_room         "\x72\x6f\x6f\x6d"
#define NID_room                448
#define OBJ_room                OBJ_pilotObjectClass,7L

#define LN_documentSeries               "\x64\x6f\x63\x75\x6d\x65\x6e\x74\x53\x65\x72\x69\x65\x73"
#define NID_documentSeries              449
#define OBJ_documentSeries              OBJ_pilotObjectClass,9L

#define SN_Domain               "\x64\x6f\x6d\x61\x69\x6e"
#define LN_Domain               "\x44\x6f\x6d\x61\x69\x6e"
#define NID_Domain              392
#define OBJ_Domain              OBJ_pilotObjectClass,13L

#define LN_rFC822localPart              "\x72\x46\x43\x38\x32\x32\x6c\x6f\x63\x61\x6c\x50\x61\x72\x74"
#define NID_rFC822localPart             450
#define OBJ_rFC822localPart             OBJ_pilotObjectClass,14L

#define LN_dNSDomain            "\x64\x4e\x53\x44\x6f\x6d\x61\x69\x6e"
#define NID_dNSDomain           451
#define OBJ_dNSDomain           OBJ_pilotObjectClass,15L

#define LN_domainRelatedObject          "\x64\x6f\x6d\x61\x69\x6e\x52\x65\x6c\x61\x74\x65\x64\x4f\x62\x6a\x65\x63\x74"
#define NID_domainRelatedObject         452
#define OBJ_domainRelatedObject         OBJ_pilotObjectClass,17L

#define LN_friendlyCountry              "\x66\x72\x69\x65\x6e\x64\x6c\x79\x43\x6f\x75\x6e\x74\x72\x79"
#define NID_friendlyCountry             453
#define OBJ_friendlyCountry             OBJ_pilotObjectClass,18L

#define LN_simpleSecurityObject         "\x73\x69\x6d\x70\x6c\x65\x53\x65\x63\x75\x72\x69\x74\x79\x4f\x62\x6a\x65\x63\x74"
#define NID_simpleSecurityObject                454
#define OBJ_simpleSecurityObject                OBJ_pilotObjectClass,19L

#define LN_pilotOrganization            "\x70\x69\x6c\x6f\x74\x4f\x72\x67\x61\x6e\x69\x7a\x61\x74\x69\x6f\x6e"
#define NID_pilotOrganization           455
#define OBJ_pilotOrganization           OBJ_pilotObjectClass,20L

#define LN_pilotDSA             "\x70\x69\x6c\x6f\x74\x44\x53\x41"
#define NID_pilotDSA            456
#define OBJ_pilotDSA            OBJ_pilotObjectClass,21L

#define LN_qualityLabelledData          "\x71\x75\x61\x6c\x69\x74\x79\x4c\x61\x62\x65\x6c\x6c\x65\x64\x44\x61\x74\x61"
#define NID_qualityLabelledData         457
#define OBJ_qualityLabelledData         OBJ_pilotObjectClass,22L

#define SN_userId               "\x55\x49\x44"
#define LN_userId               "\x75\x73\x65\x72\x49\x64"
#define NID_userId              458
#define OBJ_userId              OBJ_pilotAttributeType,1L

#define LN_textEncodedORAddress         "\x74\x65\x78\x74\x45\x6e\x63\x6f\x64\x65\x64\x4f\x52\x41\x64\x64\x72\x65\x73\x73"
#define NID_textEncodedORAddress                459
#define OBJ_textEncodedORAddress                OBJ_pilotAttributeType,2L

#define SN_rfc822Mailbox                "\x6d\x61\x69\x6c"
#define LN_rfc822Mailbox                "\x72\x66\x63\x38\x32\x32\x4d\x61\x69\x6c\x62\x6f\x78"
#define NID_rfc822Mailbox               460
#define OBJ_rfc822Mailbox               OBJ_pilotAttributeType,3L

#define SN_info         "\x69\x6e\x66\x6f"
#define NID_info                461
#define OBJ_info                OBJ_pilotAttributeType,4L

#define LN_favouriteDrink               "\x66\x61\x76\x6f\x75\x72\x69\x74\x65\x44\x72\x69\x6e\x6b"
#define NID_favouriteDrink              462
#define OBJ_favouriteDrink              OBJ_pilotAttributeType,5L

#define LN_roomNumber           "\x72\x6f\x6f\x6d\x4e\x75\x6d\x62\x65\x72"
#define NID_roomNumber          463
#define OBJ_roomNumber          OBJ_pilotAttributeType,6L

#define SN_photo                "\x70\x68\x6f\x74\x6f"
#define NID_photo               464
#define OBJ_photo               OBJ_pilotAttributeType,7L

#define LN_userClass            "\x75\x73\x65\x72\x43\x6c\x61\x73\x73"
#define NID_userClass           465
#define OBJ_userClass           OBJ_pilotAttributeType,8L

#define SN_host         "\x68\x6f\x73\x74"
#define NID_host                466
#define OBJ_host                OBJ_pilotAttributeType,9L

#define SN_manager              "\x6d\x61\x6e\x61\x67\x65\x72"
#define NID_manager             467
#define OBJ_manager             OBJ_pilotAttributeType,10L

#define LN_documentIdentifier           "\x64\x6f\x63\x75\x6d\x65\x6e\x74\x49\x64\x65\x6e\x74\x69\x66\x69\x65\x72"
#define NID_documentIdentifier          468
#define OBJ_documentIdentifier          OBJ_pilotAttributeType,11L

#define LN_documentTitle                "\x64\x6f\x63\x75\x6d\x65\x6e\x74\x54\x69\x74\x6c\x65"
#define NID_documentTitle               469
#define OBJ_documentTitle               OBJ_pilotAttributeType,12L

#define LN_documentVersion              "\x64\x6f\x63\x75\x6d\x65\x6e\x74\x56\x65\x72\x73\x69\x6f\x6e"
#define NID_documentVersion             470
#define OBJ_documentVersion             OBJ_pilotAttributeType,13L

#define LN_documentAuthor               "\x64\x6f\x63\x75\x6d\x65\x6e\x74\x41\x75\x74\x68\x6f\x72"
#define NID_documentAuthor              471
#define OBJ_documentAuthor              OBJ_pilotAttributeType,14L

#define LN_documentLocation             "\x64\x6f\x63\x75\x6d\x65\x6e\x74\x4c\x6f\x63\x61\x74\x69\x6f\x6e"
#define NID_documentLocation            472
#define OBJ_documentLocation            OBJ_pilotAttributeType,15L

#define LN_homeTelephoneNumber          "\x68\x6f\x6d\x65\x54\x65\x6c\x65\x70\x68\x6f\x6e\x65\x4e\x75\x6d\x62\x65\x72"
#define NID_homeTelephoneNumber         473
#define OBJ_homeTelephoneNumber         OBJ_pilotAttributeType,20L

#define SN_secretary            "\x73\x65\x63\x72\x65\x74\x61\x72\x79"
#define NID_secretary           474
#define OBJ_secretary           OBJ_pilotAttributeType,21L

#define LN_otherMailbox         "\x6f\x74\x68\x65\x72\x4d\x61\x69\x6c\x62\x6f\x78"
#define NID_otherMailbox                475
#define OBJ_otherMailbox                OBJ_pilotAttributeType,22L

#define LN_lastModifiedTime             "\x6c\x61\x73\x74\x4d\x6f\x64\x69\x66\x69\x65\x64\x54\x69\x6d\x65"
#define NID_lastModifiedTime            476
#define OBJ_lastModifiedTime            OBJ_pilotAttributeType,23L

#define LN_lastModifiedBy               "\x6c\x61\x73\x74\x4d\x6f\x64\x69\x66\x69\x65\x64\x42\x79"
#define NID_lastModifiedBy              477
#define OBJ_lastModifiedBy              OBJ_pilotAttributeType,24L

#define SN_domainComponent              "\x44\x43"
#define LN_domainComponent              "\x64\x6f\x6d\x61\x69\x6e\x43\x6f\x6d\x70\x6f\x6e\x65\x6e\x74"
#define NID_domainComponent             391
#define OBJ_domainComponent             OBJ_pilotAttributeType,25L

#define LN_aRecord              "\x61\x52\x65\x63\x6f\x72\x64"
#define NID_aRecord             478
#define OBJ_aRecord             OBJ_pilotAttributeType,26L

#define LN_pilotAttributeType27         "\x70\x69\x6c\x6f\x74\x41\x74\x74\x72\x69\x62\x75\x74\x65\x54\x79\x70\x65\x32\x37"
#define NID_pilotAttributeType27                479
#define OBJ_pilotAttributeType27                OBJ_pilotAttributeType,27L

#define LN_mXRecord             "\x6d\x58\x52\x65\x63\x6f\x72\x64"
#define NID_mXRecord            480
#define OBJ_mXRecord            OBJ_pilotAttributeType,28L

#define LN_nSRecord             "\x6e\x53\x52\x65\x63\x6f\x72\x64"
#define NID_nSRecord            481
#define OBJ_nSRecord            OBJ_pilotAttributeType,29L

#define LN_sOARecord            "\x73\x4f\x41\x52\x65\x63\x6f\x72\x64"
#define NID_sOARecord           482
#define OBJ_sOARecord           OBJ_pilotAttributeType,30L

#define LN_cNAMERecord          "\x63\x4e\x41\x4d\x45\x52\x65\x63\x6f\x72\x64"
#define NID_cNAMERecord         483
#define OBJ_cNAMERecord         OBJ_pilotAttributeType,31L

#define LN_associatedDomain             "\x61\x73\x73\x6f\x63\x69\x61\x74\x65\x64\x44\x6f\x6d\x61\x69\x6e"
#define NID_associatedDomain            484
#define OBJ_associatedDomain            OBJ_pilotAttributeType,37L

#define LN_associatedName               "\x61\x73\x73\x6f\x63\x69\x61\x74\x65\x64\x4e\x61\x6d\x65"
#define NID_associatedName              485
#define OBJ_associatedName              OBJ_pilotAttributeType,38L

#define LN_homePostalAddress            "\x68\x6f\x6d\x65\x50\x6f\x73\x74\x61\x6c\x41\x64\x64\x72\x65\x73\x73"
#define NID_homePostalAddress           486
#define OBJ_homePostalAddress           OBJ_pilotAttributeType,39L

#define LN_personalTitle                "\x70\x65\x72\x73\x6f\x6e\x61\x6c\x54\x69\x74\x6c\x65"
#define NID_personalTitle               487
#define OBJ_personalTitle               OBJ_pilotAttributeType,40L

#define LN_mobileTelephoneNumber                "\x6d\x6f\x62\x69\x6c\x65\x54\x65\x6c\x65\x70\x68\x6f\x6e\x65\x4e\x75\x6d\x62\x65\x72"
#define NID_mobileTelephoneNumber               488
#define OBJ_mobileTelephoneNumber               OBJ_pilotAttributeType,41L

#define LN_pagerTelephoneNumber         "\x70\x61\x67\x65\x72\x54\x65\x6c\x65\x70\x68\x6f\x6e\x65\x4e\x75\x6d\x62\x65\x72"
#define NID_pagerTelephoneNumber                489
#define OBJ_pagerTelephoneNumber                OBJ_pilotAttributeType,42L

#define LN_friendlyCountryName          "\x66\x72\x69\x65\x6e\x64\x6c\x79\x43\x6f\x75\x6e\x74\x72\x79\x4e\x61\x6d\x65"
#define NID_friendlyCountryName         490
#define OBJ_friendlyCountryName         OBJ_pilotAttributeType,43L

#define LN_organizationalStatus         "\x6f\x72\x67\x61\x6e\x69\x7a\x61\x74\x69\x6f\x6e\x61\x6c\x53\x74\x61\x74\x75\x73"
#define NID_organizationalStatus                491
#define OBJ_organizationalStatus                OBJ_pilotAttributeType,45L

#define LN_janetMailbox         "\x6a\x61\x6e\x65\x74\x4d\x61\x69\x6c\x62\x6f\x78"
#define NID_janetMailbox                492
#define OBJ_janetMailbox                OBJ_pilotAttributeType,46L

#define LN_mailPreferenceOption         "\x6d\x61\x69\x6c\x50\x72\x65\x66\x65\x72\x65\x6e\x63\x65\x4f\x70\x74\x69\x6f\x6e"
#define NID_mailPreferenceOption                493
#define OBJ_mailPreferenceOption                OBJ_pilotAttributeType,47L

#define LN_buildingName         "\x62\x75\x69\x6c\x64\x69\x6e\x67\x4e\x61\x6d\x65"
#define NID_buildingName                494
#define OBJ_buildingName                OBJ_pilotAttributeType,48L

#define LN_dSAQuality           "\x64\x53\x41\x51\x75\x61\x6c\x69\x74\x79"
#define NID_dSAQuality          495
#define OBJ_dSAQuality          OBJ_pilotAttributeType,49L

#define LN_singleLevelQuality           "\x73\x69\x6e\x67\x6c\x65\x4c\x65\x76\x65\x6c\x51\x75\x61\x6c\x69\x74\x79"
#define NID_singleLevelQuality          496
#define OBJ_singleLevelQuality          OBJ_pilotAttributeType,50L

#define LN_subtreeMinimumQuality                "\x73\x75\x62\x74\x72\x65\x65\x4d\x69\x6e\x69\x6d\x75\x6d\x51\x75\x61\x6c\x69\x74\x79"
#define NID_subtreeMinimumQuality               497
#define OBJ_subtreeMinimumQuality               OBJ_pilotAttributeType,51L

#define LN_subtreeMaximumQuality                "\x73\x75\x62\x74\x72\x65\x65\x4d\x61\x78\x69\x6d\x75\x6d\x51\x75\x61\x6c\x69\x74\x79"
#define NID_subtreeMaximumQuality               498
#define OBJ_subtreeMaximumQuality               OBJ_pilotAttributeType,52L

#define LN_personalSignature            "\x70\x65\x72\x73\x6f\x6e\x61\x6c\x53\x69\x67\x6e\x61\x74\x75\x72\x65"
#define NID_personalSignature           499
#define OBJ_personalSignature           OBJ_pilotAttributeType,53L

#define LN_dITRedirect          "\x64\x49\x54\x52\x65\x64\x69\x72\x65\x63\x74"
#define NID_dITRedirect         500
#define OBJ_dITRedirect         OBJ_pilotAttributeType,54L

#define SN_audio                "\x61\x75\x64\x69\x6f"
#define NID_audio               501
#define OBJ_audio               OBJ_pilotAttributeType,55L

#define LN_documentPublisher            "\x64\x6f\x63\x75\x6d\x65\x6e\x74\x50\x75\x62\x6c\x69\x73\x68\x65\x72"
#define NID_documentPublisher           502
#define OBJ_documentPublisher           OBJ_pilotAttributeType,56L

#define SN_id_set               "\x69\x64\x2d\x73\x65\x74"
#define LN_id_set               "\x53\x65\x63\x75\x72\x65\x20\x45\x6c\x65\x63\x74\x72\x6f\x6e\x69\x63\x20\x54\x72\x61\x6e\x73\x61\x63\x74\x69\x6f\x6e\x73"
#define NID_id_set              512
#define OBJ_id_set              OBJ_international_organizations,42L

#define SN_set_ctype            "\x73\x65\x74\x2d\x63\x74\x79\x70\x65"
#define LN_set_ctype            "\x63\x6f\x6e\x74\x65\x6e\x74\x20\x74\x79\x70\x65\x73"
#define NID_set_ctype           513
#define OBJ_set_ctype           OBJ_id_set,0L

#define SN_set_msgExt           "\x73\x65\x74\x2d\x6d\x73\x67\x45\x78\x74"
#define LN_set_msgExt           "\x6d\x65\x73\x73\x61\x67\x65\x20\x65\x78\x74\x65\x6e\x73\x69\x6f\x6e\x73"
#define NID_set_msgExt          514
#define OBJ_set_msgExt          OBJ_id_set,1L

#define SN_set_attr             "\x73\x65\x74\x2d\x61\x74\x74\x72"
#define NID_set_attr            515
#define OBJ_set_attr            OBJ_id_set,3L

#define SN_set_policy           "\x73\x65\x74\x2d\x70\x6f\x6c\x69\x63\x79"
#define NID_set_policy          516
#define OBJ_set_policy          OBJ_id_set,5L

#define SN_set_certExt          "\x73\x65\x74\x2d\x63\x65\x72\x74\x45\x78\x74"
#define LN_set_certExt          "\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x65\x78\x74\x65\x6e\x73\x69\x6f\x6e\x73"
#define NID_set_certExt         517
#define OBJ_set_certExt         OBJ_id_set,7L

#define SN_set_brand            "\x73\x65\x74\x2d\x62\x72\x61\x6e\x64"
#define NID_set_brand           518
#define OBJ_set_brand           OBJ_id_set,8L

#define SN_setct_PANData                "\x73\x65\x74\x63\x74\x2d\x50\x41\x4e\x44\x61\x74\x61"
#define NID_setct_PANData               519
#define OBJ_setct_PANData               OBJ_set_ctype,0L

#define SN_setct_PANToken               "\x73\x65\x74\x63\x74\x2d\x50\x41\x4e\x54\x6f\x6b\x65\x6e"
#define NID_setct_PANToken              520
#define OBJ_setct_PANToken              OBJ_set_ctype,1L

#define SN_setct_PANOnly                "\x73\x65\x74\x63\x74\x2d\x50\x41\x4e\x4f\x6e\x6c\x79"
#define NID_setct_PANOnly               521
#define OBJ_setct_PANOnly               OBJ_set_ctype,2L

#define SN_setct_OIData         "\x73\x65\x74\x63\x74\x2d\x4f\x49\x44\x61\x74\x61"
#define NID_setct_OIData                522
#define OBJ_setct_OIData                OBJ_set_ctype,3L

#define SN_setct_PI             "\x73\x65\x74\x63\x74\x2d\x50\x49"
#define NID_setct_PI            523
#define OBJ_setct_PI            OBJ_set_ctype,4L

#define SN_setct_PIData         "\x73\x65\x74\x63\x74\x2d\x50\x49\x44\x61\x74\x61"
#define NID_setct_PIData                524
#define OBJ_setct_PIData                OBJ_set_ctype,5L

#define SN_setct_PIDataUnsigned         "\x73\x65\x74\x63\x74\x2d\x50\x49\x44\x61\x74\x61\x55\x6e\x73\x69\x67\x6e\x65\x64"
#define NID_setct_PIDataUnsigned                525
#define OBJ_setct_PIDataUnsigned                OBJ_set_ctype,6L

#define SN_setct_HODInput               "\x73\x65\x74\x63\x74\x2d\x48\x4f\x44\x49\x6e\x70\x75\x74"
#define NID_setct_HODInput              526
#define OBJ_setct_HODInput              OBJ_set_ctype,7L

#define SN_setct_AuthResBaggage         "\x73\x65\x74\x63\x74\x2d\x41\x75\x74\x68\x52\x65\x73\x42\x61\x67\x67\x61\x67\x65"
#define NID_setct_AuthResBaggage                527
#define OBJ_setct_AuthResBaggage                OBJ_set_ctype,8L

#define SN_setct_AuthRevReqBaggage              "\x73\x65\x74\x63\x74\x2d\x41\x75\x74\x68\x52\x65\x76\x52\x65\x71\x42\x61\x67\x67\x61\x67\x65"
#define NID_setct_AuthRevReqBaggage             528
#define OBJ_setct_AuthRevReqBaggage             OBJ_set_ctype,9L

#define SN_setct_AuthRevResBaggage              "\x73\x65\x74\x63\x74\x2d\x41\x75\x74\x68\x52\x65\x76\x52\x65\x73\x42\x61\x67\x67\x61\x67\x65"
#define NID_setct_AuthRevResBaggage             529
#define OBJ_setct_AuthRevResBaggage             OBJ_set_ctype,10L

#define SN_setct_CapTokenSeq            "\x73\x65\x74\x63\x74\x2d\x43\x61\x70\x54\x6f\x6b\x65\x6e\x53\x65\x71"
#define NID_setct_CapTokenSeq           530
#define OBJ_setct_CapTokenSeq           OBJ_set_ctype,11L

#define SN_setct_PInitResData           "\x73\x65\x74\x63\x74\x2d\x50\x49\x6e\x69\x74\x52\x65\x73\x44\x61\x74\x61"
#define NID_setct_PInitResData          531
#define OBJ_setct_PInitResData          OBJ_set_ctype,12L

#define SN_setct_PI_TBS         "\x73\x65\x74\x63\x74\x2d\x50\x49\x2d\x54\x42\x53"
#define NID_setct_PI_TBS                532
#define OBJ_setct_PI_TBS                OBJ_set_ctype,13L

#define SN_setct_PResData               "\x73\x65\x74\x63\x74\x2d\x50\x52\x65\x73\x44\x61\x74\x61"
#define NID_setct_PResData              533
#define OBJ_setct_PResData              OBJ_set_ctype,14L

#define SN_setct_AuthReqTBS             "\x73\x65\x74\x63\x74\x2d\x41\x75\x74\x68\x52\x65\x71\x54\x42\x53"
#define NID_setct_AuthReqTBS            534
#define OBJ_setct_AuthReqTBS            OBJ_set_ctype,16L

#define SN_setct_AuthResTBS             "\x73\x65\x74\x63\x74\x2d\x41\x75\x74\x68\x52\x65\x73\x54\x42\x53"
#define NID_setct_AuthResTBS            535
#define OBJ_setct_AuthResTBS            OBJ_set_ctype,17L

#define SN_setct_AuthResTBSX            "\x73\x65\x74\x63\x74\x2d\x41\x75\x74\x68\x52\x65\x73\x54\x42\x53\x58"
#define NID_setct_AuthResTBSX           536
#define OBJ_setct_AuthResTBSX           OBJ_set_ctype,18L

#define SN_setct_AuthTokenTBS           "\x73\x65\x74\x63\x74\x2d\x41\x75\x74\x68\x54\x6f\x6b\x65\x6e\x54\x42\x53"
#define NID_setct_AuthTokenTBS          537
#define OBJ_setct_AuthTokenTBS          OBJ_set_ctype,19L

#define SN_setct_CapTokenData           "\x73\x65\x74\x63\x74\x2d\x43\x61\x70\x54\x6f\x6b\x65\x6e\x44\x61\x74\x61"
#define NID_setct_CapTokenData          538
#define OBJ_setct_CapTokenData          OBJ_set_ctype,20L

#define SN_setct_CapTokenTBS            "\x73\x65\x74\x63\x74\x2d\x43\x61\x70\x54\x6f\x6b\x65\x6e\x54\x42\x53"
#define NID_setct_CapTokenTBS           539
#define OBJ_setct_CapTokenTBS           OBJ_set_ctype,21L

#define SN_setct_AcqCardCodeMsg         "\x73\x65\x74\x63\x74\x2d\x41\x63\x71\x43\x61\x72\x64\x43\x6f\x64\x65\x4d\x73\x67"
#define NID_setct_AcqCardCodeMsg                540
#define OBJ_setct_AcqCardCodeMsg                OBJ_set_ctype,22L

#define SN_setct_AuthRevReqTBS          "\x73\x65\x74\x63\x74\x2d\x41\x75\x74\x68\x52\x65\x76\x52\x65\x71\x54\x42\x53"
#define NID_setct_AuthRevReqTBS         541
#define OBJ_setct_AuthRevReqTBS         OBJ_set_ctype,23L

#define SN_setct_AuthRevResData         "\x73\x65\x74\x63\x74\x2d\x41\x75\x74\x68\x52\x65\x76\x52\x65\x73\x44\x61\x74\x61"
#define NID_setct_AuthRevResData                542
#define OBJ_setct_AuthRevResData                OBJ_set_ctype,24L

#define SN_setct_AuthRevResTBS          "\x73\x65\x74\x63\x74\x2d\x41\x75\x74\x68\x52\x65\x76\x52\x65\x73\x54\x42\x53"
#define NID_setct_AuthRevResTBS         543
#define OBJ_setct_AuthRevResTBS         OBJ_set_ctype,25L

#define SN_setct_CapReqTBS              "\x73\x65\x74\x63\x74\x2d\x43\x61\x70\x52\x65\x71\x54\x42\x53"
#define NID_setct_CapReqTBS             544
#define OBJ_setct_CapReqTBS             OBJ_set_ctype,26L

#define SN_setct_CapReqTBSX             "\x73\x65\x74\x63\x74\x2d\x43\x61\x70\x52\x65\x71\x54\x42\x53\x58"
#define NID_setct_CapReqTBSX            545
#define OBJ_setct_CapReqTBSX            OBJ_set_ctype,27L

#define SN_setct_CapResData             "\x73\x65\x74\x63\x74\x2d\x43\x61\x70\x52\x65\x73\x44\x61\x74\x61"
#define NID_setct_CapResData            546
#define OBJ_setct_CapResData            OBJ_set_ctype,28L

#define SN_setct_CapRevReqTBS           "\x73\x65\x74\x63\x74\x2d\x43\x61\x70\x52\x65\x76\x52\x65\x71\x54\x42\x53"
#define NID_setct_CapRevReqTBS          547
#define OBJ_setct_CapRevReqTBS          OBJ_set_ctype,29L

#define SN_setct_CapRevReqTBSX          "\x73\x65\x74\x63\x74\x2d\x43\x61\x70\x52\x65\x76\x52\x65\x71\x54\x42\x53\x58"
#define NID_setct_CapRevReqTBSX         548
#define OBJ_setct_CapRevReqTBSX         OBJ_set_ctype,30L

#define SN_setct_CapRevResData          "\x73\x65\x74\x63\x74\x2d\x43\x61\x70\x52\x65\x76\x52\x65\x73\x44\x61\x74\x61"
#define NID_setct_CapRevResData         549
#define OBJ_setct_CapRevResData         OBJ_set_ctype,31L

#define SN_setct_CredReqTBS             "\x73\x65\x74\x63\x74\x2d\x43\x72\x65\x64\x52\x65\x71\x54\x42\x53"
#define NID_setct_CredReqTBS            550
#define OBJ_setct_CredReqTBS            OBJ_set_ctype,32L

#define SN_setct_CredReqTBSX            "\x73\x65\x74\x63\x74\x2d\x43\x72\x65\x64\x52\x65\x71\x54\x42\x53\x58"
#define NID_setct_CredReqTBSX           551
#define OBJ_setct_CredReqTBSX           OBJ_set_ctype,33L

#define SN_setct_CredResData            "\x73\x65\x74\x63\x74\x2d\x43\x72\x65\x64\x52\x65\x73\x44\x61\x74\x61"
#define NID_setct_CredResData           552
#define OBJ_setct_CredResData           OBJ_set_ctype,34L

#define SN_setct_CredRevReqTBS          "\x73\x65\x74\x63\x74\x2d\x43\x72\x65\x64\x52\x65\x76\x52\x65\x71\x54\x42\x53"
#define NID_setct_CredRevReqTBS         553
#define OBJ_setct_CredRevReqTBS         OBJ_set_ctype,35L

#define SN_setct_CredRevReqTBSX         "\x73\x65\x74\x63\x74\x2d\x43\x72\x65\x64\x52\x65\x76\x52\x65\x71\x54\x42\x53\x58"
#define NID_setct_CredRevReqTBSX                554
#define OBJ_setct_CredRevReqTBSX                OBJ_set_ctype,36L

#define SN_setct_CredRevResData         "\x73\x65\x74\x63\x74\x2d\x43\x72\x65\x64\x52\x65\x76\x52\x65\x73\x44\x61\x74\x61"
#define NID_setct_CredRevResData                555
#define OBJ_setct_CredRevResData                OBJ_set_ctype,37L

#define SN_setct_PCertReqData           "\x73\x65\x74\x63\x74\x2d\x50\x43\x65\x72\x74\x52\x65\x71\x44\x61\x74\x61"
#define NID_setct_PCertReqData          556
#define OBJ_setct_PCertReqData          OBJ_set_ctype,38L

#define SN_setct_PCertResTBS            "\x73\x65\x74\x63\x74\x2d\x50\x43\x65\x72\x74\x52\x65\x73\x54\x42\x53"
#define NID_setct_PCertResTBS           557
#define OBJ_setct_PCertResTBS           OBJ_set_ctype,39L

#define SN_setct_BatchAdminReqData              "\x73\x65\x74\x63\x74\x2d\x42\x61\x74\x63\x68\x41\x64\x6d\x69\x6e\x52\x65\x71\x44\x61\x74\x61"
#define NID_setct_BatchAdminReqData             558
#define OBJ_setct_BatchAdminReqData             OBJ_set_ctype,40L

#define SN_setct_BatchAdminResData              "\x73\x65\x74\x63\x74\x2d\x42\x61\x74\x63\x68\x41\x64\x6d\x69\x6e\x52\x65\x73\x44\x61\x74\x61"
#define NID_setct_BatchAdminResData             559
#define OBJ_setct_BatchAdminResData             OBJ_set_ctype,41L

#define SN_setct_CardCInitResTBS                "\x73\x65\x74\x63\x74\x2d\x43\x61\x72\x64\x43\x49\x6e\x69\x74\x52\x65\x73\x54\x42\x53"
#define NID_setct_CardCInitResTBS               560
#define OBJ_setct_CardCInitResTBS               OBJ_set_ctype,42L

#define SN_setct_MeAqCInitResTBS                "\x73\x65\x74\x63\x74\x2d\x4d\x65\x41\x71\x43\x49\x6e\x69\x74\x52\x65\x73\x54\x42\x53"
#define NID_setct_MeAqCInitResTBS               561
#define OBJ_setct_MeAqCInitResTBS               OBJ_set_ctype,43L

#define SN_setct_RegFormResTBS          "\x73\x65\x74\x63\x74\x2d\x52\x65\x67\x46\x6f\x72\x6d\x52\x65\x73\x54\x42\x53"
#define NID_setct_RegFormResTBS         562
#define OBJ_setct_RegFormResTBS         OBJ_set_ctype,44L

#define SN_setct_CertReqData            "\x73\x65\x74\x63\x74\x2d\x43\x65\x72\x74\x52\x65\x71\x44\x61\x74\x61"
#define NID_setct_CertReqData           563
#define OBJ_setct_CertReqData           OBJ_set_ctype,45L

#define SN_setct_CertReqTBS             "\x73\x65\x74\x63\x74\x2d\x43\x65\x72\x74\x52\x65\x71\x54\x42\x53"
#define NID_setct_CertReqTBS            564
#define OBJ_setct_CertReqTBS            OBJ_set_ctype,46L

#define SN_setct_CertResData            "\x73\x65\x74\x63\x74\x2d\x43\x65\x72\x74\x52\x65\x73\x44\x61\x74\x61"
#define NID_setct_CertResData           565
#define OBJ_setct_CertResData           OBJ_set_ctype,47L

#define SN_setct_CertInqReqTBS          "\x73\x65\x74\x63\x74\x2d\x43\x65\x72\x74\x49\x6e\x71\x52\x65\x71\x54\x42\x53"
#define NID_setct_CertInqReqTBS         566
#define OBJ_setct_CertInqReqTBS         OBJ_set_ctype,48L

#define SN_setct_ErrorTBS               "\x73\x65\x74\x63\x74\x2d\x45\x72\x72\x6f\x72\x54\x42\x53"
#define NID_setct_ErrorTBS              567
#define OBJ_setct_ErrorTBS              OBJ_set_ctype,49L

#define SN_setct_PIDualSignedTBE                "\x73\x65\x74\x63\x74\x2d\x50\x49\x44\x75\x61\x6c\x53\x69\x67\x6e\x65\x64\x54\x42\x45"
#define NID_setct_PIDualSignedTBE               568
#define OBJ_setct_PIDualSignedTBE               OBJ_set_ctype,50L

#define SN_setct_PIUnsignedTBE          "\x73\x65\x74\x63\x74\x2d\x50\x49\x55\x6e\x73\x69\x67\x6e\x65\x64\x54\x42\x45"
#define NID_setct_PIUnsignedTBE         569
#define OBJ_setct_PIUnsignedTBE         OBJ_set_ctype,51L

#define SN_setct_AuthReqTBE             "\x73\x65\x74\x63\x74\x2d\x41\x75\x74\x68\x52\x65\x71\x54\x42\x45"
#define NID_setct_AuthReqTBE            570
#define OBJ_setct_AuthReqTBE            OBJ_set_ctype,52L

#define SN_setct_AuthResTBE             "\x73\x65\x74\x63\x74\x2d\x41\x75\x74\x68\x52\x65\x73\x54\x42\x45"
#define NID_setct_AuthResTBE            571
#define OBJ_setct_AuthResTBE            OBJ_set_ctype,53L

#define SN_setct_AuthResTBEX            "\x73\x65\x74\x63\x74\x2d\x41\x75\x74\x68\x52\x65\x73\x54\x42\x45\x58"
#define NID_setct_AuthResTBEX           572
#define OBJ_setct_AuthResTBEX           OBJ_set_ctype,54L

#define SN_setct_AuthTokenTBE           "\x73\x65\x74\x63\x74\x2d\x41\x75\x74\x68\x54\x6f\x6b\x65\x6e\x54\x42\x45"
#define NID_setct_AuthTokenTBE          573
#define OBJ_setct_AuthTokenTBE          OBJ_set_ctype,55L

#define SN_setct_CapTokenTBE            "\x73\x65\x74\x63\x74\x2d\x43\x61\x70\x54\x6f\x6b\x65\x6e\x54\x42\x45"
#define NID_setct_CapTokenTBE           574
#define OBJ_setct_CapTokenTBE           OBJ_set_ctype,56L

#define SN_setct_CapTokenTBEX           "\x73\x65\x74\x63\x74\x2d\x43\x61\x70\x54\x6f\x6b\x65\x6e\x54\x42\x45\x58"
#define NID_setct_CapTokenTBEX          575
#define OBJ_setct_CapTokenTBEX          OBJ_set_ctype,57L

#define SN_setct_AcqCardCodeMsgTBE              "\x73\x65\x74\x63\x74\x2d\x41\x63\x71\x43\x61\x72\x64\x43\x6f\x64\x65\x4d\x73\x67\x54\x42\x45"
#define NID_setct_AcqCardCodeMsgTBE             576
#define OBJ_setct_AcqCardCodeMsgTBE             OBJ_set_ctype,58L

#define SN_setct_AuthRevReqTBE          "\x73\x65\x74\x63\x74\x2d\x41\x75\x74\x68\x52\x65\x76\x52\x65\x71\x54\x42\x45"
#define NID_setct_AuthRevReqTBE         577
#define OBJ_setct_AuthRevReqTBE         OBJ_set_ctype,59L

#define SN_setct_AuthRevResTBE          "\x73\x65\x74\x63\x74\x2d\x41\x75\x74\x68\x52\x65\x76\x52\x65\x73\x54\x42\x45"
#define NID_setct_AuthRevResTBE         578
#define OBJ_setct_AuthRevResTBE         OBJ_set_ctype,60L

#define SN_setct_AuthRevResTBEB         "\x73\x65\x74\x63\x74\x2d\x41\x75\x74\x68\x52\x65\x76\x52\x65\x73\x54\x42\x45\x42"
#define NID_setct_AuthRevResTBEB                579
#define OBJ_setct_AuthRevResTBEB                OBJ_set_ctype,61L

#define SN_setct_CapReqTBE              "\x73\x65\x74\x63\x74\x2d\x43\x61\x70\x52\x65\x71\x54\x42\x45"
#define NID_setct_CapReqTBE             580
#define OBJ_setct_CapReqTBE             OBJ_set_ctype,62L

#define SN_setct_CapReqTBEX             "\x73\x65\x74\x63\x74\x2d\x43\x61\x70\x52\x65\x71\x54\x42\x45\x58"
#define NID_setct_CapReqTBEX            581
#define OBJ_setct_CapReqTBEX            OBJ_set_ctype,63L

#define SN_setct_CapResTBE              "\x73\x65\x74\x63\x74\x2d\x43\x61\x70\x52\x65\x73\x54\x42\x45"
#define NID_setct_CapResTBE             582
#define OBJ_setct_CapResTBE             OBJ_set_ctype,64L

#define SN_setct_CapRevReqTBE           "\x73\x65\x74\x63\x74\x2d\x43\x61\x70\x52\x65\x76\x52\x65\x71\x54\x42\x45"
#define NID_setct_CapRevReqTBE          583
#define OBJ_setct_CapRevReqTBE          OBJ_set_ctype,65L

#define SN_setct_CapRevReqTBEX          "\x73\x65\x74\x63\x74\x2d\x43\x61\x70\x52\x65\x76\x52\x65\x71\x54\x42\x45\x58"
#define NID_setct_CapRevReqTBEX         584
#define OBJ_setct_CapRevReqTBEX         OBJ_set_ctype,66L

#define SN_setct_CapRevResTBE           "\x73\x65\x74\x63\x74\x2d\x43\x61\x70\x52\x65\x76\x52\x65\x73\x54\x42\x45"
#define NID_setct_CapRevResTBE          585
#define OBJ_setct_CapRevResTBE          OBJ_set_ctype,67L

#define SN_setct_CredReqTBE             "\x73\x65\x74\x63\x74\x2d\x43\x72\x65\x64\x52\x65\x71\x54\x42\x45"
#define NID_setct_CredReqTBE            586
#define OBJ_setct_CredReqTBE            OBJ_set_ctype,68L

#define SN_setct_CredReqTBEX            "\x73\x65\x74\x63\x74\x2d\x43\x72\x65\x64\x52\x65\x71\x54\x42\x45\x58"
#define NID_setct_CredReqTBEX           587
#define OBJ_setct_CredReqTBEX           OBJ_set_ctype,69L

#define SN_setct_CredResTBE             "\x73\x65\x74\x63\x74\x2d\x43\x72\x65\x64\x52\x65\x73\x54\x42\x45"
#define NID_setct_CredResTBE            588
#define OBJ_setct_CredResTBE            OBJ_set_ctype,70L

#define SN_setct_CredRevReqTBE          "\x73\x65\x74\x63\x74\x2d\x43\x72\x65\x64\x52\x65\x76\x52\x65\x71\x54\x42\x45"
#define NID_setct_CredRevReqTBE         589
#define OBJ_setct_CredRevReqTBE         OBJ_set_ctype,71L

#define SN_setct_CredRevReqTBEX         "\x73\x65\x74\x63\x74\x2d\x43\x72\x65\x64\x52\x65\x76\x52\x65\x71\x54\x42\x45\x58"
#define NID_setct_CredRevReqTBEX                590
#define OBJ_setct_CredRevReqTBEX                OBJ_set_ctype,72L

#define SN_setct_CredRevResTBE          "\x73\x65\x74\x63\x74\x2d\x43\x72\x65\x64\x52\x65\x76\x52\x65\x73\x54\x42\x45"
#define NID_setct_CredRevResTBE         591
#define OBJ_setct_CredRevResTBE         OBJ_set_ctype,73L

#define SN_setct_BatchAdminReqTBE               "\x73\x65\x74\x63\x74\x2d\x42\x61\x74\x63\x68\x41\x64\x6d\x69\x6e\x52\x65\x71\x54\x42\x45"
#define NID_setct_BatchAdminReqTBE              592
#define OBJ_setct_BatchAdminReqTBE              OBJ_set_ctype,74L

#define SN_setct_BatchAdminResTBE               "\x73\x65\x74\x63\x74\x2d\x42\x61\x74\x63\x68\x41\x64\x6d\x69\x6e\x52\x65\x73\x54\x42\x45"
#define NID_setct_BatchAdminResTBE              593
#define OBJ_setct_BatchAdminResTBE              OBJ_set_ctype,75L

#define SN_setct_RegFormReqTBE          "\x73\x65\x74\x63\x74\x2d\x52\x65\x67\x46\x6f\x72\x6d\x52\x65\x71\x54\x42\x45"
#define NID_setct_RegFormReqTBE         594
#define OBJ_setct_RegFormReqTBE         OBJ_set_ctype,76L

#define SN_setct_CertReqTBE             "\x73\x65\x74\x63\x74\x2d\x43\x65\x72\x74\x52\x65\x71\x54\x42\x45"
#define NID_setct_CertReqTBE            595
#define OBJ_setct_CertReqTBE            OBJ_set_ctype,77L

#define SN_setct_CertReqTBEX            "\x73\x65\x74\x63\x74\x2d\x43\x65\x72\x74\x52\x65\x71\x54\x42\x45\x58"
#define NID_setct_CertReqTBEX           596
#define OBJ_setct_CertReqTBEX           OBJ_set_ctype,78L

#define SN_setct_CertResTBE             "\x73\x65\x74\x63\x74\x2d\x43\x65\x72\x74\x52\x65\x73\x54\x42\x45"
#define NID_setct_CertResTBE            597
#define OBJ_setct_CertResTBE            OBJ_set_ctype,79L

#define SN_setct_CRLNotificationTBS             "\x73\x65\x74\x63\x74\x2d\x43\x52\x4c\x4e\x6f\x74\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x54\x42\x53"
#define NID_setct_CRLNotificationTBS            598
#define OBJ_setct_CRLNotificationTBS            OBJ_set_ctype,80L

#define SN_setct_CRLNotificationResTBS          "\x73\x65\x74\x63\x74\x2d\x43\x52\x4c\x4e\x6f\x74\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x52\x65\x73\x54\x42\x53"
#define NID_setct_CRLNotificationResTBS         599
#define OBJ_setct_CRLNotificationResTBS         OBJ_set_ctype,81L

#define SN_setct_BCIDistributionTBS             "\x73\x65\x74\x63\x74\x2d\x42\x43\x49\x44\x69\x73\x74\x72\x69\x62\x75\x74\x69\x6f\x6e\x54\x42\x53"
#define NID_setct_BCIDistributionTBS            600
#define OBJ_setct_BCIDistributionTBS            OBJ_set_ctype,82L

#define SN_setext_genCrypt              "\x73\x65\x74\x65\x78\x74\x2d\x67\x65\x6e\x43\x72\x79\x70\x74"
#define LN_setext_genCrypt              "\x67\x65\x6e\x65\x72\x69\x63\x20\x63\x72\x79\x70\x74\x6f\x67\x72\x61\x6d"
#define NID_setext_genCrypt             601
#define OBJ_setext_genCrypt             OBJ_set_msgExt,1L

#define SN_setext_miAuth                "\x73\x65\x74\x65\x78\x74\x2d\x6d\x69\x41\x75\x74\x68"
#define LN_setext_miAuth                "\x6d\x65\x72\x63\x68\x61\x6e\x74\x20\x69\x6e\x69\x74\x69\x61\x74\x65\x64\x20\x61\x75\x74\x68"
#define NID_setext_miAuth               602
#define OBJ_setext_miAuth               OBJ_set_msgExt,3L

#define SN_setext_pinSecure             "\x73\x65\x74\x65\x78\x74\x2d\x70\x69\x6e\x53\x65\x63\x75\x72\x65"
#define NID_setext_pinSecure            603
#define OBJ_setext_pinSecure            OBJ_set_msgExt,4L

#define SN_setext_pinAny                "\x73\x65\x74\x65\x78\x74\x2d\x70\x69\x6e\x41\x6e\x79"
#define NID_setext_pinAny               604
#define OBJ_setext_pinAny               OBJ_set_msgExt,5L

#define SN_setext_track2                "\x73\x65\x74\x65\x78\x74\x2d\x74\x72\x61\x63\x6b\x32"
#define NID_setext_track2               605
#define OBJ_setext_track2               OBJ_set_msgExt,7L

#define SN_setext_cv            "\x73\x65\x74\x65\x78\x74\x2d\x63\x76"
#define LN_setext_cv            "\x61\x64\x64\x69\x74\x69\x6f\x6e\x61\x6c\x20\x76\x65\x72\x69\x66\x69\x63\x61\x74\x69\x6f\x6e"
#define NID_setext_cv           606
#define OBJ_setext_cv           OBJ_set_msgExt,8L

#define SN_set_policy_root              "\x73\x65\x74\x2d\x70\x6f\x6c\x69\x63\x79\x2d\x72\x6f\x6f\x74"
#define NID_set_policy_root             607
#define OBJ_set_policy_root             OBJ_set_policy,0L

#define SN_setCext_hashedRoot           "\x73\x65\x74\x43\x65\x78\x74\x2d\x68\x61\x73\x68\x65\x64\x52\x6f\x6f\x74"
#define NID_setCext_hashedRoot          608
#define OBJ_setCext_hashedRoot          OBJ_set_certExt,0L

#define SN_setCext_certType             "\x73\x65\x74\x43\x65\x78\x74\x2d\x63\x65\x72\x74\x54\x79\x70\x65"
#define NID_setCext_certType            609
#define OBJ_setCext_certType            OBJ_set_certExt,1L

#define SN_setCext_merchData            "\x73\x65\x74\x43\x65\x78\x74\x2d\x6d\x65\x72\x63\x68\x44\x61\x74\x61"
#define NID_setCext_merchData           610
#define OBJ_setCext_merchData           OBJ_set_certExt,2L

#define SN_setCext_cCertRequired                "\x73\x65\x74\x43\x65\x78\x74\x2d\x63\x43\x65\x72\x74\x52\x65\x71\x75\x69\x72\x65\x64"
#define NID_setCext_cCertRequired               611
#define OBJ_setCext_cCertRequired               OBJ_set_certExt,3L

#define SN_setCext_tunneling            "\x73\x65\x74\x43\x65\x78\x74\x2d\x74\x75\x6e\x6e\x65\x6c\x69\x6e\x67"
#define NID_setCext_tunneling           612
#define OBJ_setCext_tunneling           OBJ_set_certExt,4L

#define SN_setCext_setExt               "\x73\x65\x74\x43\x65\x78\x74\x2d\x73\x65\x74\x45\x78\x74"
#define NID_setCext_setExt              613
#define OBJ_setCext_setExt              OBJ_set_certExt,5L

#define SN_setCext_setQualf             "\x73\x65\x74\x43\x65\x78\x74\x2d\x73\x65\x74\x51\x75\x61\x6c\x66"
#define NID_setCext_setQualf            614
#define OBJ_setCext_setQualf            OBJ_set_certExt,6L

#define SN_setCext_PGWYcapabilities             "\x73\x65\x74\x43\x65\x78\x74\x2d\x50\x47\x57\x59\x63\x61\x70\x61\x62\x69\x6c\x69\x74\x69\x65\x73"
#define NID_setCext_PGWYcapabilities            615
#define OBJ_setCext_PGWYcapabilities            OBJ_set_certExt,7L

#define SN_setCext_TokenIdentifier              "\x73\x65\x74\x43\x65\x78\x74\x2d\x54\x6f\x6b\x65\x6e\x49\x64\x65\x6e\x74\x69\x66\x69\x65\x72"
#define NID_setCext_TokenIdentifier             616
#define OBJ_setCext_TokenIdentifier             OBJ_set_certExt,8L

#define SN_setCext_Track2Data           "\x73\x65\x74\x43\x65\x78\x74\x2d\x54\x72\x61\x63\x6b\x32\x44\x61\x74\x61"
#define NID_setCext_Track2Data          617
#define OBJ_setCext_Track2Data          OBJ_set_certExt,9L

#define SN_setCext_TokenType            "\x73\x65\x74\x43\x65\x78\x74\x2d\x54\x6f\x6b\x65\x6e\x54\x79\x70\x65"
#define NID_setCext_TokenType           618
#define OBJ_setCext_TokenType           OBJ_set_certExt,10L

#define SN_setCext_IssuerCapabilities           "\x73\x65\x74\x43\x65\x78\x74\x2d\x49\x73\x73\x75\x65\x72\x43\x61\x70\x61\x62\x69\x6c\x69\x74\x69\x65\x73"
#define NID_setCext_IssuerCapabilities          619
#define OBJ_setCext_IssuerCapabilities          OBJ_set_certExt,11L

#define SN_setAttr_Cert         "\x73\x65\x74\x41\x74\x74\x72\x2d\x43\x65\x72\x74"
#define NID_setAttr_Cert                620
#define OBJ_setAttr_Cert                OBJ_set_attr,0L

#define SN_setAttr_PGWYcap              "\x73\x65\x74\x41\x74\x74\x72\x2d\x50\x47\x57\x59\x63\x61\x70"
#define LN_setAttr_PGWYcap              "\x70\x61\x79\x6d\x65\x6e\x74\x20\x67\x61\x74\x65\x77\x61\x79\x20\x63\x61\x70\x61\x62\x69\x6c\x69\x74\x69\x65\x73"
#define NID_setAttr_PGWYcap             621
#define OBJ_setAttr_PGWYcap             OBJ_set_attr,1L

#define SN_setAttr_TokenType            "\x73\x65\x74\x41\x74\x74\x72\x2d\x54\x6f\x6b\x65\x6e\x54\x79\x70\x65"
#define NID_setAttr_TokenType           622
#define OBJ_setAttr_TokenType           OBJ_set_attr,2L

#define SN_setAttr_IssCap               "\x73\x65\x74\x41\x74\x74\x72\x2d\x49\x73\x73\x43\x61\x70"
#define LN_setAttr_IssCap               "\x69\x73\x73\x75\x65\x72\x20\x63\x61\x70\x61\x62\x69\x6c\x69\x74\x69\x65\x73"
#define NID_setAttr_IssCap              623
#define OBJ_setAttr_IssCap              OBJ_set_attr,3L

#define SN_set_rootKeyThumb             "\x73\x65\x74\x2d\x72\x6f\x6f\x74\x4b\x65\x79\x54\x68\x75\x6d\x62"
#define NID_set_rootKeyThumb            624
#define OBJ_set_rootKeyThumb            OBJ_setAttr_Cert,0L

#define SN_set_addPolicy                "\x73\x65\x74\x2d\x61\x64\x64\x50\x6f\x6c\x69\x63\x79"
#define NID_set_addPolicy               625
#define OBJ_set_addPolicy               OBJ_setAttr_Cert,1L

#define SN_setAttr_Token_EMV            "\x73\x65\x74\x41\x74\x74\x72\x2d\x54\x6f\x6b\x65\x6e\x2d\x45\x4d\x56"
#define NID_setAttr_Token_EMV           626
#define OBJ_setAttr_Token_EMV           OBJ_setAttr_TokenType,1L

#define SN_setAttr_Token_B0Prime                "\x73\x65\x74\x41\x74\x74\x72\x2d\x54\x6f\x6b\x65\x6e\x2d\x42\x30\x50\x72\x69\x6d\x65"
#define NID_setAttr_Token_B0Prime               627
#define OBJ_setAttr_Token_B0Prime               OBJ_setAttr_TokenType,2L

#define SN_setAttr_IssCap_CVM           "\x73\x65\x74\x41\x74\x74\x72\x2d\x49\x73\x73\x43\x61\x70\x2d\x43\x56\x4d"
#define NID_setAttr_IssCap_CVM          628
#define OBJ_setAttr_IssCap_CVM          OBJ_setAttr_IssCap,3L

#define SN_setAttr_IssCap_T2            "\x73\x65\x74\x41\x74\x74\x72\x2d\x49\x73\x73\x43\x61\x70\x2d\x54\x32"
#define NID_setAttr_IssCap_T2           629
#define OBJ_setAttr_IssCap_T2           OBJ_setAttr_IssCap,4L

#define SN_setAttr_IssCap_Sig           "\x73\x65\x74\x41\x74\x74\x72\x2d\x49\x73\x73\x43\x61\x70\x2d\x53\x69\x67"
#define NID_setAttr_IssCap_Sig          630
#define OBJ_setAttr_IssCap_Sig          OBJ_setAttr_IssCap,5L

#define SN_setAttr_GenCryptgrm          "\x73\x65\x74\x41\x74\x74\x72\x2d\x47\x65\x6e\x43\x72\x79\x70\x74\x67\x72\x6d"
#define LN_setAttr_GenCryptgrm          "\x67\x65\x6e\x65\x72\x61\x74\x65\x20\x63\x72\x79\x70\x74\x6f\x67\x72\x61\x6d"
#define NID_setAttr_GenCryptgrm         631
#define OBJ_setAttr_GenCryptgrm         OBJ_setAttr_IssCap_CVM,1L

#define SN_setAttr_T2Enc                "\x73\x65\x74\x41\x74\x74\x72\x2d\x54\x32\x45\x6e\x63"
#define LN_setAttr_T2Enc                "\x65\x6e\x63\x72\x79\x70\x74\x65\x64\x20\x74\x72\x61\x63\x6b\x20\x32"
#define NID_setAttr_T2Enc               632
#define OBJ_setAttr_T2Enc               OBJ_setAttr_IssCap_T2,1L

#define SN_setAttr_T2cleartxt           "\x73\x65\x74\x41\x74\x74\x72\x2d\x54\x32\x63\x6c\x65\x61\x72\x74\x78\x74"
#define LN_setAttr_T2cleartxt           "\x63\x6c\x65\x61\x72\x74\x65\x78\x74\x20\x74\x72\x61\x63\x6b\x20\x32"
#define NID_setAttr_T2cleartxt          633
#define OBJ_setAttr_T2cleartxt          OBJ_setAttr_IssCap_T2,2L

#define SN_setAttr_TokICCsig            "\x73\x65\x74\x41\x74\x74\x72\x2d\x54\x6f\x6b\x49\x43\x43\x73\x69\x67"
#define LN_setAttr_TokICCsig            "\x49\x43\x43\x20\x6f\x72\x20\x74\x6f\x6b\x65\x6e\x20\x73\x69\x67\x6e\x61\x74\x75\x72\x65"
#define NID_setAttr_TokICCsig           634
#define OBJ_setAttr_TokICCsig           OBJ_setAttr_IssCap_Sig,1L

#define SN_setAttr_SecDevSig            "\x73\x65\x74\x41\x74\x74\x72\x2d\x53\x65\x63\x44\x65\x76\x53\x69\x67"
#define LN_setAttr_SecDevSig            "\x73\x65\x63\x75\x72\x65\x20\x64\x65\x76\x69\x63\x65\x20\x73\x69\x67\x6e\x61\x74\x75\x72\x65"
#define NID_setAttr_SecDevSig           635
#define OBJ_setAttr_SecDevSig           OBJ_setAttr_IssCap_Sig,2L

#define SN_set_brand_IATA_ATA           "\x73\x65\x74\x2d\x62\x72\x61\x6e\x64\x2d\x49\x41\x54\x41\x2d\x41\x54\x41"
#define NID_set_brand_IATA_ATA          636
#define OBJ_set_brand_IATA_ATA          OBJ_set_brand,1L

#define SN_set_brand_Diners             "\x73\x65\x74\x2d\x62\x72\x61\x6e\x64\x2d\x44\x69\x6e\x65\x72\x73"
#define NID_set_brand_Diners            637
#define OBJ_set_brand_Diners            OBJ_set_brand,30L

#define SN_set_brand_AmericanExpress            "\x73\x65\x74\x2d\x62\x72\x61\x6e\x64\x2d\x41\x6d\x65\x72\x69\x63\x61\x6e\x45\x78\x70\x72\x65\x73\x73"
#define NID_set_brand_AmericanExpress           638
#define OBJ_set_brand_AmericanExpress           OBJ_set_brand,34L

#define SN_set_brand_JCB                "\x73\x65\x74\x2d\x62\x72\x61\x6e\x64\x2d\x4a\x43\x42"
#define NID_set_brand_JCB               639
#define OBJ_set_brand_JCB               OBJ_set_brand,35L

#define SN_set_brand_Visa               "\x73\x65\x74\x2d\x62\x72\x61\x6e\x64\x2d\x56\x69\x73\x61"
#define NID_set_brand_Visa              640
#define OBJ_set_brand_Visa              OBJ_set_brand,4L

#define SN_set_brand_MasterCard         "\x73\x65\x74\x2d\x62\x72\x61\x6e\x64\x2d\x4d\x61\x73\x74\x65\x72\x43\x61\x72\x64"
#define NID_set_brand_MasterCard                641
#define OBJ_set_brand_MasterCard                OBJ_set_brand,5L

#define SN_set_brand_Novus              "\x73\x65\x74\x2d\x62\x72\x61\x6e\x64\x2d\x4e\x6f\x76\x75\x73"
#define NID_set_brand_Novus             642
#define OBJ_set_brand_Novus             OBJ_set_brand,6011L

#define SN_des_cdmf             "\x44\x45\x53\x2d\x43\x44\x4d\x46"
#define LN_des_cdmf             "\x64\x65\x73\x2d\x63\x64\x6d\x66"
#define NID_des_cdmf            643
#define OBJ_des_cdmf            OBJ_rsadsi,3L,10L

#define SN_rsaOAEPEncryptionSET         "\x72\x73\x61\x4f\x41\x45\x50\x45\x6e\x63\x72\x79\x70\x74\x69\x6f\x6e\x53\x45\x54"
#define NID_rsaOAEPEncryptionSET                644
#define OBJ_rsaOAEPEncryptionSET                OBJ_rsadsi,1L,1L,6L

#define SN_ipsec3               "\x4f\x61\x6b\x6c\x65\x79\x2d\x45\x43\x32\x4e\x2d\x33"
#define LN_ipsec3               "\x69\x70\x73\x65\x63\x33"
#define NID_ipsec3              749

#define SN_ipsec4               "\x4f\x61\x6b\x6c\x65\x79\x2d\x45\x43\x32\x4e\x2d\x34"
#define LN_ipsec4               "\x69\x70\x73\x65\x63\x34"
#define NID_ipsec4              750

#define SN_whirlpool            "\x77\x68\x69\x72\x6c\x70\x6f\x6f\x6c"
#define NID_whirlpool           804
#define OBJ_whirlpool           OBJ_iso,0L,10118L,3L,0L,55L

#define SN_cryptopro            "\x63\x72\x79\x70\x74\x6f\x70\x72\x6f"
#define NID_cryptopro           805
#define OBJ_cryptopro           OBJ_member_body,643L,2L,2L

#define SN_cryptocom            "\x63\x72\x79\x70\x74\x6f\x63\x6f\x6d"
#define NID_cryptocom           806
#define OBJ_cryptocom           OBJ_member_body,643L,2L,9L

#define SN_id_GostR3411_94_with_GostR3410_2001          "\x69\x64\x2d\x47\x6f\x73\x74\x52\x33\x34\x31\x31\x2d\x39\x34\x2d\x77\x69\x74\x68\x2d\x47\x6f\x73\x74\x52\x33\x34\x31\x30\x2d\x32\x30\x30\x31"
#define LN_id_GostR3411_94_with_GostR3410_2001          "\x47\x4f\x53\x54\x20\x52\x20\x33\x34\x2e\x31\x31\x2d\x39\x34\x20\x77\x69\x74\x68\x20\x47\x4f\x53\x54\x20\x52\x20\x33\x34\x2e\x31\x30\x2d\x32\x30\x30\x31"
#define NID_id_GostR3411_94_with_GostR3410_2001         807
#define OBJ_id_GostR3411_94_with_GostR3410_2001         OBJ_cryptopro,3L

#define SN_id_GostR3411_94_with_GostR3410_94            "\x69\x64\x2d\x47\x6f\x73\x74\x52\x33\x34\x31\x31\x2d\x39\x34\x2d\x77\x69\x74\x68\x2d\x47\x6f\x73\x74\x52\x33\x34\x31\x30\x2d\x39\x34"
#define LN_id_GostR3411_94_with_GostR3410_94            "\x47\x4f\x53\x54\x20\x52\x20\x33\x34\x2e\x31\x31\x2d\x39\x34\x20\x77\x69\x74\x68\x20\x47\x4f\x53\x54\x20\x52\x20\x33\x34\x2e\x31\x30\x2d\x39\x34"
#define NID_id_GostR3411_94_with_GostR3410_94           808
#define OBJ_id_GostR3411_94_with_GostR3410_94           OBJ_cryptopro,4L

#define SN_id_GostR3411_94              "\x6d\x64\x5f\x67\x6f\x73\x74\x39\x34"
#define LN_id_GostR3411_94              "\x47\x4f\x53\x54\x20\x52\x20\x33\x34\x2e\x31\x31\x2d\x39\x34"
#define NID_id_GostR3411_94             809
#define OBJ_id_GostR3411_94             OBJ_cryptopro,9L

#define SN_id_HMACGostR3411_94          "\x69\x64\x2d\x48\x4d\x41\x43\x47\x6f\x73\x74\x52\x33\x34\x31\x31\x2d\x39\x34"
#define LN_id_HMACGostR3411_94          "\x48\x4d\x41\x43\x20\x47\x4f\x53\x54\x20\x33\x34\x2e\x31\x31\x2d\x39\x34"
#define NID_id_HMACGostR3411_94         810
#define OBJ_id_HMACGostR3411_94         OBJ_cryptopro,10L

#define SN_id_GostR3410_2001            "\x67\x6f\x73\x74\x32\x30\x30\x31"
#define LN_id_GostR3410_2001            "\x47\x4f\x53\x54\x20\x52\x20\x33\x34\x2e\x31\x30\x2d\x32\x30\x30\x31"
#define NID_id_GostR3410_2001           811
#define OBJ_id_GostR3410_2001           OBJ_cryptopro,19L

#define SN_id_GostR3410_94              "\x67\x6f\x73\x74\x39\x34"
#define LN_id_GostR3410_94              "\x47\x4f\x53\x54\x20\x52\x20\x33\x34\x2e\x31\x30\x2d\x39\x34"
#define NID_id_GostR3410_94             812
#define OBJ_id_GostR3410_94             OBJ_cryptopro,20L

#define SN_id_Gost28147_89              "\x67\x6f\x73\x74\x38\x39"
#define LN_id_Gost28147_89              "\x47\x4f\x53\x54\x20\x32\x38\x31\x34\x37\x2d\x38\x39"
#define NID_id_Gost28147_89             813
#define OBJ_id_Gost28147_89             OBJ_cryptopro,21L

#define SN_gost89_cnt           "\x67\x6f\x73\x74\x38\x39\x2d\x63\x6e\x74"
#define NID_gost89_cnt          814

#define SN_id_Gost28147_89_MAC          "\x67\x6f\x73\x74\x2d\x6d\x61\x63"
#define LN_id_Gost28147_89_MAC          "\x47\x4f\x53\x54\x20\x32\x38\x31\x34\x37\x2d\x38\x39\x20\x4d\x41\x43"
#define NID_id_Gost28147_89_MAC         815
#define OBJ_id_Gost28147_89_MAC         OBJ_cryptopro,22L

#define SN_id_GostR3411_94_prf          "\x70\x72\x66\x2d\x67\x6f\x73\x74\x72\x33\x34\x31\x31\x2d\x39\x34"
#define LN_id_GostR3411_94_prf          "\x47\x4f\x53\x54\x20\x52\x20\x33\x34\x2e\x31\x31\x2d\x39\x34\x20\x50\x52\x46"
#define NID_id_GostR3411_94_prf         816
#define OBJ_id_GostR3411_94_prf         OBJ_cryptopro,23L

#define SN_id_GostR3410_2001DH          "\x69\x64\x2d\x47\x6f\x73\x74\x52\x33\x34\x31\x30\x2d\x32\x30\x30\x31\x44\x48"
#define LN_id_GostR3410_2001DH          "\x47\x4f\x53\x54\x20\x52\x20\x33\x34\x2e\x31\x30\x2d\x32\x30\x30\x31\x20\x44\x48"
#define NID_id_GostR3410_2001DH         817
#define OBJ_id_GostR3410_2001DH         OBJ_cryptopro,98L

#define SN_id_GostR3410_94DH            "\x69\x64\x2d\x47\x6f\x73\x74\x52\x33\x34\x31\x30\x2d\x39\x34\x44\x48"
#define LN_id_GostR3410_94DH            "\x47\x4f\x53\x54\x20\x52\x20\x33\x34\x2e\x31\x30\x2d\x39\x34\x20\x44\x48"
#define NID_id_GostR3410_94DH           818
#define OBJ_id_GostR3410_94DH           OBJ_cryptopro,99L

#define SN_id_Gost28147_89_CryptoPro_KeyMeshing         "\x69\x64\x2d\x47\x6f\x73\x74\x32\x38\x31\x34\x37\x2d\x38\x39\x2d\x43\x72\x79\x70\x74\x6f\x50\x72\x6f\x2d\x4b\x65\x79\x4d\x65\x73\x68\x69\x6e\x67"
#define NID_id_Gost28147_89_CryptoPro_KeyMeshing                819
#define OBJ_id_Gost28147_89_CryptoPro_KeyMeshing                OBJ_cryptopro,14L,1L

#define SN_id_Gost28147_89_None_KeyMeshing              "\x69\x64\x2d\x47\x6f\x73\x74\x32\x38\x31\x34\x37\x2d\x38\x39\x2d\x4e\x6f\x6e\x65\x2d\x4b\x65\x79\x4d\x65\x73\x68\x69\x6e\x67"
#define NID_id_Gost28147_89_None_KeyMeshing             820
#define OBJ_id_Gost28147_89_None_KeyMeshing             OBJ_cryptopro,14L,0L

#define SN_id_GostR3411_94_TestParamSet         "\x69\x64\x2d\x47\x6f\x73\x74\x52\x33\x34\x31\x31\x2d\x39\x34\x2d\x54\x65\x73\x74\x50\x61\x72\x61\x6d\x53\x65\x74"
#define NID_id_GostR3411_94_TestParamSet                821
#define OBJ_id_GostR3411_94_TestParamSet                OBJ_cryptopro,30L,0L

#define SN_id_GostR3411_94_CryptoProParamSet            "\x69\x64\x2d\x47\x6f\x73\x74\x52\x33\x34\x31\x31\x2d\x39\x34\x2d\x43\x72\x79\x70\x74\x6f\x50\x72\x6f\x50\x61\x72\x61\x6d\x53\x65\x74"
#define NID_id_GostR3411_94_CryptoProParamSet           822
#define OBJ_id_GostR3411_94_CryptoProParamSet           OBJ_cryptopro,30L,1L

#define SN_id_Gost28147_89_TestParamSet         "\x69\x64\x2d\x47\x6f\x73\x74\x32\x38\x31\x34\x37\x2d\x38\x39\x2d\x54\x65\x73\x74\x50\x61\x72\x61\x6d\x53\x65\x74"
#define NID_id_Gost28147_89_TestParamSet                823
#define OBJ_id_Gost28147_89_TestParamSet                OBJ_cryptopro,31L,0L

#define SN_id_Gost28147_89_CryptoPro_A_ParamSet         "\x69\x64\x2d\x47\x6f\x73\x74\x32\x38\x31\x34\x37\x2d\x38\x39\x2d\x43\x72\x79\x70\x74\x6f\x50\x72\x6f\x2d\x41\x2d\x50\x61\x72\x61\x6d\x53\x65\x74"
#define NID_id_Gost28147_89_CryptoPro_A_ParamSet                824
#define OBJ_id_Gost28147_89_CryptoPro_A_ParamSet                OBJ_cryptopro,31L,1L

#define SN_id_Gost28147_89_CryptoPro_B_ParamSet         "\x69\x64\x2d\x47\x6f\x73\x74\x32\x38\x31\x34\x37\x2d\x38\x39\x2d\x43\x72\x79\x70\x74\x6f\x50\x72\x6f\x2d\x42\x2d\x50\x61\x72\x61\x6d\x53\x65\x74"
#define NID_id_Gost28147_89_CryptoPro_B_ParamSet                825
#define OBJ_id_Gost28147_89_CryptoPro_B_ParamSet                OBJ_cryptopro,31L,2L

#define SN_id_Gost28147_89_CryptoPro_C_ParamSet         "\x69\x64\x2d\x47\x6f\x73\x74\x32\x38\x31\x34\x37\x2d\x38\x39\x2d\x43\x72\x79\x70\x74\x6f\x50\x72\x6f\x2d\x43\x2d\x50\x61\x72\x61\x6d\x53\x65\x74"
#define NID_id_Gost28147_89_CryptoPro_C_ParamSet                826
#define OBJ_id_Gost28147_89_CryptoPro_C_ParamSet                OBJ_cryptopro,31L,3L

#define SN_id_Gost28147_89_CryptoPro_D_ParamSet         "\x69\x64\x2d\x47\x6f\x73\x74\x32\x38\x31\x34\x37\x2d\x38\x39\x2d\x43\x72\x79\x70\x74\x6f\x50\x72\x6f\x2d\x44\x2d\x50\x61\x72\x61\x6d\x53\x65\x74"
#define NID_id_Gost28147_89_CryptoPro_D_ParamSet                827
#define OBJ_id_Gost28147_89_CryptoPro_D_ParamSet                OBJ_cryptopro,31L,4L

#define SN_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet         "\x69\x64\x2d\x47\x6f\x73\x74\x32\x38\x31\x34\x37\x2d\x38\x39\x2d\x43\x72\x79\x70\x74\x6f\x50\x72\x6f\x2d\x4f\x73\x63\x61\x72\x2d\x31\x2d\x31\x2d\x50\x61\x72\x61\x6d\x53\x65\x74"
#define NID_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet                828
#define OBJ_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet                OBJ_cryptopro,31L,5L

#define SN_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet         "\x69\x64\x2d\x47\x6f\x73\x74\x32\x38\x31\x34\x37\x2d\x38\x39\x2d\x43\x72\x79\x70\x74\x6f\x50\x72\x6f\x2d\x4f\x73\x63\x61\x72\x2d\x31\x2d\x30\x2d\x50\x61\x72\x61\x6d\x53\x65\x74"
#define NID_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet                829
#define OBJ_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet                OBJ_cryptopro,31L,6L

#define SN_id_Gost28147_89_CryptoPro_RIC_1_ParamSet             "\x69\x64\x2d\x47\x6f\x73\x74\x32\x38\x31\x34\x37\x2d\x38\x39\x2d\x43\x72\x79\x70\x74\x6f\x50\x72\x6f\x2d\x52\x49\x43\x2d\x31\x2d\x50\x61\x72\x61\x6d\x53\x65\x74"
#define NID_id_Gost28147_89_CryptoPro_RIC_1_ParamSet            830
#define OBJ_id_Gost28147_89_CryptoPro_RIC_1_ParamSet            OBJ_cryptopro,31L,7L

#define SN_id_GostR3410_94_TestParamSet         "\x69\x64\x2d\x47\x6f\x73\x74\x52\x33\x34\x31\x30\x2d\x39\x34\x2d\x54\x65\x73\x74\x50\x61\x72\x61\x6d\x53\x65\x74"
#define NID_id_GostR3410_94_TestParamSet                831
#define OBJ_id_GostR3410_94_TestParamSet                OBJ_cryptopro,32L,0L

#define SN_id_GostR3410_94_CryptoPro_A_ParamSet         "\x69\x64\x2d\x47\x6f\x73\x74\x52\x33\x34\x31\x30\x2d\x39\x34\x2d\x43\x72\x79\x70\x74\x6f\x50\x72\x6f\x2d\x41\x2d\x50\x61\x72\x61\x6d\x53\x65\x74"
#define NID_id_GostR3410_94_CryptoPro_A_ParamSet                832
#define OBJ_id_GostR3410_94_CryptoPro_A_ParamSet                OBJ_cryptopro,32L,2L

#define SN_id_GostR3410_94_CryptoPro_B_ParamSet         "\x69\x64\x2d\x47\x6f\x73\x74\x52\x33\x34\x31\x30\x2d\x39\x34\x2d\x43\x72\x79\x70\x74\x6f\x50\x72\x6f\x2d\x42\x2d\x50\x61\x72\x61\x6d\x53\x65\x74"
#define NID_id_GostR3410_94_CryptoPro_B_ParamSet                833
#define OBJ_id_GostR3410_94_CryptoPro_B_ParamSet                OBJ_cryptopro,32L,3L

#define SN_id_GostR3410_94_CryptoPro_C_ParamSet         "\x69\x64\x2d\x47\x6f\x73\x74\x52\x33\x34\x31\x30\x2d\x39\x34\x2d\x43\x72\x79\x70\x74\x6f\x50\x72\x6f\x2d\x43\x2d\x50\x61\x72\x61\x6d\x53\x65\x74"
#define NID_id_GostR3410_94_CryptoPro_C_ParamSet                834
#define OBJ_id_GostR3410_94_CryptoPro_C_ParamSet                OBJ_cryptopro,32L,4L

#define SN_id_GostR3410_94_CryptoPro_D_ParamSet         "\x69\x64\x2d\x47\x6f\x73\x74\x52\x33\x34\x31\x30\x2d\x39\x34\x2d\x43\x72\x79\x70\x74\x6f\x50\x72\x6f\x2d\x44\x2d\x50\x61\x72\x61\x6d\x53\x65\x74"
#define NID_id_GostR3410_94_CryptoPro_D_ParamSet                835
#define OBJ_id_GostR3410_94_CryptoPro_D_ParamSet                OBJ_cryptopro,32L,5L

#define SN_id_GostR3410_94_CryptoPro_XchA_ParamSet              "\x69\x64\x2d\x47\x6f\x73\x74\x52\x33\x34\x31\x30\x2d\x39\x34\x2d\x43\x72\x79\x70\x74\x6f\x50\x72\x6f\x2d\x58\x63\x68\x41\x2d\x50\x61\x72\x61\x6d\x53\x65\x74"
#define NID_id_GostR3410_94_CryptoPro_XchA_ParamSet             836
#define OBJ_id_GostR3410_94_CryptoPro_XchA_ParamSet             OBJ_cryptopro,33L,1L

#define SN_id_GostR3410_94_CryptoPro_XchB_ParamSet              "\x69\x64\x2d\x47\x6f\x73\x74\x52\x33\x34\x31\x30\x2d\x39\x34\x2d\x43\x72\x79\x70\x74\x6f\x50\x72\x6f\x2d\x58\x63\x68\x42\x2d\x50\x61\x72\x61\x6d\x53\x65\x74"
#define NID_id_GostR3410_94_CryptoPro_XchB_ParamSet             837
#define OBJ_id_GostR3410_94_CryptoPro_XchB_ParamSet             OBJ_cryptopro,33L,2L

#define SN_id_GostR3410_94_CryptoPro_XchC_ParamSet              "\x69\x64\x2d\x47\x6f\x73\x74\x52\x33\x34\x31\x30\x2d\x39\x34\x2d\x43\x72\x79\x70\x74\x6f\x50\x72\x6f\x2d\x58\x63\x68\x43\x2d\x50\x61\x72\x61\x6d\x53\x65\x74"
#define NID_id_GostR3410_94_CryptoPro_XchC_ParamSet             838
#define OBJ_id_GostR3410_94_CryptoPro_XchC_ParamSet             OBJ_cryptopro,33L,3L

#define SN_id_GostR3410_2001_TestParamSet               "\x69\x64\x2d\x47\x6f\x73\x74\x52\x33\x34\x31\x30\x2d\x32\x30\x30\x31\x2d\x54\x65\x73\x74\x50\x61\x72\x61\x6d\x53\x65\x74"
#define NID_id_GostR3410_2001_TestParamSet              839
#define OBJ_id_GostR3410_2001_TestParamSet              OBJ_cryptopro,35L,0L

#define SN_id_GostR3410_2001_CryptoPro_A_ParamSet               "\x69\x64\x2d\x47\x6f\x73\x74\x52\x33\x34\x31\x30\x2d\x32\x30\x30\x31\x2d\x43\x72\x79\x70\x74\x6f\x50\x72\x6f\x2d\x41\x2d\x50\x61\x72\x61\x6d\x53\x65\x74"
#define NID_id_GostR3410_2001_CryptoPro_A_ParamSet              840
#define OBJ_id_GostR3410_2001_CryptoPro_A_ParamSet              OBJ_cryptopro,35L,1L

#define SN_id_GostR3410_2001_CryptoPro_B_ParamSet               "\x69\x64\x2d\x47\x6f\x73\x74\x52\x33\x34\x31\x30\x2d\x32\x30\x30\x31\x2d\x43\x72\x79\x70\x74\x6f\x50\x72\x6f\x2d\x42\x2d\x50\x61\x72\x61\x6d\x53\x65\x74"
#define NID_id_GostR3410_2001_CryptoPro_B_ParamSet              841
#define OBJ_id_GostR3410_2001_CryptoPro_B_ParamSet              OBJ_cryptopro,35L,2L

#define SN_id_GostR3410_2001_CryptoPro_C_ParamSet               "\x69\x64\x2d\x47\x6f\x73\x74\x52\x33\x34\x31\x30\x2d\x32\x30\x30\x31\x2d\x43\x72\x79\x70\x74\x6f\x50\x72\x6f\x2d\x43\x2d\x50\x61\x72\x61\x6d\x53\x65\x74"
#define NID_id_GostR3410_2001_CryptoPro_C_ParamSet              842
#define OBJ_id_GostR3410_2001_CryptoPro_C_ParamSet              OBJ_cryptopro,35L,3L

#define SN_id_GostR3410_2001_CryptoPro_XchA_ParamSet            "\x69\x64\x2d\x47\x6f\x73\x74\x52\x33\x34\x31\x30\x2d\x32\x30\x30\x31\x2d\x43\x72\x79\x70\x74\x6f\x50\x72\x6f\x2d\x58\x63\x68\x41\x2d\x50\x61\x72\x61\x6d\x53\x65\x74"
#define NID_id_GostR3410_2001_CryptoPro_XchA_ParamSet           843
#define OBJ_id_GostR3410_2001_CryptoPro_XchA_ParamSet           OBJ_cryptopro,36L,0L

#define SN_id_GostR3410_2001_CryptoPro_XchB_ParamSet            "\x69\x64\x2d\x47\x6f\x73\x74\x52\x33\x34\x31\x30\x2d\x32\x30\x30\x31\x2d\x43\x72\x79\x70\x74\x6f\x50\x72\x6f\x2d\x58\x63\x68\x42\x2d\x50\x61\x72\x61\x6d\x53\x65\x74"
#define NID_id_GostR3410_2001_CryptoPro_XchB_ParamSet           844
#define OBJ_id_GostR3410_2001_CryptoPro_XchB_ParamSet           OBJ_cryptopro,36L,1L

#define SN_id_GostR3410_94_a            "\x69\x64\x2d\x47\x6f\x73\x74\x52\x33\x34\x31\x30\x2d\x39\x34\x2d\x61"
#define NID_id_GostR3410_94_a           845
#define OBJ_id_GostR3410_94_a           OBJ_id_GostR3410_94,1L

#define SN_id_GostR3410_94_aBis         "\x69\x64\x2d\x47\x6f\x73\x74\x52\x33\x34\x31\x30\x2d\x39\x34\x2d\x61\x42\x69\x73"
#define NID_id_GostR3410_94_aBis                846
#define OBJ_id_GostR3410_94_aBis                OBJ_id_GostR3410_94,2L

#define SN_id_GostR3410_94_b            "\x69\x64\x2d\x47\x6f\x73\x74\x52\x33\x34\x31\x30\x2d\x39\x34\x2d\x62"
#define NID_id_GostR3410_94_b           847
#define OBJ_id_GostR3410_94_b           OBJ_id_GostR3410_94,3L

#define SN_id_GostR3410_94_bBis         "\x69\x64\x2d\x47\x6f\x73\x74\x52\x33\x34\x31\x30\x2d\x39\x34\x2d\x62\x42\x69\x73"
#define NID_id_GostR3410_94_bBis                848
#define OBJ_id_GostR3410_94_bBis                OBJ_id_GostR3410_94,4L

#define SN_id_Gost28147_89_cc           "\x69\x64\x2d\x47\x6f\x73\x74\x32\x38\x31\x34\x37\x2d\x38\x39\x2d\x63\x63"
#define LN_id_Gost28147_89_cc           "\x47\x4f\x53\x54\x20\x32\x38\x31\x34\x37\x2d\x38\x39\x20\x43\x72\x79\x70\x74\x6f\x63\x6f\x6d\x20\x50\x61\x72\x61\x6d\x53\x65\x74"
#define NID_id_Gost28147_89_cc          849
#define OBJ_id_Gost28147_89_cc          OBJ_cryptocom,1L,6L,1L

#define SN_id_GostR3410_94_cc           "\x67\x6f\x73\x74\x39\x34\x63\x63"
#define LN_id_GostR3410_94_cc           "\x47\x4f\x53\x54\x20\x33\x34\x2e\x31\x30\x2d\x39\x34\x20\x43\x72\x79\x70\x74\x6f\x63\x6f\x6d"
#define NID_id_GostR3410_94_cc          850
#define OBJ_id_GostR3410_94_cc          OBJ_cryptocom,1L,5L,3L

#define SN_id_GostR3410_2001_cc         "\x67\x6f\x73\x74\x32\x30\x30\x31\x63\x63"
#define LN_id_GostR3410_2001_cc         "\x47\x4f\x53\x54\x20\x33\x34\x2e\x31\x30\x2d\x32\x30\x30\x31\x20\x43\x72\x79\x70\x74\x6f\x63\x6f\x6d"
#define NID_id_GostR3410_2001_cc                851
#define OBJ_id_GostR3410_2001_cc                OBJ_cryptocom,1L,5L,4L

#define SN_id_GostR3411_94_with_GostR3410_94_cc         "\x69\x64\x2d\x47\x6f\x73\x74\x52\x33\x34\x31\x31\x2d\x39\x34\x2d\x77\x69\x74\x68\x2d\x47\x6f\x73\x74\x52\x33\x34\x31\x30\x2d\x39\x34\x2d\x63\x63"
#define LN_id_GostR3411_94_with_GostR3410_94_cc         "\x47\x4f\x53\x54\x20\x52\x20\x33\x34\x2e\x31\x31\x2d\x39\x34\x20\x77\x69\x74\x68\x20\x47\x4f\x53\x54\x20\x52\x20\x33\x34\x2e\x31\x30\x2d\x39\x34\x20\x43\x72\x79\x70\x74\x6f\x63\x6f\x6d"
#define NID_id_GostR3411_94_with_GostR3410_94_cc                852
#define OBJ_id_GostR3411_94_with_GostR3410_94_cc                OBJ_cryptocom,1L,3L,3L

#define SN_id_GostR3411_94_with_GostR3410_2001_cc               "\x69\x64\x2d\x47\x6f\x73\x74\x52\x33\x34\x31\x31\x2d\x39\x34\x2d\x77\x69\x74\x68\x2d\x47\x6f\x73\x74\x52\x33\x34\x31\x30\x2d\x32\x30\x30\x31\x2d\x63\x63"
#define LN_id_GostR3411_94_with_GostR3410_2001_cc               "\x47\x4f\x53\x54\x20\x52\x20\x33\x34\x2e\x31\x31\x2d\x39\x34\x20\x77\x69\x74\x68\x20\x47\x4f\x53\x54\x20\x52\x20\x33\x34\x2e\x31\x30\x2d\x32\x30\x30\x31\x20\x43\x72\x79\x70\x74\x6f\x63\x6f\x6d"
#define NID_id_GostR3411_94_with_GostR3410_2001_cc              853
#define OBJ_id_GostR3411_94_with_GostR3410_2001_cc              OBJ_cryptocom,1L,3L,4L

#define SN_id_GostR3410_2001_ParamSet_cc                "\x69\x64\x2d\x47\x6f\x73\x74\x52\x33\x34\x31\x30\x2d\x32\x30\x30\x31\x2d\x50\x61\x72\x61\x6d\x53\x65\x74\x2d\x63\x63"
#define LN_id_GostR3410_2001_ParamSet_cc                "\x47\x4f\x53\x54\x20\x52\x20\x33\x34\x31\x30\x2d\x32\x30\x30\x31\x20\x50\x61\x72\x61\x6d\x65\x74\x65\x72\x20\x53\x65\x74\x20\x43\x72\x79\x70\x74\x6f\x63\x6f\x6d"
#define NID_id_GostR3410_2001_ParamSet_cc               854
#define OBJ_id_GostR3410_2001_ParamSet_cc               OBJ_cryptocom,1L,8L,1L

#define SN_camellia_128_cbc             "\x43\x41\x4d\x45\x4c\x4c\x49\x41\x2d\x31\x32\x38\x2d\x43\x42\x43"
#define LN_camellia_128_cbc             "\x63\x61\x6d\x65\x6c\x6c\x69\x61\x2d\x31\x32\x38\x2d\x63\x62\x63"
#define NID_camellia_128_cbc            751
#define OBJ_camellia_128_cbc            1L,2L,392L,200011L,61L,1L,1L,1L,2L

#define SN_camellia_192_cbc             "\x43\x41\x4d\x45\x4c\x4c\x49\x41\x2d\x31\x39\x32\x2d\x43\x42\x43"
#define LN_camellia_192_cbc             "\x63\x61\x6d\x65\x6c\x6c\x69\x61\x2d\x31\x39\x32\x2d\x63\x62\x63"
#define NID_camellia_192_cbc            752
#define OBJ_camellia_192_cbc            1L,2L,392L,200011L,61L,1L,1L,1L,3L

#define SN_camellia_256_cbc             "\x43\x41\x4d\x45\x4c\x4c\x49\x41\x2d\x32\x35\x36\x2d\x43\x42\x43"
#define LN_camellia_256_cbc             "\x63\x61\x6d\x65\x6c\x6c\x69\x61\x2d\x32\x35\x36\x2d\x63\x62\x63"
#define NID_camellia_256_cbc            753
#define OBJ_camellia_256_cbc            1L,2L,392L,200011L,61L,1L,1L,1L,4L

#define SN_id_camellia128_wrap          "\x69\x64\x2d\x63\x61\x6d\x65\x6c\x6c\x69\x61\x31\x32\x38\x2d\x77\x72\x61\x70"
#define NID_id_camellia128_wrap         907
#define OBJ_id_camellia128_wrap         1L,2L,392L,200011L,61L,1L,1L,3L,2L

#define SN_id_camellia192_wrap          "\x69\x64\x2d\x63\x61\x6d\x65\x6c\x6c\x69\x61\x31\x39\x32\x2d\x77\x72\x61\x70"
#define NID_id_camellia192_wrap         908
#define OBJ_id_camellia192_wrap         1L,2L,392L,200011L,61L,1L,1L,3L,3L

#define SN_id_camellia256_wrap          "\x69\x64\x2d\x63\x61\x6d\x65\x6c\x6c\x69\x61\x32\x35\x36\x2d\x77\x72\x61\x70"
#define NID_id_camellia256_wrap         909
#define OBJ_id_camellia256_wrap         1L,2L,392L,200011L,61L,1L,1L,3L,4L

#define OBJ_ntt_ds              0L,3L,4401L,5L

#define OBJ_camellia            OBJ_ntt_ds,3L,1L,9L

#define SN_camellia_128_ecb             "\x43\x41\x4d\x45\x4c\x4c\x49\x41\x2d\x31\x32\x38\x2d\x45\x43\x42"
#define LN_camellia_128_ecb             "\x63\x61\x6d\x65\x6c\x6c\x69\x61\x2d\x31\x32\x38\x2d\x65\x63\x62"
#define NID_camellia_128_ecb            754
#define OBJ_camellia_128_ecb            OBJ_camellia,1L

#define SN_camellia_128_ofb128          "\x43\x41\x4d\x45\x4c\x4c\x49\x41\x2d\x31\x32\x38\x2d\x4f\x46\x42"
#define LN_camellia_128_ofb128          "\x63\x61\x6d\x65\x6c\x6c\x69\x61\x2d\x31\x32\x38\x2d\x6f\x66\x62"
#define NID_camellia_128_ofb128         766
#define OBJ_camellia_128_ofb128         OBJ_camellia,3L

#define SN_camellia_128_cfb128          "\x43\x41\x4d\x45\x4c\x4c\x49\x41\x2d\x31\x32\x38\x2d\x43\x46\x42"
#define LN_camellia_128_cfb128          "\x63\x61\x6d\x65\x6c\x6c\x69\x61\x2d\x31\x32\x38\x2d\x63\x66\x62"
#define NID_camellia_128_cfb128         757
#define OBJ_camellia_128_cfb128         OBJ_camellia,4L

#define SN_camellia_192_ecb             "\x43\x41\x4d\x45\x4c\x4c\x49\x41\x2d\x31\x39\x32\x2d\x45\x43\x42"
#define LN_camellia_192_ecb             "\x63\x61\x6d\x65\x6c\x6c\x69\x61\x2d\x31\x39\x32\x2d\x65\x63\x62"
#define NID_camellia_192_ecb            755
#define OBJ_camellia_192_ecb            OBJ_camellia,21L

#define SN_camellia_192_ofb128          "\x43\x41\x4d\x45\x4c\x4c\x49\x41\x2d\x31\x39\x32\x2d\x4f\x46\x42"
#define LN_camellia_192_ofb128          "\x63\x61\x6d\x65\x6c\x6c\x69\x61\x2d\x31\x39\x32\x2d\x6f\x66\x62"
#define NID_camellia_192_ofb128         767
#define OBJ_camellia_192_ofb128         OBJ_camellia,23L

#define SN_camellia_192_cfb128          "\x43\x41\x4d\x45\x4c\x4c\x49\x41\x2d\x31\x39\x32\x2d\x43\x46\x42"
#define LN_camellia_192_cfb128          "\x63\x61\x6d\x65\x6c\x6c\x69\x61\x2d\x31\x39\x32\x2d\x63\x66\x62"
#define NID_camellia_192_cfb128         758
#define OBJ_camellia_192_cfb128         OBJ_camellia,24L

#define SN_camellia_256_ecb             "\x43\x41\x4d\x45\x4c\x4c\x49\x41\x2d\x32\x35\x36\x2d\x45\x43\x42"
#define LN_camellia_256_ecb             "\x63\x61\x6d\x65\x6c\x6c\x69\x61\x2d\x32\x35\x36\x2d\x65\x63\x62"
#define NID_camellia_256_ecb            756
#define OBJ_camellia_256_ecb            OBJ_camellia,41L

#define SN_camellia_256_ofb128          "\x43\x41\x4d\x45\x4c\x4c\x49\x41\x2d\x32\x35\x36\x2d\x4f\x46\x42"
#define LN_camellia_256_ofb128          "\x63\x61\x6d\x65\x6c\x6c\x69\x61\x2d\x32\x35\x36\x2d\x6f\x66\x62"
#define NID_camellia_256_ofb128         768
#define OBJ_camellia_256_ofb128         OBJ_camellia,43L

#define SN_camellia_256_cfb128          "\x43\x41\x4d\x45\x4c\x4c\x49\x41\x2d\x32\x35\x36\x2d\x43\x46\x42"
#define LN_camellia_256_cfb128          "\x63\x61\x6d\x65\x6c\x6c\x69\x61\x2d\x32\x35\x36\x2d\x63\x66\x62"
#define NID_camellia_256_cfb128         759
#define OBJ_camellia_256_cfb128         OBJ_camellia,44L

#define SN_camellia_128_cfb1            "\x43\x41\x4d\x45\x4c\x4c\x49\x41\x2d\x31\x32\x38\x2d\x43\x46\x42\x31"
#define LN_camellia_128_cfb1            "\x63\x61\x6d\x65\x6c\x6c\x69\x61\x2d\x31\x32\x38\x2d\x63\x66\x62\x31"
#define NID_camellia_128_cfb1           760

#define SN_camellia_192_cfb1            "\x43\x41\x4d\x45\x4c\x4c\x49\x41\x2d\x31\x39\x32\x2d\x43\x46\x42\x31"
#define LN_camellia_192_cfb1            "\x63\x61\x6d\x65\x6c\x6c\x69\x61\x2d\x31\x39\x32\x2d\x63\x66\x62\x31"
#define NID_camellia_192_cfb1           761

#define SN_camellia_256_cfb1            "\x43\x41\x4d\x45\x4c\x4c\x49\x41\x2d\x32\x35\x36\x2d\x43\x46\x42\x31"
#define LN_camellia_256_cfb1            "\x63\x61\x6d\x65\x6c\x6c\x69\x61\x2d\x32\x35\x36\x2d\x63\x66\x62\x31"
#define NID_camellia_256_cfb1           762

#define SN_camellia_128_cfb8            "\x43\x41\x4d\x45\x4c\x4c\x49\x41\x2d\x31\x32\x38\x2d\x43\x46\x42\x38"
#define LN_camellia_128_cfb8            "\x63\x61\x6d\x65\x6c\x6c\x69\x61\x2d\x31\x32\x38\x2d\x63\x66\x62\x38"
#define NID_camellia_128_cfb8           763

#define SN_camellia_192_cfb8            "\x43\x41\x4d\x45\x4c\x4c\x49\x41\x2d\x31\x39\x32\x2d\x43\x46\x42\x38"
#define LN_camellia_192_cfb8            "\x63\x61\x6d\x65\x6c\x6c\x69\x61\x2d\x31\x39\x32\x2d\x63\x66\x62\x38"
#define NID_camellia_192_cfb8           764

#define SN_camellia_256_cfb8            "\x43\x41\x4d\x45\x4c\x4c\x49\x41\x2d\x32\x35\x36\x2d\x43\x46\x42\x38"
#define LN_camellia_256_cfb8            "\x63\x61\x6d\x65\x6c\x6c\x69\x61\x2d\x32\x35\x36\x2d\x63\x66\x62\x38"
#define NID_camellia_256_cfb8           765

#define SN_kisa         "\x4b\x49\x53\x41"
#define LN_kisa         "\x6b\x69\x73\x61"
#define NID_kisa                773
#define OBJ_kisa                OBJ_member_body,410L,200004L

#define SN_seed_ecb             "\x53\x45\x45\x44\x2d\x45\x43\x42"
#define LN_seed_ecb             "\x73\x65\x65\x64\x2d\x65\x63\x62"
#define NID_seed_ecb            776
#define OBJ_seed_ecb            OBJ_kisa,1L,3L

#define SN_seed_cbc             "\x53\x45\x45\x44\x2d\x43\x42\x43"
#define LN_seed_cbc             "\x73\x65\x65\x64\x2d\x63\x62\x63"
#define NID_seed_cbc            777
#define OBJ_seed_cbc            OBJ_kisa,1L,4L

#define SN_seed_cfb128          "\x53\x45\x45\x44\x2d\x43\x46\x42"
#define LN_seed_cfb128          "\x73\x65\x65\x64\x2d\x63\x66\x62"
#define NID_seed_cfb128         779
#define OBJ_seed_cfb128         OBJ_kisa,1L,5L

#define SN_seed_ofb128          "\x53\x45\x45\x44\x2d\x4f\x46\x42"
#define LN_seed_ofb128          "\x73\x65\x65\x64\x2d\x6f\x66\x62"
#define NID_seed_ofb128         778
#define OBJ_seed_ofb128         OBJ_kisa,1L,6L

#define SN_hmac         "\x48\x4d\x41\x43"
#define LN_hmac         "\x68\x6d\x61\x63"
#define NID_hmac                855

#define SN_cmac         "\x43\x4d\x41\x43"
#define LN_cmac         "\x63\x6d\x61\x63"
#define NID_cmac                894

#define SN_rc4_hmac_md5         "\x52\x43\x34\x2d\x48\x4d\x41\x43\x2d\x4d\x44\x35"
#define LN_rc4_hmac_md5         "\x72\x63\x34\x2d\x68\x6d\x61\x63\x2d\x6d\x64\x35"
#define NID_rc4_hmac_md5                915

#define SN_aes_128_cbc_hmac_sha1                "\x41\x45\x53\x2d\x31\x32\x38\x2d\x43\x42\x43\x2d\x48\x4d\x41\x43\x2d\x53\x48\x41\x31"
#define LN_aes_128_cbc_hmac_sha1                "\x61\x65\x73\x2d\x31\x32\x38\x2d\x63\x62\x63\x2d\x68\x6d\x61\x63\x2d\x73\x68\x61\x31"
#define NID_aes_128_cbc_hmac_sha1               916

#define SN_aes_192_cbc_hmac_sha1                "\x41\x45\x53\x2d\x31\x39\x32\x2d\x43\x42\x43\x2d\x48\x4d\x41\x43\x2d\x53\x48\x41\x31"
#define LN_aes_192_cbc_hmac_sha1                "\x61\x65\x73\x2d\x31\x39\x32\x2d\x63\x62\x63\x2d\x68\x6d\x61\x63\x2d\x73\x68\x61\x31"
#define NID_aes_192_cbc_hmac_sha1               917

#define SN_aes_256_cbc_hmac_sha1                "\x41\x45\x53\x2d\x32\x35\x36\x2d\x43\x42\x43\x2d\x48\x4d\x41\x43\x2d\x53\x48\x41\x31"
#define LN_aes_256_cbc_hmac_sha1                "\x61\x65\x73\x2d\x32\x35\x36\x2d\x63\x62\x63\x2d\x68\x6d\x61\x63\x2d\x73\x68\x61\x31"
#define NID_aes_256_cbc_hmac_sha1               918

#define SN_aes_128_cbc_hmac_sha256              "\x41\x45\x53\x2d\x31\x32\x38\x2d\x43\x42\x43\x2d\x48\x4d\x41\x43\x2d\x53\x48\x41\x32\x35\x36"
#define LN_aes_128_cbc_hmac_sha256              "\x61\x65\x73\x2d\x31\x32\x38\x2d\x63\x62\x63\x2d\x68\x6d\x61\x63\x2d\x73\x68\x61\x32\x35\x36"
#define NID_aes_128_cbc_hmac_sha256             948

#define SN_aes_192_cbc_hmac_sha256              "\x41\x45\x53\x2d\x31\x39\x32\x2d\x43\x42\x43\x2d\x48\x4d\x41\x43\x2d\x53\x48\x41\x32\x35\x36"
#define LN_aes_192_cbc_hmac_sha256              "\x61\x65\x73\x2d\x31\x39\x32\x2d\x63\x62\x63\x2d\x68\x6d\x61\x63\x2d\x73\x68\x61\x32\x35\x36"
#define NID_aes_192_cbc_hmac_sha256             949

#define SN_aes_256_cbc_hmac_sha256              "\x41\x45\x53\x2d\x32\x35\x36\x2d\x43\x42\x43\x2d\x48\x4d\x41\x43\x2d\x53\x48\x41\x32\x35\x36"
#define LN_aes_256_cbc_hmac_sha256              "\x61\x65\x73\x2d\x32\x35\x36\x2d\x63\x62\x63\x2d\x68\x6d\x61\x63\x2d\x73\x68\x61\x32\x35\x36"
#define NID_aes_256_cbc_hmac_sha256             950

#define SN_dhpublicnumber               "\x64\x68\x70\x75\x62\x6c\x69\x63\x6e\x75\x6d\x62\x65\x72"
#define LN_dhpublicnumber               "\x58\x39\x2e\x34\x32\x20\x44\x48"
#define NID_dhpublicnumber              920
#define OBJ_dhpublicnumber              OBJ_ISO_US,10046L,2L,1L

#define SN_brainpoolP160r1              "\x62\x72\x61\x69\x6e\x70\x6f\x6f\x6c\x50\x31\x36\x30\x72\x31"
#define NID_brainpoolP160r1             921
#define OBJ_brainpoolP160r1             1L,3L,36L,3L,3L,2L,8L,1L,1L,1L

#define SN_brainpoolP160t1              "\x62\x72\x61\x69\x6e\x70\x6f\x6f\x6c\x50\x31\x36\x30\x74\x31"
#define NID_brainpoolP160t1             922
#define OBJ_brainpoolP160t1             1L,3L,36L,3L,3L,2L,8L,1L,1L,2L

#define SN_brainpoolP192r1              "\x62\x72\x61\x69\x6e\x70\x6f\x6f\x6c\x50\x31\x39\x32\x72\x31"
#define NID_brainpoolP192r1             923
#define OBJ_brainpoolP192r1             1L,3L,36L,3L,3L,2L,8L,1L,1L,3L

#define SN_brainpoolP192t1              "\x62\x72\x61\x69\x6e\x70\x6f\x6f\x6c\x50\x31\x39\x32\x74\x31"
#define NID_brainpoolP192t1             924
#define OBJ_brainpoolP192t1             1L,3L,36L,3L,3L,2L,8L,1L,1L,4L

#define SN_brainpoolP224r1              "\x62\x72\x61\x69\x6e\x70\x6f\x6f\x6c\x50\x32\x32\x34\x72\x31"
#define NID_brainpoolP224r1             925
#define OBJ_brainpoolP224r1             1L,3L,36L,3L,3L,2L,8L,1L,1L,5L

#define SN_brainpoolP224t1              "\x62\x72\x61\x69\x6e\x70\x6f\x6f\x6c\x50\x32\x32\x34\x74\x31"
#define NID_brainpoolP224t1             926
#define OBJ_brainpoolP224t1             1L,3L,36L,3L,3L,2L,8L,1L,1L,6L

#define SN_brainpoolP256r1              "\x62\x72\x61\x69\x6e\x70\x6f\x6f\x6c\x50\x32\x35\x36\x72\x31"
#define NID_brainpoolP256r1             927
#define OBJ_brainpoolP256r1             1L,3L,36L,3L,3L,2L,8L,1L,1L,7L

#define SN_brainpoolP256t1              "\x62\x72\x61\x69\x6e\x70\x6f\x6f\x6c\x50\x32\x35\x36\x74\x31"
#define NID_brainpoolP256t1             928
#define OBJ_brainpoolP256t1             1L,3L,36L,3L,3L,2L,8L,1L,1L,8L

#define SN_brainpoolP320r1              "\x62\x72\x61\x69\x6e\x70\x6f\x6f\x6c\x50\x33\x32\x30\x72\x31"
#define NID_brainpoolP320r1             929
#define OBJ_brainpoolP320r1             1L,3L,36L,3L,3L,2L,8L,1L,1L,9L

#define SN_brainpoolP320t1              "\x62\x72\x61\x69\x6e\x70\x6f\x6f\x6c\x50\x33\x32\x30\x74\x31"
#define NID_brainpoolP320t1             930
#define OBJ_brainpoolP320t1             1L,3L,36L,3L,3L,2L,8L,1L,1L,10L

#define SN_brainpoolP384r1              "\x62\x72\x61\x69\x6e\x70\x6f\x6f\x6c\x50\x33\x38\x34\x72\x31"
#define NID_brainpoolP384r1             931
#define OBJ_brainpoolP384r1             1L,3L,36L,3L,3L,2L,8L,1L,1L,11L

#define SN_brainpoolP384t1              "\x62\x72\x61\x69\x6e\x70\x6f\x6f\x6c\x50\x33\x38\x34\x74\x31"
#define NID_brainpoolP384t1             932
#define OBJ_brainpoolP384t1             1L,3L,36L,3L,3L,2L,8L,1L,1L,12L

#define SN_brainpoolP512r1              "\x62\x72\x61\x69\x6e\x70\x6f\x6f\x6c\x50\x35\x31\x32\x72\x31"
#define NID_brainpoolP512r1             933
#define OBJ_brainpoolP512r1             1L,3L,36L,3L,3L,2L,8L,1L,1L,13L

#define SN_brainpoolP512t1              "\x62\x72\x61\x69\x6e\x70\x6f\x6f\x6c\x50\x35\x31\x32\x74\x31"
#define NID_brainpoolP512t1             934
#define OBJ_brainpoolP512t1             1L,3L,36L,3L,3L,2L,8L,1L,1L,14L

#define OBJ_x9_63_scheme                1L,3L,133L,16L,840L,63L,0L

#define OBJ_secg_scheme         OBJ_certicom_arc,1L

#define SN_dhSinglePass_stdDH_sha1kdf_scheme            "\x64\x68\x53\x69\x6e\x67\x6c\x65\x50\x61\x73\x73\x2d\x73\x74\x64\x44\x48\x2d\x73\x68\x61\x31\x6b\x64\x66\x2d\x73\x63\x68\x65\x6d\x65"
#define NID_dhSinglePass_stdDH_sha1kdf_scheme           936
#define OBJ_dhSinglePass_stdDH_sha1kdf_scheme           OBJ_x9_63_scheme,2L

#define SN_dhSinglePass_stdDH_sha224kdf_scheme          "\x64\x68\x53\x69\x6e\x67\x6c\x65\x50\x61\x73\x73\x2d\x73\x74\x64\x44\x48\x2d\x73\x68\x61\x32\x32\x34\x6b\x64\x66\x2d\x73\x63\x68\x65\x6d\x65"
#define NID_dhSinglePass_stdDH_sha224kdf_scheme         937
#define OBJ_dhSinglePass_stdDH_sha224kdf_scheme         OBJ_secg_scheme,11L,0L

#define SN_dhSinglePass_stdDH_sha256kdf_scheme          "\x64\x68\x53\x69\x6e\x67\x6c\x65\x50\x61\x73\x73\x2d\x73\x74\x64\x44\x48\x2d\x73\x68\x61\x32\x35\x36\x6b\x64\x66\x2d\x73\x63\x68\x65\x6d\x65"
#define NID_dhSinglePass_stdDH_sha256kdf_scheme         938
#define OBJ_dhSinglePass_stdDH_sha256kdf_scheme         OBJ_secg_scheme,11L,1L

#define SN_dhSinglePass_stdDH_sha384kdf_scheme          "\x64\x68\x53\x69\x6e\x67\x6c\x65\x50\x61\x73\x73\x2d\x73\x74\x64\x44\x48\x2d\x73\x68\x61\x33\x38\x34\x6b\x64\x66\x2d\x73\x63\x68\x65\x6d\x65"
#define NID_dhSinglePass_stdDH_sha384kdf_scheme         939
#define OBJ_dhSinglePass_stdDH_sha384kdf_scheme         OBJ_secg_scheme,11L,2L

#define SN_dhSinglePass_stdDH_sha512kdf_scheme          "\x64\x68\x53\x69\x6e\x67\x6c\x65\x50\x61\x73\x73\x2d\x73\x74\x64\x44\x48\x2d\x73\x68\x61\x35\x31\x32\x6b\x64\x66\x2d\x73\x63\x68\x65\x6d\x65"
#define NID_dhSinglePass_stdDH_sha512kdf_scheme         940
#define OBJ_dhSinglePass_stdDH_sha512kdf_scheme         OBJ_secg_scheme,11L,3L

#define SN_dhSinglePass_cofactorDH_sha1kdf_scheme               "\x64\x68\x53\x69\x6e\x67\x6c\x65\x50\x61\x73\x73\x2d\x63\x6f\x66\x61\x63\x74\x6f\x72\x44\x48\x2d\x73\x68\x61\x31\x6b\x64\x66\x2d\x73\x63\x68\x65\x6d\x65"
#define NID_dhSinglePass_cofactorDH_sha1kdf_scheme              941
#define OBJ_dhSinglePass_cofactorDH_sha1kdf_scheme              OBJ_x9_63_scheme,3L

#define SN_dhSinglePass_cofactorDH_sha224kdf_scheme             "\x64\x68\x53\x69\x6e\x67\x6c\x65\x50\x61\x73\x73\x2d\x63\x6f\x66\x61\x63\x74\x6f\x72\x44\x48\x2d\x73\x68\x61\x32\x32\x34\x6b\x64\x66\x2d\x73\x63\x68\x65\x6d\x65"
#define NID_dhSinglePass_cofactorDH_sha224kdf_scheme            942
#define OBJ_dhSinglePass_cofactorDH_sha224kdf_scheme            OBJ_secg_scheme,14L,0L

#define SN_dhSinglePass_cofactorDH_sha256kdf_scheme             "\x64\x68\x53\x69\x6e\x67\x6c\x65\x50\x61\x73\x73\x2d\x63\x6f\x66\x61\x63\x74\x6f\x72\x44\x48\x2d\x73\x68\x61\x32\x35\x36\x6b\x64\x66\x2d\x73\x63\x68\x65\x6d\x65"
#define NID_dhSinglePass_cofactorDH_sha256kdf_scheme            943
#define OBJ_dhSinglePass_cofactorDH_sha256kdf_scheme            OBJ_secg_scheme,14L,1L

#define SN_dhSinglePass_cofactorDH_sha384kdf_scheme             "\x64\x68\x53\x69\x6e\x67\x6c\x65\x50\x61\x73\x73\x2d\x63\x6f\x66\x61\x63\x74\x6f\x72\x44\x48\x2d\x73\x68\x61\x33\x38\x34\x6b\x64\x66\x2d\x73\x63\x68\x65\x6d\x65"
#define NID_dhSinglePass_cofactorDH_sha384kdf_scheme            944
#define OBJ_dhSinglePass_cofactorDH_sha384kdf_scheme            OBJ_secg_scheme,14L,2L

#define SN_dhSinglePass_cofactorDH_sha512kdf_scheme             "\x64\x68\x53\x69\x6e\x67\x6c\x65\x50\x61\x73\x73\x2d\x63\x6f\x66\x61\x63\x74\x6f\x72\x44\x48\x2d\x73\x68\x61\x35\x31\x32\x6b\x64\x66\x2d\x73\x63\x68\x65\x6d\x65"
#define NID_dhSinglePass_cofactorDH_sha512kdf_scheme            945
#define OBJ_dhSinglePass_cofactorDH_sha512kdf_scheme            OBJ_secg_scheme,14L,3L

#define SN_dh_std_kdf           "\x64\x68\x2d\x73\x74\x64\x2d\x6b\x64\x66"
#define NID_dh_std_kdf          946

#define SN_dh_cofactor_kdf              "\x64\x68\x2d\x63\x6f\x66\x61\x63\x74\x6f\x72\x2d\x6b\x64\x66"
#define NID_dh_cofactor_kdf             947

#define SN_ct_precert_scts              "\x63\x74\x5f\x70\x72\x65\x63\x65\x72\x74\x5f\x73\x63\x74\x73"
#define LN_ct_precert_scts              "\x43\x54\x20\x50\x72\x65\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x53\x43\x54\x73"
#define NID_ct_precert_scts             951
#define OBJ_ct_precert_scts             1L,3L,6L,1L,4L,1L,11129L,2L,4L,2L

#define SN_ct_precert_poison            "\x63\x74\x5f\x70\x72\x65\x63\x65\x72\x74\x5f\x70\x6f\x69\x73\x6f\x6e"
#define LN_ct_precert_poison            "\x43\x54\x20\x50\x72\x65\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x50\x6f\x69\x73\x6f\x6e"
#define NID_ct_precert_poison           952
#define OBJ_ct_precert_poison           1L,3L,6L,1L,4L,1L,11129L,2L,4L,3L

#define SN_ct_precert_signer            "\x63\x74\x5f\x70\x72\x65\x63\x65\x72\x74\x5f\x73\x69\x67\x6e\x65\x72"
#define LN_ct_precert_signer            "\x43\x54\x20\x50\x72\x65\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x53\x69\x67\x6e\x65\x72"
#define NID_ct_precert_signer           953
#define OBJ_ct_precert_signer           1L,3L,6L,1L,4L,1L,11129L,2L,4L,4L

#define SN_ct_cert_scts         "\x63\x74\x5f\x63\x65\x72\x74\x5f\x73\x63\x74\x73"
#define LN_ct_cert_scts         "\x43\x54\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x53\x43\x54\x73"
#define NID_ct_cert_scts                954
#define OBJ_ct_cert_scts                1L,3L,6L,1L,4L,1L,11129L,2L,4L,5L

#define SN_jurisdictionLocalityName             "\x6a\x75\x72\x69\x73\x64\x69\x63\x74\x69\x6f\x6e\x4c"
#define LN_jurisdictionLocalityName             "\x6a\x75\x72\x69\x73\x64\x69\x63\x74\x69\x6f\x6e\x4c\x6f\x63\x61\x6c\x69\x74\x79\x4e\x61\x6d\x65"
#define NID_jurisdictionLocalityName            955
#define OBJ_jurisdictionLocalityName            1L,3L,6L,1L,4L,1L,311L,60L,2L,1L,1L

#define SN_jurisdictionStateOrProvinceName              "\x6a\x75\x72\x69\x73\x64\x69\x63\x74\x69\x6f\x6e\x53\x54"
#define LN_jurisdictionStateOrProvinceName              "\x6a\x75\x72\x69\x73\x64\x69\x63\x74\x69\x6f\x6e\x53\x74\x61\x74\x65\x4f\x72\x50\x72\x6f\x76\x69\x6e\x63\x65\x4e\x61\x6d\x65"
#define NID_jurisdictionStateOrProvinceName             956
#define OBJ_jurisdictionStateOrProvinceName             1L,3L,6L,1L,4L,1L,311L,60L,2L,1L,2L

#define SN_jurisdictionCountryName              "\x6a\x75\x72\x69\x73\x64\x69\x63\x74\x69\x6f\x6e\x43"
#define LN_jurisdictionCountryName              "\x6a\x75\x72\x69\x73\x64\x69\x63\x74\x69\x6f\x6e\x43\x6f\x75\x6e\x74\x72\x79\x4e\x61\x6d\x65"
#define NID_jurisdictionCountryName             957
#define OBJ_jurisdictionCountryName             1L,3L,6L,1L,4L,1L,311L,60L,2L,1L,3L
