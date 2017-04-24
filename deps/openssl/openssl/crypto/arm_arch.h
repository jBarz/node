#ifndef __ARM_ARCH_H__
# define __ARM_ARCH_H__

# if !defined(__ARM_ARCH__)
#  if defined(__CC_ARM)
#   define __ARM_ARCH__ __TARGET_ARCH_ARM
#   if defined(__BIG_ENDIAN)
#    define __ARMEB__
#   else
#    define __ARMEL__
#   endif
#  elif defined(__GNUC__)
#   if   defined(__aarch64__)
#    define __ARM_ARCH__ 8
#    if __BYTE_ORDER__==__ORDER_BIG_ENDIAN__
#     define __ARMEB__
#    else
#     define __ARMEL__
#    endif
  /*
   * Why doesn't gcc define __ARM_ARCH__? Instead it defines
   * bunch of below macros. See all_architectires[] table in
   * gcc/config/arm/arm.c. On a side note it defines
   * __ARMEL__/__ARMEB__ for little-/big-endian.
   */
#   elif defined(__ARM_ARCH)
#    define __ARM_ARCH__ __ARM_ARCH
#   elif defined(__ARM_ARCH_8A__)
#    define __ARM_ARCH__ 8
#   elif defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__)     || \
        defined(__ARM_ARCH_7R__)|| defined(__ARM_ARCH_7M__)     || \
        defined(__ARM_ARCH_7EM__)
#    define __ARM_ARCH__ 7
#   elif defined(__ARM_ARCH_6__) || defined(__ARM_ARCH_6J__)     || \
        defined(__ARM_ARCH_6K__)|| defined(__ARM_ARCH_6M__)     || \
        defined(__ARM_ARCH_6Z__)|| defined(__ARM_ARCH_6ZK__)    || \
        defined(__ARM_ARCH_6T2__)
#    define __ARM_ARCH__ 6
#   elif defined(__ARM_ARCH_5__) || defined(__ARM_ARCH_5T__)     || \
        defined(__ARM_ARCH_5E__)|| defined(__ARM_ARCH_5TE__)    || \
        defined(__ARM_ARCH_5TEJ__)
#    define __ARM_ARCH__ 5
#   elif defined(__ARM_ARCH_4__) || defined(__ARM_ARCH_4T__)
#    define __ARM_ARCH__ 4
#   else
#    error "\x75\x6e\x73\x75\x70\x70\x6f\x72\x74\x65\x64\x20\x41\x52\x4d\x20\x61\x72\x63\x68\x69\x74\x65\x63\x74\x75\x72\x65"
#   endif
#  endif
# endif

# ifdef OPENSSL_FIPSCANISTER
#  include <openssl/fipssyms.h>
# endif

# if !defined(__ARM_MAX_ARCH__)
#  define __ARM_MAX_ARCH__ __ARM_ARCH__
# endif

# if __ARM_MAX_ARCH__<__ARM_ARCH__
#  error "\x5f\x5f\x41\x52\x4d\x5f\x4d\x41\x58\x5f\x41\x52\x43\x48\x5f\x5f\x20\x63\x61\x6e\x27\x74\x20\x62\x65\x20\x6c\x65\x73\x73\x20\x74\x68\x61\x6e\x20\x5f\x5f\x41\x52\x4d\x5f\x41\x52\x43\x48\x5f\x5f"
# elif __ARM_MAX_ARCH__!=__ARM_ARCH__
#  if __ARM_ARCH__<7 && __ARM_MAX_ARCH__>=7 && defined(__ARMEB__)
#   error "\x63\x61\x6e\x27\x74\x20\x62\x75\x69\x6c\x64\x20\x75\x6e\x69\x76\x65\x72\x73\x61\x6c\x20\x62\x69\x67\x2d\x65\x6e\x64\x69\x61\x6e\x20\x62\x69\x6e\x61\x72\x79"
#  endif
# endif

# if !__ASSEMBLER__
extern unsigned int OPENSSL_armcap_P;
# endif

# define ARMV7_NEON      (1<<0)
# define ARMV7_TICK      (1<<1)
# define ARMV8_AES       (1<<2)
# define ARMV8_SHA1      (1<<3)
# define ARMV8_SHA256    (1<<4)
# define ARMV8_PMULL     (1<<5)

#endif
