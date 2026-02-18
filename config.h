#ifndef BLOCK_CIPHER_CONFIG_H
#define BLOCK_CIPHER_CONFIG_H

/* Define fixed width integer types */

#if __STDC_VERSION__ >= 199901L

#include <stdint.h>

typedef uint8_t blkcphr_u8_t;
typedef uint16_t blkcphr_u16_t;
typedef uint32_t blkcphr_u32_t;
typedef uint64_t blkcphr_u64_t;

#else /* C89 */

#include <limits.h>

typedef unsigned char blkcphr_u8_t;
typedef unsigned short blkcphr_u16_t;

#if ULONG_MAX == 0xFFFFFFFFul
typedef unsigned long blkcphr_u32_t;
#else
typedef unsigned int  blkcphr_u32_t;
#endif

#if defined(__GNUC__)
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Wlong-long"
typedef unsigned long long blkcphr_u64_t;
#  pragma GCC diagnostic pop
#elif defined(_MSC_VER)
typedef unsigned __int64 blkcphr_u64_t;
#else
#  error Unsupported copmiler
#endif

#endif /* __STDC_VERSION__ >= 199901L */

/* Integer byte swap functions */

#if defined(__GNUC__)
#  define blkcphr_bswap16 __builtin_bswap16
#  define blkcphr_bswap32 __builtin_bswap32
#  define blkcphr_bswap64 __builtin_bswap64
#elif defined(_MSC_VER)
#  include <stdlib.h>
#  define blkcphr_bswap16 _byteswap_ushort
#  define blkcphr_bswap32 _byteswap_ulong
#  define blkcphr_bswap64 _byteswap_uint64
#else
#  error Unsupported compiler
#endif

/* Detecting endianess */

#if defined(__GNUC__)
#  if defined(__BYTE_ORDER__)
#    if   __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#      define BLKCPHR_IS_LITTLE 1
#      define BLKCPHR_IS_BIG    0
#    elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#      define BLKCPHR_IS_LITTLE 0
#      define BLKCPHR_IS_BIG    1
#    else
#      error Unknown endianess
#    endif
#  else
#    error Not defined __BYTE_ORDER__
#  endif
#elif defined(_MSC_VER)
#  define BLKCPHR_IS_LITTLE 1
#  define BLKCPHR_IS_BIG    0
#else
#  error Unsupported compiler
#endif

#endif /* BLOCK_CIPHER_CONFIG_H */