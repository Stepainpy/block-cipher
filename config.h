#ifndef BLOCK_CIPHER_CONFIG_H
#define BLOCK_CIPHER_CONFIG_H

/* Compiler detection */

#if defined(__GNUC__)
#  define BLKCPHR_ON_GNUC 1
#  if defined(__clang__)
#    define BLKCPHR_ON_CLANG 1
#  else
#    define BLKCPHR_ON_GCC 1
#  endif
#elif defined(_MSC_VER)
#  define BLKCPHR_ON_MSVC 1
#else
#  error Unsupported compiler
#endif

/* Turning off warning "-Wlong-long" on GNUC */

#if BLKCPHR_ON_GNUC && __STDC_VERSION__ < 199901L
#  define BLKCPHR_U64_WARN_BEGIN \
    _Pragma("GCC diagnostic push") \
    _Pragma("GCC diagnostic ignored \"-Wlong-long\"")
#  define BLKCPHR_U64_WARN_END \
    _Pragma("GCC diagnostic pop")
#else
#  define BLKCPHR_U64_WARN_BEGIN
#  define BLKCPHR_U64_WARN_END
#endif

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

#if BLKCPHR_ON_GNUC
BLKCPHR_U64_WARN_BEGIN
typedef unsigned long long blkcphr_u64_t;
BLKCPHR_U64_WARN_END
#elif BLKCPHR_ON_MSVC
typedef unsigned __int64 blkcphr_u64_t;
#else
#  error Unsupported copmiler
#endif

#endif /* __STDC_VERSION__ >= 199901L */

/* Integer byte swap functions */

#if BLKCPHR_ON_GNUC
#  define blkcphr_bswap16 __builtin_bswap16
#  define blkcphr_bswap32 __builtin_bswap32
#  define blkcphr_bswap64 __builtin_bswap64
#elif BLKCPHR_ON_MSVC
#  include <stdlib.h>
#  define blkcphr_bswap16 _byteswap_ushort
#  define blkcphr_bswap32 _byteswap_ulong
#  define blkcphr_bswap64 _byteswap_uint64
#else
#  error Unsupported compiler
#endif

/* Detecting endianness */

#if BLKCPHR_ON_GNUC
#  if defined(__BYTE_ORDER__)
#    if   __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#      define BLKCPHR_IS_LITTLE 1
#      define BLKCPHR_IS_BIG    0
#    elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#      define BLKCPHR_IS_LITTLE 0
#      define BLKCPHR_IS_BIG    1
#    else
#      error Unknown endianness
#    endif
#  else
#    error Not defined __BYTE_ORDER__
#  endif
#elif BLKCPHR_ON_MSVC
#  define BLKCPHR_IS_LITTLE 1
#  define BLKCPHR_IS_BIG    0
#else
#  error Unsupported compiler
#endif

/* If condition for preprocessor */

#define BLKCPHR_CONCAT_(left, right) left ## right
#define BLKCPHR_CONCAT(left, right) BLKCPHR_CONCAT_(left, right)

#define BLKCPHR_IF_0(stmt)
#define BLKCPHR_IF_1(stmt) stmt
#define BLKCPHR_IF(cond, stmt) BLKCPHR_CONCAT(BLKCPHR_IF_, cond)(stmt)

#define BLKCPHR_IF_LITTLE(stmt) BLKCPHR_IF(BLKCPHR_IS_LITTLE, stmt)
#define BLKCPHR_IF_BIG(stmt) BLKCPHR_IF(BLKCPHR_IS_BIG, stmt)

/* Byte swapping one, pair and blocks */

#define BLKCPHR_BSWAP_B_ONE(bits, value) do { \
    (value) = blkcphr_bswap##bits(value); \
} while (0)

#define BLKCPHR_BSWAP_B_PAIR(bits, L, R) do { \
    (L) = blkcphr_bswap##bits(L); \
    (R) = blkcphr_bswap##bits(R); \
} while (0)

#define BLKCPHR_BSWAP_Bx2(bits, array) do { \
    (array)[0] = blkcphr_bswap##bits((array)[0]); \
    (array)[1] = blkcphr_bswap##bits((array)[1]); \
} while (0)

#define BLKCPHR_BSWAP_Bx3(bits, array) do { \
    (array)[0] = blkcphr_bswap##bits((array)[0]); \
    (array)[1] = blkcphr_bswap##bits((array)[1]); \
    (array)[2] = blkcphr_bswap##bits((array)[2]); \
} while (0)

#define BLKCPHR_BSWAP_Bx4(bits, array) do { \
    (array)[0] = blkcphr_bswap##bits((array)[0]); \
    (array)[1] = blkcphr_bswap##bits((array)[1]); \
    (array)[2] = blkcphr_bswap##bits((array)[2]); \
    (array)[3] = blkcphr_bswap##bits((array)[3]); \
} while (0)

#define BLKCPHR_BSWAP_Bx6(bits, array) do { \
    (array)[0] = blkcphr_bswap##bits((array)[0]); \
    (array)[1] = blkcphr_bswap##bits((array)[1]); \
    (array)[2] = blkcphr_bswap##bits((array)[2]); \
    (array)[3] = blkcphr_bswap##bits((array)[3]); \
    (array)[4] = blkcphr_bswap##bits((array)[4]); \
    (array)[5] = blkcphr_bswap##bits((array)[5]); \
} while (0)

#define BLKCPHR_BSWAP_Bx8(bits, array) do { \
    (array)[0] = blkcphr_bswap##bits((array)[0]); \
    (array)[1] = blkcphr_bswap##bits((array)[1]); \
    (array)[2] = blkcphr_bswap##bits((array)[2]); \
    (array)[3] = blkcphr_bswap##bits((array)[3]); \
    (array)[4] = blkcphr_bswap##bits((array)[4]); \
    (array)[5] = blkcphr_bswap##bits((array)[5]); \
    (array)[6] = blkcphr_bswap##bits((array)[6]); \
    (array)[7] = blkcphr_bswap##bits((array)[7]); \
} while (0)

#define BLKCPHR_BSWAP_16x4(exp) BLKCPHR_BSWAP_Bx4(16, exp)
#define BLKCPHR_BSWAP_16x8(exp) BLKCPHR_BSWAP_Bx8(16, exp)

/* #define BLKCPHR_BSWAP_16_ONE(value) do { \
    (value) = blkcphr_bswap16(value); \
} while (0)

#define BLKCPHR_BSWAP_16_PAIR(L, R) do { \
    (L) = blkcphr_bswap16(L); \
    (R) = blkcphr_bswap16(R); \
} while (0)

#define BLKCPHR_BSWAP_16x2(array) do { \
    (array)[0] = blkcphr_bswap16((array)[0]); \
    (array)[1] = blkcphr_bswap16((array)[1]); \
} while (0)

#define BLKCPHR_BSWAP_16x4(array) do { \
    (array)[0] = blkcphr_bswap16((array)[0]); \
    (array)[1] = blkcphr_bswap16((array)[1]); \
    (array)[2] = blkcphr_bswap16((array)[2]); \
    (array)[3] = blkcphr_bswap16((array)[3]); \
} while (0)

#define BLKCPHR_BSWAP_16x8(array) do { \
    (array)[0] = blkcphr_bswap16((array)[0]); \
    (array)[1] = blkcphr_bswap16((array)[1]); \
    (array)[2] = blkcphr_bswap16((array)[2]); \
    (array)[3] = blkcphr_bswap16((array)[3]); \
    (array)[4] = blkcphr_bswap16((array)[4]); \
    (array)[5] = blkcphr_bswap16((array)[5]); \
    (array)[6] = blkcphr_bswap16((array)[6]); \
    (array)[7] = blkcphr_bswap16((array)[7]); \
} while (0) */

#define BLKCPHR_BSWAP_32_ONE(value) BLKCPHR_BSWAP_B_ONE(32, value)
#define BLKCPHR_BSWAP_32_PAIR(L, R) BLKCPHR_BSWAP_B_PAIR(32, L, R)
#define BLKCPHR_BSWAP_32x4(array) BLKCPHR_BSWAP_Bx4(32, array)
#define BLKCPHR_BSWAP_32x6(array) BLKCPHR_BSWAP_Bx6(32, array)
#define BLKCPHR_BSWAP_32x8(array) BLKCPHR_BSWAP_Bx8(32, array)

/* #define BLKCPHR_BSWAP_32_ONE(value) do { \
    (value) = blkcphr_bswap32(value); \
} while (0)

#define BLKCPHR_BSWAP_32_PAIR(L, R) do { \
    (L) = blkcphr_bswap32(L); \
    (R) = blkcphr_bswap32(R); \
} while (0)

#define BLKCPHR_BSWAP_32x2(array) do { \
    (array)[0] = blkcphr_bswap32((array)[0]); \
    (array)[1] = blkcphr_bswap32((array)[1]); \
} while (0)

#define BLKCPHR_BSWAP_32x4(array) do { \
    (array)[0] = blkcphr_bswap32((array)[0]); \
    (array)[1] = blkcphr_bswap32((array)[1]); \
    (array)[2] = blkcphr_bswap32((array)[2]); \
    (array)[3] = blkcphr_bswap32((array)[3]); \
} while (0)

#define BLKCPHR_BSWAP_32x6(array) do { \
    (array)[0] = blkcphr_bswap32((array)[0]); \
    (array)[1] = blkcphr_bswap32((array)[1]); \
    (array)[2] = blkcphr_bswap32((array)[2]); \
    (array)[3] = blkcphr_bswap32((array)[3]); \
    (array)[4] = blkcphr_bswap32((array)[4]); \
    (array)[5] = blkcphr_bswap32((array)[5]); \
} while (0)

#define BLKCPHR_BSWAP_32x8(array) do { \
    (array)[0] = blkcphr_bswap32((array)[0]); \
    (array)[1] = blkcphr_bswap32((array)[1]); \
    (array)[2] = blkcphr_bswap32((array)[2]); \
    (array)[3] = blkcphr_bswap32((array)[3]); \
    (array)[4] = blkcphr_bswap32((array)[4]); \
    (array)[5] = blkcphr_bswap32((array)[5]); \
    (array)[6] = blkcphr_bswap32((array)[6]); \
    (array)[7] = blkcphr_bswap32((array)[7]); \
} while (0) */

#define BLKCPHR_BSWAP_64_ONE(value) BLKCPHR_BSWAP_B_ONE(64, value)
#define BLKCPHR_BSWAP_64_PAIR(L, R) BLKCPHR_BSWAP_B_PAIR(64, L, R)
#define BLKCPHR_BSWAP_64x2(array) BLKCPHR_BSWAP_Bx2(64, array)
#define BLKCPHR_BSWAP_64x3(array) BLKCPHR_BSWAP_Bx3(64, array)
#define BLKCPHR_BSWAP_64x4(array) BLKCPHR_BSWAP_Bx4(64, array)

/* #define BLKCPHR_BSWAP_64_ONE(value) do { \
    (value) = blkcphr_bswap64(value); \
} while (0)

#define BLKCPHR_BSWAP_64_PAIR(L, R) do { \
    (L) = blkcphr_bswap64(L); \
    (R) = blkcphr_bswap64(R); \
} while (0)

#define BLKCPHR_BSWAP_64x2(array) do { \
    (array)[0] = blkcphr_bswap64((array)[0]); \
    (array)[1] = blkcphr_bswap64((array)[1]); \
} while (0)

#define BLKCPHR_BSWAP_64x3(array) do { \
    (array)[0] = blkcphr_bswap64((array)[0]); \
    (array)[1] = blkcphr_bswap64((array)[1]); \
    (array)[2] = blkcphr_bswap64((array)[2]); \
} while (0)

#define BLKCPHR_BSWAP_64x4(array) do { \
    (array)[0] = blkcphr_bswap64((array)[0]); \
    (array)[1] = blkcphr_bswap64((array)[1]); \
    (array)[2] = blkcphr_bswap64((array)[2]); \
    (array)[3] = blkcphr_bswap64((array)[3]); \
} while (0)

#define BLKCPHR_BSWAP_64x8(array) do { \
    (array)[0] = blkcphr_bswap64((array)[0]); \
    (array)[1] = blkcphr_bswap64((array)[1]); \
    (array)[2] = blkcphr_bswap64((array)[2]); \
    (array)[3] = blkcphr_bswap64((array)[3]); \
    (array)[4] = blkcphr_bswap64((array)[4]); \
    (array)[5] = blkcphr_bswap64((array)[5]); \
    (array)[6] = blkcphr_bswap64((array)[6]); \
    (array)[7] = blkcphr_bswap64((array)[7]); \
} while (0) */

/* Bit rotation functions */

#ifdef BLKCPHR_USE_ROTL32
static blkcphr_u32_t BLKCPHR_USE_ROTL32(blkcphr_u32_t n, blkcphr_u32_t s)
    { s &= 31; return n << s | n >> (-s & 31); }
#endif

#ifdef BLKCPHR_USE_ROTR32
static blkcphr_u32_t BLKCPHR_USE_ROTR32(blkcphr_u32_t n, blkcphr_u32_t s)
    { s &= 31; return n >> s | n << (-s & 31); }
#endif

#ifdef BLKCPHR_USE_ROTL64
static blkcphr_u64_t BLKCPHR_USE_ROTL64(blkcphr_u64_t n, blkcphr_u64_t s)
    { s &= 63; return n << s | n >> (-s & 63); }
#endif

#ifdef BLKCPHR_USE_ROTR64
static blkcphr_u64_t BLKCPHR_USE_ROTR64(blkcphr_u64_t n, blkcphr_u64_t s)
    { s &= 63; return n >> s | n << (-s & 63); }
#endif

#endif /* BLOCK_CIPHER_CONFIG_H */