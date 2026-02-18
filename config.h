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
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wlong-long"
typedef unsigned long long blkcphr_u64_t;
#pragma GCC diagnostic pop
#elif defined(_MSC_VER)
typedef unsigned __int64 blkcphr_u64_t;
#endif

#endif /* __STDC_VERSION__ >= 199901L */

#endif /* BLOCK_CIPHER_CONFIG_H */