/* Implementation of block cipher GOST 28147-89 (Magma) */

#ifndef GOST_CIPHER_H
#define GOST_CIPHER_H

#include <stdint.h>

#ifndef GOST_DEF
#define GOST_DEF
#endif

GOST_DEF uint64_t gost_encrypt(uint64_t block, const uint32_t key[8]);
GOST_DEF uint64_t gost_decrypt(uint64_t block, const uint32_t key[8]);

#endif // GOST_CIPHER_H

#ifdef GOST_IMPLEMENTATION

#include <stddef.h>

#define low32(x) ((uint32_t)(x))
#define hgh32(x) ((uint32_t)((x) >> 32))
#define join2x32(h, l) ((uint64_t)(h) << 32 | (l))
#define split64(n, h, l) l = low32(n); h = hgh32(n)

/* S-box from RFC 7836 */
static const uint8_t __gost_S[8][16] = {
    { 12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1 },
    { 6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15 },
    { 11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0 },
    { 12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11 },
    { 7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12 },
    { 5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0 },
    { 8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7 },
    { 1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2 }
};

static inline uint32_t __gost_rotl32(uint32_t n, int s) {
    return (n << s) | (n >> (32 - s));
}

static uint32_t __gost_f(uint32_t x, uint32_t ki) {
    uint32_t res = 0; x += ki;
    for (size_t i = 0; i < 8; i++)
        res |= ((uint32_t)__gost_S[i][(x >> (i * 4)) & 15]) << (i * 4);
    return __gost_rotl32(res, 11);
}

uint64_t gost_encrypt(uint64_t block, const uint32_t key[8]) {
    uint32_t L, R;
    split64(block, R, L);

    for (size_t i = 0; i < 24; i++) {
        L ^= __gost_f(R, key[i%8]); i++;
        R ^= __gost_f(L, key[i%8]);
    }
    for (size_t i = 8; i --> 0;) {
        L ^= __gost_f(R, key[i]); i--;
        R ^= __gost_f(L, key[i]);
    }

    return join2x32(L, R);
}

uint64_t gost_decrypt(uint64_t block, const uint32_t key[8]) {
    uint32_t L, R;
    split64(block, R, L);

    for (size_t i = 0; i < 8; i++) {
        L ^= __gost_f(R, key[i]); i++;
        R ^= __gost_f(L, key[i]);
    }
    for (size_t i = 24; i --> 0;) {
        L ^= __gost_f(R, key[i%8]); i--;
        R ^= __gost_f(L, key[i%8]);
    }

    return join2x32(L, R);
}

#endif // GOST_IMPLEMENTATION