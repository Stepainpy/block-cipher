/* Implementation of block cipher EnRUPT
 * Default use EnRUPT-64/256
 */

#ifndef ENRUPT_CIPHER_H
#define ENRUPT_CIPHER_H

#include <stdint.h>

#ifndef ENRUPT_DEF
#define ENRUPT_DEF
#endif

ENRUPT_DEF uint64_t enrupt_encrypt(uint64_t block, const uint32_t key[8]);
ENRUPT_DEF uint64_t enrupt_decrypt(uint64_t block, const uint32_t key[8]);

ENRUPT_DEF void enrupt_ex_encrypt(uint32_t* dst,
    const uint32_t* src, size_t slenw, const uint32_t* key, size_t klenw);
ENRUPT_DEF void enrupt_ex_decrypt(uint32_t* dst,
    const uint32_t* src, size_t slenw, const uint32_t* key, size_t klenw);

#endif // ENRUPT_CIPHER_H

#ifdef ENRUPT_IMPLEMENTATION

#include <stddef.h>

static inline uint32_t __enrupt_rotr(uint32_t n, int s) {
    return (n >> s) | (n << (32 - s));
}

uint64_t enrupt_encrypt(uint64_t block, const uint32_t key[8]) {
    uint32_t b[2] = {(uint32_t)block, (uint32_t)(block >> 32)};
    for (uint32_t i = 0; i < 48; i++)
        b[i % 2] ^= __enrupt_rotr(
            2 * b[(i-1) % 2] ^ b[(i+1) % 2] ^ key[i % 8] ^ i, 8
        ) * 9 ^ key[i % 8];
    return (uint64_t)b[1] << 32 | b[0];
}

uint64_t enrupt_decrypt(uint64_t block, const uint32_t key[8]) {
    uint32_t b[2] = {(uint32_t)block, (uint32_t)(block >> 32)};
    for (uint32_t i = 48; i --> 0;)
        b[i % 2] ^= __enrupt_rotr(
            2 * b[(i-1) % 2] ^ b[(i+1) % 2] ^ key[i % 8] ^ i, 8
        ) * 9 ^ key[i % 8];
    return (uint64_t)b[1] << 32 | b[0];
}

void enrupt_ex_encrypt(uint32_t* dst,
    const uint32_t* src, size_t slenw,
    const uint32_t* key, size_t klenw
) {
    for (size_t i = 0; i < slenw; i++)
        dst[i] = src[i];
    for (uint32_t i = 0; i < 4 * (2 * slenw + klenw); i++)
        dst[i % slenw] ^= __enrupt_rotr(
            2 * dst[(i-1) % slenw] ^ dst[(i+1) % slenw] ^ key[i % klenw] ^ i, 8
        ) * 9 ^ key[i % klenw];
}

void enrupt_ex_decrypt(uint32_t* dst,
    const uint32_t* src, size_t slenw,
    const uint32_t* key, size_t klenw
) {
    for (size_t i = 0; i < slenw; i++)
        dst[i] = src[i];
    for (uint32_t i = 4 * (2 * slenw + klenw); i --> 0;)
        dst[i % slenw] ^= __enrupt_rotr(
            2 * dst[(i-1) % slenw] ^ dst[(i+1) % slenw] ^ key[i % klenw] ^ i, 8
        ) * 9 ^ key[i % klenw];
}

#endif // ENRUPT_IMPLEMENTATION