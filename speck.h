/* Implementation of block cipher Speck-128/128 */

#ifndef SPECK_CIPHER_H
#define SPECK_CIPHER_H

#include <stdint.h>

#ifndef SPECK_DEF
#define SPECK_DEF
#endif

typedef struct { uint64_t data[2]; } speck_block_t;
typedef struct { uint64_t keys[32]; } speck_keys_t;

SPECK_DEF void speck_init_keys(speck_keys_t* ks, const uint64_t key[2]);
SPECK_DEF speck_block_t speck_encrypt(speck_block_t block, speck_keys_t* keys);
SPECK_DEF speck_block_t speck_decrypt(speck_block_t block, speck_keys_t* keys);

#endif // SPECK_CIPHER_H

#ifdef SPECK_IMPLEMENTATION

#include <stddef.h>

static inline uint64_t __speck_rotl(uint64_t n, int s) {
    return (n << s) | (n >> (64 - s));
}
static inline uint64_t __speck_rotr(uint64_t n, int s) {
    return (n >> s) | (n << (64 - s));
}

static inline void __speck_round(uint64_t* L, uint64_t* R, uint64_t K) {
    *L = __speck_rotr(*L, 8); *L += *R;
    *R = __speck_rotl(*R, 3); *L ^=  K;
    *R ^= *L;
}

static inline void __speck_inv_round(uint64_t* L, uint64_t* R, uint64_t K) {
    *R ^= *L;
    *R = __speck_rotr(*R, 3); *L ^=  K;
    *L -= *R; *L = __speck_rotl(*L, 8);
}

void speck_init_keys(speck_keys_t* ks, const uint64_t key[2]) {
    uint64_t kl = key[0], kr = key[1];
    for (size_t i = 0; i < 32; i++) {
        ks->keys[i] = kr;
        __speck_round(&kl, &kr, i);
    }
}

speck_block_t speck_encrypt(speck_block_t block, speck_keys_t* keys) {
    for (size_t i = 0; i < 32; i++)
        __speck_round(block.data, block.data + 1, keys->keys[i]);
    return block;
}

speck_block_t speck_decrypt(speck_block_t block, speck_keys_t* keys) {
    for (size_t i = 32; i --> 0;)
        __speck_inv_round(block.data, block.data + 1, keys->keys[i]);
    return block;
}

#endif // SPECK_IMPLEMENTATION