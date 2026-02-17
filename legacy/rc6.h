/* Implementation of block cipher RC6-32/20/x and RC6-64/20/x */

#ifndef RC6_CIPHER_H
#define RC6_CIPHER_H

#include <stdint.h>

#ifndef RC6_DEF
#define RC6_DEF
#endif

typedef struct { uint32_t data[4]; } rc6_32_block_t;
typedef struct { uint64_t data[4]; } rc6_64_block_t;
typedef struct { uint32_t S[44]; } rc6_32_keys_t;
typedef struct { uint64_t S[44]; } rc6_64_keys_t;

RC6_DEF void rc6_32_init_keys(rc6_32_keys_t* ks, const uint32_t* key, size_t kw);
RC6_DEF rc6_32_block_t rc6_32_encrypt(rc6_32_block_t block, rc6_32_keys_t* ks);
RC6_DEF rc6_32_block_t rc6_32_decrypt(rc6_32_block_t block, rc6_32_keys_t* ks);

RC6_DEF void rc6_64_init_keys(rc6_64_keys_t* ks, const uint64_t* key, size_t kw);
RC6_DEF rc6_64_block_t rc6_64_encrypt(rc6_64_block_t block, rc6_64_keys_t* ks);
RC6_DEF rc6_64_block_t rc6_64_decrypt(rc6_64_block_t block, rc6_64_keys_t* ks);

#endif // RC6_CIPHER_H

#ifdef RC6_IMPLEMENTATION

#include <string.h>

static inline uint32_t __rc6_rotl32(uint32_t n, int s) {
    return (n << s) | (n >> (32 - s));
}
static inline uint32_t __rc6_rotr32(uint32_t n, int s) {
    return (n >> s) | (n << (32 - s));
}
static inline uint64_t __rc6_rotl64(uint64_t n, int s) {
    return (n << s) | (n >> (64 - s));
}
static inline uint64_t __rc6_rotr64(uint64_t n, int s) {
    return (n >> s) | (n << (64 - s));
}

void rc6_32_init_keys(rc6_32_keys_t* ks, const uint32_t* key, size_t kw) {
    uint32_t L[kw]; memcpy(L, key, kw * 4);

    ks->S[0] = 0xb7e15163;
    for (size_t i = 1; i < 44; i++)
        ks->S[i] = ks->S[i-1] + 0x9e3779b9;
    
    uint32_t A = 0, B = 0;
    size_t v = 3 * (kw < 44 ? 44 : kw);
    for (size_t s=0, i=0, j=0; s < v; s++) {
        A = ks->S[i] = __rc6_rotl32(ks->S[i] + A + B, 3);
        B =     L[j] = __rc6_rotl32(    L[j] + A + B, (A + B) & 31);
        i = (i + 1) % 44;
        j = (j + 1) % kw;
    }
}

rc6_32_block_t rc6_32_encrypt(rc6_32_block_t block, rc6_32_keys_t* ks) {
    uint32_t t, u, tmp,
        A = block.data[0], B = block.data[1],
        C = block.data[2], D = block.data[3];

    B += ks->S[0];
    D += ks->S[1];
    for (size_t i = 1; i <= 20; i++) {
        t = __rc6_rotl32(B * (2*B + 1), 5);
        u = __rc6_rotl32(D * (2*D + 1), 5);
        A = __rc6_rotl32(A ^ t, u & 31) + ks->S[2 * i];
        C = __rc6_rotl32(C ^ u, t & 31) + ks->S[2 * i + 1];
        tmp = A; A = B; B = C; C = D; D = tmp;
    }
    A += ks->S[42];
    C += ks->S[43];

    block.data[0] = A, block.data[1] = B,
    block.data[2] = C, block.data[3] = D;
    return block;
}

rc6_32_block_t rc6_32_decrypt(rc6_32_block_t block, rc6_32_keys_t* ks) {
    uint32_t t, u, tmp,
        A = block.data[0], B = block.data[1],
        C = block.data[2], D = block.data[3];

    C -= ks->S[43];
    A -= ks->S[42];
    for (size_t i = 21; i --> 1;) {
        tmp = D; D = C; C = B; B = A; A = tmp;
        u = __rc6_rotl32(D * (2*D + 1), 5);
        t = __rc6_rotl32(B * (2*B + 1), 5);
        C = __rc6_rotr32(C - ks->S[2 * i + 1], t & 31) ^ u;
        A = __rc6_rotr32(A - ks->S[2 * i],     u & 31) ^ t;
    }
    D -= ks->S[1];
    B -= ks->S[0];

    block.data[0] = A, block.data[1] = B,
    block.data[2] = C, block.data[3] = D;
    return block;
}

void rc6_64_init_keys(rc6_64_keys_t* ks, const uint64_t* key, size_t kw) {
    uint64_t L[kw]; memcpy(L, key, kw * 8);

    ks->S[0] = 0xb7e151628aed2a6b;
    for (size_t i = 1; i < 44; i++)
        ks->S[i] = ks->S[i-1] + 0x9e3779b97f4a7c15;
    
    uint64_t A = 0, B = 0;
    size_t v = 3 * (kw < 44 ? 44 : kw);
    for (size_t s=0, i=0, j=0; s < v; s++) {
        A = ks->S[i] = __rc6_rotl64(ks->S[i] + A + B, 3);
        B =     L[j] = __rc6_rotl64(    L[j] + A + B, (A + B) & 63);
        i = (i + 1) % 44;
        j = (j + 1) % kw;
    }
}

rc6_64_block_t rc6_64_encrypt(rc6_64_block_t block, rc6_64_keys_t* ks) {
    uint64_t t, u, tmp,
        A = block.data[0], B = block.data[1],
        C = block.data[2], D = block.data[3];

    B += ks->S[0];
    D += ks->S[1];
    for (size_t i = 1; i <= 20; i++) {
        t = __rc6_rotl64(B * (2*B + 1), 6);
        u = __rc6_rotl64(D * (2*D + 1), 6);
        A = __rc6_rotl64(A ^ t, u & 63) + ks->S[2 * i];
        C = __rc6_rotl64(C ^ u, t & 63) + ks->S[2 * i + 1];
        tmp = A; A = B; B = C; C = D; D = tmp;
    }
    A += ks->S[42];
    C += ks->S[43];

    block.data[0] = A, block.data[1] = B,
    block.data[2] = C, block.data[3] = D;
    return block;
}

rc6_64_block_t rc6_64_decrypt(rc6_64_block_t block, rc6_64_keys_t* ks) {
    uint64_t t, u, tmp,
        A = block.data[0], B = block.data[1],
        C = block.data[2], D = block.data[3];

    C -= ks->S[43];
    A -= ks->S[42];
    for (size_t i = 21; i --> 1;) {
        tmp = D; D = C; C = B; B = A; A = tmp;
        u = __rc6_rotl64(D * (2*D + 1), 6);
        t = __rc6_rotl64(B * (2*B + 1), 6);
        C = __rc6_rotr64(C - ks->S[2 * i + 1], t & 63) ^ u;
        A = __rc6_rotr64(A - ks->S[2 * i],     u & 63) ^ t;
    }
    D -= ks->S[1];
    B -= ks->S[0];

    block.data[0] = A, block.data[1] = B,
    block.data[2] = C, block.data[3] = D;
    return block;
}

#endif // RC6_IMPLEMENTATION