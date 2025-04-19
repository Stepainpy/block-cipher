/* Implementation of block cipher algorithms:
 * - TEA (Tiny Encryption Algorithm)
 * - XTEA (eXtended TEA)
 * - RTEA (Ruptor's TEA)
 * - Raiden
 * Algorithm overview:
 * https://ru.wikipedia.org/wiki/TEA
 */

#ifndef TEA_CIPHER_H
#define TEA_CIPHER_H

#include <stdint.h>

#ifndef TEA_DEF
#define TEA_DEF
#endif

TEA_DEF uint64_t     tea_encrypt(uint64_t block, const uint32_t key[4]);
TEA_DEF uint64_t     tea_decrypt(uint64_t block, const uint32_t key[4]);

TEA_DEF uint64_t    xtea_encrypt(uint64_t block, const uint32_t key[4]);
TEA_DEF uint64_t    xtea_decrypt(uint64_t block, const uint32_t key[4]);

TEA_DEF uint64_t rtea128_encrypt(uint64_t block, const uint32_t key[4]);
TEA_DEF uint64_t rtea128_decrypt(uint64_t block, const uint32_t key[4]);

TEA_DEF uint64_t rtea256_encrypt(uint64_t block, const uint32_t key[8]);
TEA_DEF uint64_t rtea256_decrypt(uint64_t block, const uint32_t key[8]);

TEA_DEF uint64_t  raiden_encrypt(uint64_t block, const uint32_t key[4]);
TEA_DEF uint64_t  raiden_decrypt(uint64_t block, const uint32_t key[4]);

#endif // TEA_CIPHER_H

#ifdef TEA_IMPLEMENTATION

#include <stddef.h>

#define TEA_DELTA 0x9e3779b9

#define low32(x) ((uint32_t)(x))
#define hgh32(x) ((uint32_t)((x) >> 32))
#define join2x32(h, l) ((uint64_t)(h) << 32 | (l))
#define split64(n, h, l) l = low32(n); h = hgh32(n)

uint64_t tea_encrypt(uint64_t block, const uint32_t key[4]) {
    uint32_t L, R, sum = 0;
    split64(block, R, L);
    for (size_t i = 0; i < 32; i++) {
        sum += TEA_DELTA;
        L += ((R << 4) + key[0]) ^ (R + sum) ^ ((R >> 5) + key[1]);
        R += ((L << 4) + key[2]) ^ (L + sum) ^ ((L >> 5) + key[3]);
    }
    return join2x32(R, L);
}

uint64_t tea_decrypt(uint64_t block, const uint32_t key[4]) {
    uint32_t L, R, sum = TEA_DELTA << 5;
    split64(block, R, L);
    for (size_t i = 0; i < 32; i++) {
        R -= ((L << 4) + key[2]) ^ (L + sum) ^ ((L >> 5) + key[3]);
        L -= ((R << 4) + key[0]) ^ (R + sum) ^ ((R >> 5) + key[1]);
        sum -= TEA_DELTA;
    }
    return join2x32(R, L);
}

uint64_t xtea_encrypt(uint64_t block, const uint32_t key[4]) {
    uint32_t L, R, sum = 0;
    split64(block, R, L);
    for (size_t i = 0; i < 32; i++) {
        L += (((R << 4) ^ (R >> 5)) + R) ^ (sum + key[sum & 3]);
        sum += TEA_DELTA;
        R += (((L << 4) ^ (L >> 5)) + L) ^ (sum + key[(sum >> 11) & 3]);
    }
    return join2x32(R, L);
}

uint64_t xtea_decrypt(uint64_t block, const uint32_t key[4]) {
    uint32_t L, R, sum = TEA_DELTA << 5;
    split64(block, R, L);
    for (size_t i = 0; i < 32; i++) {
        R -= (((L << 4) ^ (L >> 5)) + L) ^ (sum + key[(sum >> 11) & 3]);
        sum -= TEA_DELTA;
        L -= (((R << 4) ^ (R >> 5)) + R) ^ (sum + key[sum & 3]);
    }
    return join2x32(R, L);
}

uint64_t rtea128_encrypt(uint64_t block, const uint32_t key[4]) {
    uint32_t L, R;
    split64(block, R, L);
    for (size_t i = 0; i < 48; i++) {
        L += R + ((R << 6) ^ (R >> 8)) + key[i % 4] + i; i++;
        R += L + ((L << 6) ^ (L >> 8)) + key[i % 4] + i;
    }
    return join2x32(R, L);
}

uint64_t rtea128_decrypt(uint64_t block, const uint32_t key[4]) {
    uint32_t L, R;
    split64(block, R, L);
    for (size_t i = 48; i --> 0;) {
        R -= L + ((L << 6) ^ (L >> 8)) + key[i % 4] + i; i--;
        L -= R + ((R << 6) ^ (R >> 8)) + key[i % 4] + i;
    }
    return join2x32(R, L);
}

uint64_t rtea256_encrypt(uint64_t block, const uint32_t key[8]) {
    uint32_t L, R;
    split64(block, R, L);
    for (size_t i = 0; i < 64; i++) {
        R += L + ((L << 6) ^ (L >> 8)) + key[i % 8] + i; i++;
        L += R + ((R << 6) ^ (R >> 8)) + key[i % 8] + i;
    }
    return join2x32(R, L);
}

uint64_t rtea256_decrypt(uint64_t block, const uint32_t key[8]) {
    uint32_t L, R;
    split64(block, R, L);
    for (size_t i = 64; i --> 0;) {
        L -= R + ((R << 6) ^ (R >> 8)) + key[i % 8] + i; i--;
        R -= L + ((L << 6) ^ (L >> 8)) + key[i % 8] + i;
    }
    return join2x32(R, L);
}

uint64_t raiden_encrypt(uint64_t block, const uint32_t key[4]) {
    uint32_t L, R, sk, k[4] = { key[0], key[1], key[2], key[3] };
    split64(block, R, L);
    for (size_t i = 0; i < 16; i++) {
        sk = k[i % 4] = k[0] + k[1] + ((k[2] + k[3]) ^ (k[0] << (k[2] & 0x1f)));
        L += ((sk + R) << 9) ^ (sk - R) ^ ((sk + R) >> 14);
        R += ((sk + L) << 9) ^ (sk - L) ^ ((sk + L) >> 14);
    }
    return join2x32(R, L);
}

uint64_t raiden_decrypt(uint64_t block, const uint32_t key[4]) {
    uint32_t L, R, sk[16], k[4] = { key[0], key[1], key[2], key[3] };
    split64(block, R, L);
    for (size_t i = 0; i < 16; i++)
        sk[i] = k[i % 4] = k[0] + k[1] + ((k[2] + k[3]) ^ (k[0] << (k[2] & 0x1f)));
    for (size_t i = 16; i --> 0;) {
        R -= ((sk[i] + L) << 9) ^ (sk[i] - L) ^ ((sk[i] + L) >> 14);
        L -= ((sk[i] + R) << 9) ^ (sk[i] - R) ^ ((sk[i] + R) >> 14);
    }
    return join2x32(R, L);
}

#endif // TEA_IMPLEMENTATION