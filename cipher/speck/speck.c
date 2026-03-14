/* Speck data interpretation
 *
 * 0    1    2    3    4    5    6    7    8    9    10   11   12   13   14   15   16
 * +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
 * | P0 | P1 | P2 | P3 | P4 | P5 | P6 | P7 | P8 | P9 | PA | PB | PC | PD | PE | PF |  ->  0xP0P1P2P3P4P5P6P7 0xP8P9PAPBPCPDPEPF
 * +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+               L                  R
 * ^- src
 *
 * 0    1    2    3    4    5    6    7    8    9    10   11   12   13   14   15   16
 * +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
 * | C0 | C1 | C2 | C3 | C4 | C5 | C6 | C7 | C8 | C9 | CA | CB | CC | CD | CE | CF |  ->  0xC0C1C2C3C4C5C6C7 0xC8C9CACBCCCDCECF
 * +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+               L                  R
 * ^- dest
 *
 * 0    1            15   16                                       128-bit key
 * +----+---- ... ---+----+
 * | K0 | K1  ... KE | KF |                         ->  K0K1K2K3K4K5K6K7 K8K9KAKBKCKDKEKF
 * +----+---- ... ---+----+                                   K[0]             K[1]
 * ^- key
 *
 * 0    1            15   16   17           23   24                192-bit key
 * +----+---- ... ---+----+----+---- ... ---+----+
 * | K0 | K1  ... KE | KF | k0 | k1  ... k6 | k7 |  ->  K0K1K2K3K4K5K6K7 K8K9KAKBKCKDKEKF
 * +----+---- ... ---+----+----+---- ... ---+----+            K[0]             K[1]
 * ^- key                                               k0k1k2k3k4k5k6k7
 *                                                            K[2]
 *
 * 0    1            15   16   17           31   32                256-bit key
 * +----+---- ... ---+----+----+---- ... ---+----+
 * | K0 | K1  ... KE | KF | k0 | k1  ... kE | kF |  ->  K0K1K2K3K4K5K6K7 K8K9KAKBKCKDKEKF
 * +----+---- ... ---+----+----+---- ... ---+----+            K[0]             KL[1]
 * ^- key                                               k0k1k2k3k4k5k6k7 k8k9kAkBkCkDkEkF
 *                                                            K[2]             K[3]
 */

#define BLKCPHR_USE_ROTL64 specki_rotl
#define BLKCPHR_USE_ROTR64 specki_rotr

#include "speck.h"
#include <string.h>
#include "config.h"

typedef blkcphr_u64_t speck_word_t;

static struct {
    speck_word_t K[34];
    speck_word_t rounds;
} specki_ctx;

static void specki_round_fwd(speck_word_t* L, speck_word_t* R, speck_word_t K) {
    *L  = specki_rotr(*L, 8);
    *L += *R;
    *L ^=  K;
    *R  = specki_rotl(*R, 3);
    *R ^= *L;
}

static void specki_round_inv(speck_word_t* L, speck_word_t* R, speck_word_t K) {
    *R ^= *L;
    *R  = specki_rotr(*R, 3);
    *L ^=  K;
    *L -= *R;
    *L  = specki_rotl(*L, 8);
}

static void specki_init_key128(const void* key) {
    speck_word_t K[2], i;

    memcpy(K, key, sizeof K);
    BLKCPHR_IF_LITTLE(BLKCPHR_BSWAP_64x2(K));
/* #if BLKCPHR_IS_LITTLE
    K[0] = blkcphr_bswap64(K[0]);
    K[1] = blkcphr_bswap64(K[1]);
#endif */

    specki_ctx.K[0] = K[1];
    for (i = 0; i < 31; i++) {
        specki_round_fwd(K + 0, K + 1, i);
        specki_ctx.K[i + 1] = K[1];
    }

    specki_ctx.rounds = 32;
}

static void specki_init_key192(const void* key) {
    speck_word_t K[3], i;

    memcpy(K, key, sizeof K);
    BLKCPHR_IF_LITTLE(BLKCPHR_BSWAP_64x3(K));
/* #if BLKCPHR_IS_LITTLE
    K[0] = blkcphr_bswap64(K[0]);
    K[1] = blkcphr_bswap64(K[1]);
    K[2] = blkcphr_bswap64(K[2]);
#endif */

    specki_ctx.K[0] = K[2];
    for (i = 0; i < 32; i++) {
        specki_round_fwd(K + (1 - i % 2), K + 2, i);
        specki_ctx.K[i + 1] = K[2];
    }

    specki_ctx.rounds = 33;
}

static void specki_init_key256(const void* key) {
    speck_word_t K[4], i;

    memcpy(K, key, sizeof K);
    BLKCPHR_IF_LITTLE(BLKCPHR_BSWAP_64x4(K));
/* #if BLKCPHR_IS_LITTLE
    K[0] = blkcphr_bswap64(K[0]);
    K[1] = blkcphr_bswap64(K[1]);
    K[2] = blkcphr_bswap64(K[2]);
    K[3] = blkcphr_bswap64(K[3]);
#endif */

    specki_ctx.K[0] = K[3];
    for (i = 0; i < 33; i++) {
        specki_round_fwd(K + (2 - i % 3), K + 3, i);
        specki_ctx.K[i + 1] = K[3];
    }

    specki_ctx.rounds = 34;
}

int speck_init(const void* key, int bits) {
    switch (bits) {
        case 128: specki_init_key128(key); return 0;
        case 192: specki_init_key192(key); return 0;
        case 256: specki_init_key256(key); return 0;
        default: return 1;
    }
}

static void specki_write_to_pair(speck_word_t* L, speck_word_t* R, const void* src) {
    memcpy(L, (const char*)src + 0, sizeof *L);
    memcpy(R, (const char*)src + 8, sizeof *R);
    BLKCPHR_IF_LITTLE(BLKCPHR_BSWAP_64_PAIR(*L, *R));
/* #if BLKCPHR_IS_LITTLE
    *L = blkcphr_bswap64(*L);
    *R = blkcphr_bswap64(*R);
#endif */
}

static void specki_read_from_pair(void* dst, speck_word_t L, speck_word_t R) {
/* #if BLKCPHR_IS_LITTLE
    L = blkcphr_bswap64(L);
    R = blkcphr_bswap64(R);
#endif */
    BLKCPHR_IF_LITTLE(BLKCPHR_BSWAP_64_PAIR(L, R));
    memcpy((char*)dst + 0, &L, sizeof L);
    memcpy((char*)dst + 8, &R, sizeof R);
}

void speck_block_encode(void* dst, const void* src) {
    speck_word_t L, R, i;
    specki_write_to_pair(&L, &R, src);

    for (i = 0; i < specki_ctx.rounds; i++)
        specki_round_fwd(&L, &R, specki_ctx.K[i]);

    specki_read_from_pair(dst, L, R);
}

void speck_block_decode(void* dst, const void* src) {
    speck_word_t L, R, i;
    specki_write_to_pair(&L, &R, src);

    for (i = specki_ctx.rounds; i --> 0;)
        specki_round_inv(&L, &R, specki_ctx.K[i]);

    specki_read_from_pair(dst, L, R);
}