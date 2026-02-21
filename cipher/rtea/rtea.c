/* RTEA data interpretation
 *
 * 0    1    2    3    4    5    6    7    8
 * +----+----+----+----+----+----+----+----+
 * | P0 | P1 | P2 | P3 | P4 | P5 | P6 | P7 |  ->  0xP3P2P1P0 0xP7P6P5P4
 * +----+----+----+----+----+----+----+----+          L          R
 * ^- src
 *
 * 0    1    2    3    4    5    6    7    8
 * +----+----+----+----+----+----+----+----+
 * | C0 | C1 | C2 | C3 | C4 | C5 | C6 | C7 |  ->  0xC3C2C1C0 0xC7C6C5C4
 * +----+----+----+----+----+----+----+----+          L          R
 * ^- dest
 *
 * 0    1            15   16                                        128-bit key
 * +----+---- ... ---+----+
 * | K0 | K1  ... KE | KF |                         ->  K3K2K1K0 K7K6K5K4 KBKAK9K8 KFKEKDKC
 * +----+---- ... ---+----+                               K[0]     K[1]     K[2]     K[3]
 * ^- key
 *
 * 0    1            15   16   17           31   32                 256-bit key
 * +----+---- ... ---+----+----+---- ... ---+----+
 * | K0 | K1  ... KE | KF | k0 | k1  ... kE | kF |  ->  K3K2K1K0 K7K6K5K4 KBKAK9K8 KFKEKDKC
 * +----+---- ... ---+----+----+---- ... ---+----+        K[0]     K[1]     K[2]     K[3]
 * ^- key                                               k3k2k1k0 k7k6k5k4 kBkAk9k8 kFkEkDkC
 *                                                        K[4]     K[5]     K[6]     K[7]
 */

#include "rtea.h"
#include <string.h>
#include "config.h"

typedef blkcphr_u32_t rtea_word_t;

static struct {
    rtea_word_t K[8];
    rtea_word_t rounds;
} rteai_ctx;

static void rteai_write_to_pair(rtea_word_t* L, rtea_word_t* R, const void* src) {
    memcpy(L, (const char*)src + 0, 4);
    memcpy(R, (const char*)src + 4, 4);
#if BLKCPHR_IS_BIG
    *L = blkcphr_bswap32(*L);
    *R = blkcphr_bswap32(*R);
#endif
}

static void rteai_read_from_pair(void* dst, rtea_word_t L, rtea_word_t R) {
#if BLKCPHR_IS_BIG
    L = blkcphr_bswap32(L);
    R = blkcphr_bswap32(R);
#endif
    memcpy((char*)dst + 0, &L, 4);
    memcpy((char*)dst + 4, &R, 4);
}

int rtea_init(const void* key, int bits) {
    switch (bits) {
        case 128: {
#if BLKCPHR_IS_BIG
            const rtea_word_t* K = key;
            int i; for (i = 0; i < 8; i++)
                rteai_ctx.K[i] = blkcphr_bswap32(K[i & 3]);
#else
            memcpy(rteai_ctx.K + 0, key, 16);
            memcpy(rteai_ctx.K + 4, key, 16);
#endif
            rteai_ctx.rounds = 48;
        } break;

        case 256: {
#if BLKCPHR_IS_BIG
            const rtea_word_t* K = key;
            int i; for (i = 0; i < 8; i++)
                rteai_ctx.K[i] = blkcphr_bswap32(K[i]);
#else
            memcpy(rteai_ctx.K, key, 32);
#endif
            rteai_ctx.rounds = 64;
        } break;

        default: return 1;
    }
    return 0;
}

void rtea_block_encode(void* dst, const void* src) {
    rtea_word_t L, R, i;
    rteai_write_to_pair(&L, &R, src);

    for (i = 0; i < rteai_ctx.rounds;) {
        L += R + ((R << 6) ^ (R >> 8)) + rteai_ctx.K[i & 7] + i; ++i;
        R += L + ((L << 6) ^ (L >> 8)) + rteai_ctx.K[i & 7] + i; ++i;
    }

    rteai_read_from_pair(dst, L, R);
}

void rtea_block_decode(void* dst, const void* src) {
    rtea_word_t L, R, i;
    rteai_write_to_pair(&L, &R, src);

    for (i = rteai_ctx.rounds; i > 0;) {
        --i; R -= L + ((L << 6) ^ (L >> 8)) + rteai_ctx.K[i & 7] + i;
        --i; L -= R + ((R << 6) ^ (R >> 8)) + rteai_ctx.K[i & 7] + i;
    }

    rteai_read_from_pair(dst, L, R);
}