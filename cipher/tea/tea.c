/* TEA data interpretation
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
 * 0    1            15   16                 128-bit key
 * +----+---- ... ---+----+
 * | K0 | K1  ... KE | KF |  ->  K3K2K1K0 K7K6K5K4 KBKAK9K8 KFKEKDKC
 * +----+---- ... ---+----+        K[0]     K[1]     K[2]     K[3]
 * ^- key
 */

#include "tea.h"
#include <string.h>
#include "config.h"

typedef blkcphr_u32_t tea_word_t;

static struct {
    tea_word_t K[4];
} teai_ctx;

#define TEA_DELTA 0x9e3779b9ul

static void teai_write_to_pair(tea_word_t* L, tea_word_t* R, const void* src) {
    memcpy(L, (const char*)src + 0, 4);
    memcpy(R, (const char*)src + 4, 4);
#if BLKCPHR_IS_BIG
    *L = blkcphr_bswap32(*L);
    *R = blkcphr_bswap32(*R);
#endif
}

static void teai_read_from_pair(void* dst, tea_word_t L, tea_word_t R) {
#if BLKCPHR_IS_BIG
    L = blkcphr_bswap32(L);
    R = blkcphr_bswap32(R);
#endif
    memcpy((char*)dst + 0, &L, 4);
    memcpy((char*)dst + 4, &R, 4);
}

int tea_init(const void* key, int bits) {
#if BLKCPHR_IS_BIG
    const tea_word_t* K = key; int i;
    if (bits != 128) return 1;
    for (i = 0; i < 4; i++)
        teai_ctx.K[i] = blkcphr_bswap32(K[i]);
#else
    if (bits != 128) return 1;
    memcpy(teai_ctx.K, key, 16);
#endif
    return 0;
}

void tea_block_encode(void* dst, const void* src) {
    tea_word_t L, R, i, sum = 0;
    teai_write_to_pair(&L, &R, src);

    for (i = 0; i < 32; i++) {
        sum += TEA_DELTA;
        L += ((R << 4) + teai_ctx.K[0]) ^ (R + sum) ^ ((R >> 5) + teai_ctx.K[1]);
        R += ((L << 4) + teai_ctx.K[2]) ^ (L + sum) ^ ((L >> 5) + teai_ctx.K[3]);
    }

    teai_read_from_pair(dst, L, R);
}

void tea_block_decode(void* dst, const void* src) {
    tea_word_t L, R, i, sum = TEA_DELTA << 5;
    teai_write_to_pair(&L, &R, src);

    for (i = 0; i < 32; i++) {
        R -= ((L << 4) + teai_ctx.K[2]) ^ (L + sum) ^ ((L >> 5) + teai_ctx.K[3]);
        L -= ((R << 4) + teai_ctx.K[0]) ^ (R + sum) ^ ((R >> 5) + teai_ctx.K[1]);
        sum -= TEA_DELTA;
    }

    teai_read_from_pair(dst, L, R);
}