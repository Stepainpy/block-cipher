/* RC6 data interpretation
 *
 * 0    1    2    3    4    5    6    7    8    9    10   11   12   13   14   15   16
 * +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
 * | P0 | P1 | P2 | P3 | P4 | P5 | P6 | P7 | P8 | P9 | PA | PB | PC | PD | PE | PF |
 * +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
 * ^- src
 *
 * 0    1    2    3    4    5    6    7    8    9    10   11   12   13   14   15   16
 * +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
 * | C0 | C1 | C2 | C3 | C4 | C5 | C6 | C7 | C8 | C9 | CA | CB | CC | CD | CE | CF |
 * +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
 * ^- dest
 *
 * 0            4            8            12           16
 * +------------+------------+------------+------------+
 * | 0xT3T2T1T0 | 0xT7T6T5T4 | 0xTBTAT9T8 | 0xTFTETDTC |
 * +------------+------------+------------+------------+
 *      T[0]         T[1]         T[2]         T[3]
 */

#define BLKCPHR_USE_ROTL32 rc6i_rotl
#define BLKCPHR_USE_ROTR32 rc6i_rotr

#include "rc6.h"
#include <string.h>
#include "config.h"

typedef blkcphr_u32_t rc6_word_t;

typedef rc6_word_t rc6_block_t[4];

static struct {
    rc6_word_t S[44];
} rc6i_ctx;

int rc6_init(const void* key, int bits) {
    rc6_word_t A, B, L[64] = {0};
    int c, i, j, m, mi;

    if (bits < 0 || bits > 2040) return 1;
    if (bits % 8 != 0) return 1;
    bits /= 8; /* now is bytes */

    c = (bits + 3) / 4; /* ceil(b/4) */
    c = c ? c : 1;
    memcpy(L, key, bits);
#if BLKCPHR_IS_BIG
    for (i = 0; i < c; i++)
        L[i] = blkcphr_bswap32(L[i]);
#endif

    rc6i_ctx.S[0] = 0xb7e15163;
    for (i = 1; i < 44; i++)
        rc6i_ctx.S[i] = rc6i_ctx.S[i - 1] + 0x9e3779b9;

    A = B = i = j = 0;
    for (m = 3 * (44 > c ? 44 : c), mi = 0; mi < m; mi++) {
        A = rc6i_ctx.S[i] = rc6i_rotl(rc6i_ctx.S[i] + A + B, 3);
        B =          L[j] = rc6i_rotl(         L[j] + A + B, A + B);
        i = (i + 1) % 44;
        j = (j + 1) %  c;
    }

    return 0;
}

static void rc6i_write_to_block(rc6_block_t out, const void* src) {
    memcpy(out, src, sizeof(rc6_block_t));
    BLKCPHR_IF(BLKCPHR_IS_BIG, BLKCPHR_BSWAP_32x4(out));
/* #if BLKCPHR_IS_BIG
    out[0] = blkcphr_bswap32(out[0]);
    out[1] = blkcphr_bswap32(out[1]);
    out[2] = blkcphr_bswap32(out[2]);
    out[3] = blkcphr_bswap32(out[3]);
#endif */
}

static void rc6i_read_from_block(void* dst, const rc6_block_t in) {
    rc6_block_t T;
    memcpy(T, in, sizeof(rc6_block_t));
    BLKCPHR_IF(BLKCPHR_IS_BIG, BLKCPHR_BSWAP_32x4(T));
/* #if BLKCPHR_IS_BIG
    T[0] = blkcphr_bswap32(T[0]);
    T[1] = blkcphr_bswap32(T[1]);
    T[2] = blkcphr_bswap32(T[2]);
    T[3] = blkcphr_bswap32(T[3]);
#endif */
    memcpy(dst, T, sizeof(rc6_block_t));
}

static void rc6i_rotl_block(rc6_block_t block) {
    rc6_word_t first = block[0];
    memmove(block, block + 1, 12);
    block[3] = first;
}

static void rc6i_rotr_block(rc6_block_t block) {
    rc6_word_t last = block[3];
    memmove(block + 1, block, 12);
    block[0] = last;
}

void rc6_block_encode(void* dst, const void* src) {
    rc6_block_t block; rc6_word_t t, u; int i;
    rc6i_write_to_block(block, src);

    block[1] += rc6i_ctx.S[0];
    block[3] += rc6i_ctx.S[1];
    for (i = 1; i <= 20; i++) {
        t = rc6i_rotl(block[1] * (2 * block[1] + 1), 5);
        u = rc6i_rotl(block[3] * (2 * block[3] + 1), 5);
        block[0] = rc6i_rotl((block[0] ^ t), u) + rc6i_ctx.S[2 * i + 0];
        block[2] = rc6i_rotl((block[2] ^ u), t) + rc6i_ctx.S[2 * i + 1];
        rc6i_rotl_block(block);
    }
    block[0] += rc6i_ctx.S[42];
    block[2] += rc6i_ctx.S[43];

    rc6i_read_from_block(dst, block);
}

void rc6_block_decode(void* dst, const void* src) {
    rc6_block_t block; rc6_word_t t, u; int i;
    rc6i_write_to_block(block, src);

    block[2] -= rc6i_ctx.S[43];
    block[0] -= rc6i_ctx.S[42];
    for (i = 20; i > 0; i--) {
        rc6i_rotr_block(block);
        u = rc6i_rotl(block[3] * (2 * block[3] + 1), 5);
        t = rc6i_rotl(block[1] * (2 * block[1] + 1), 5);
        block[2] = rc6i_rotr(block[2] - rc6i_ctx.S[2 * i + 1], t) ^ u;
        block[0] = rc6i_rotr(block[0] - rc6i_ctx.S[2 * i + 0], u) ^ t;
    }
    block[3] -= rc6i_ctx.S[1];
    block[1] -= rc6i_ctx.S[0];

    rc6i_read_from_block(dst, block);
}