/* RC5 data interpretation
 *
 * 0    1    2    3    4    5    6    7    8
 * +----+----+----+----+----+----+----+----+
 * | P0 | P1 | P2 | P3 | P4 | P5 | P6 | P7 |  ->  0xP3P2P1P0 0xP7P6P5P4
 * +----+----+----+----+----+----+----+----+          A          B
 * ^- src
 *
 * 0    1    2    3    4    5    6    7    8
 * +----+----+----+----+----+----+----+----+
 * | C0 | C1 | C2 | C3 | C4 | C5 | C6 | C7 |  ->  0xC3C2C1C0 0xC7C6C5C4
 * +----+----+----+----+----+----+----+----+          A          B
 * ^- dest
 */

#define BLKCPHR_USE_ROTL32 1
#define BLKCPHR_USE_ROTR32 1

#include "rc5.h"
#include <string.h>
#include "config.h"

typedef blkcphr_u32_t rc5_word_t;

static struct {
    rc5_word_t S[42];
} rc5i_ctx;

#define rc5i_rotl blkcphr_rotl32
#define rc5i_rotr blkcphr_rotr32

int rc5_init(const void* key, int bits) {
    rc5_word_t A, B, L[64] = {0};
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

    rc5i_ctx.S[0] = 0xb7e15163;
    for (i = 1; i < 42; i++)
        rc5i_ctx.S[i] = rc5i_ctx.S[i - 1] + 0x9e3779b9;

    A = B = i = j = 0;
    for (m = 3 * (42 > c ? 42 : c), mi = 0; mi < m; mi++) {
        A = rc5i_ctx.S[i] = rc5i_rotl(rc5i_ctx.S[i] + A + B, 3);
        B =          L[j] = rc5i_rotl(         L[j] + A + B, A + B);
        i = (i + 1) % 42;
        j = (j + 1) %  c;
    }

    return 0;
}

static void rc5i_write_to_pair(rc5_word_t* A, rc5_word_t* B, const void* src) {
    memcpy(A, (const char*)src + 0, sizeof *A);
    memcpy(B, (const char*)src + 4, sizeof *B);
#if BLKCPHR_IS_BIG
    *A = blkcphr_bswap32(*A);
    *B = blkcphr_bswap32(*B);
#endif
}

static void rc5i_read_from_pair(void* dst, rc5_word_t A, rc5_word_t B) {
#if BLKCPHR_IS_BIG
    A = blkcphr_bswap32(A);
    B = blkcphr_bswap32(B);
#endif
    memcpy((char*)dst + 0, &A, sizeof A);
    memcpy((char*)dst + 4, &B, sizeof B);
}

void rc5_block_encode(void* dst, const void* src) {
    rc5_word_t A, B; int i;
    rc5i_write_to_pair(&A, &B, src);

    A += rc5i_ctx.S[0]; B += rc5i_ctx.S[1];
    for (i = 1; i <= 20; i++) {
        A = rc5i_rotl(A ^ B, B) + rc5i_ctx.S[2 * i + 0];
        B = rc5i_rotl(A ^ B, A) + rc5i_ctx.S[2 * i + 1];
    }

    rc5i_read_from_pair(dst, A, B);
}

void rc5_block_decode(void* dst, const void* src) {
    rc5_word_t A, B; int i;
    rc5i_write_to_pair(&A, &B, src);

    for (i = 20; i > 0; i--) {
        B = rc5i_rotr(B - rc5i_ctx.S[2 * i + 1], A) ^ A;
        A = rc5i_rotr(A - rc5i_ctx.S[2 * i + 0], B) ^ B;
    }
    B -= rc5i_ctx.S[1]; A -= rc5i_ctx.S[0];

    rc5i_read_from_pair(dst, A, B);
}