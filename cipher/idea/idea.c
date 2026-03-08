/* IDEA data interpretation
 *
 * 0    1    2    3    4    5    6    7    8
 * +----+----+----+----+----+----+----+----+
 * | P0 | P1 | P2 | P3 | P4 | P5 | P6 | P7 |  ->  0xP0P1 0xP2P3 0xP4P5 0xP6P7
 * +----+----+----+----+----+----+----+----+        [0]    [1]    [2]    [3]
 * ^- src
 *
 * 0    1    2    3    4    5    6    7    8
 * +----+----+----+----+----+----+----+----+
 * | C0 | C1 | C2 | C3 | C4 | C5 | C6 | C7 |  ->  0xC0C1 0xC2C3 0xC4C5 0xC6C7
 * +----+----+----+----+----+----+----+----+        [0]    [1]    [2]    [3]
 * ^- dest
 *
 * 0    1             15   16                   128-bit key
 * +----+---- ... ----+----+
 * | K0 | K1  ...  KE | KF |  ->  K0K1 K2K3 K4K5 K6K7 K8K9 KAKB KCKD KEKF
 * +----+---- ... ----+----+       [0]  [1]  [2]  [3]  [4]  [5]  [6]  [7]
 * ^- key
 */

#include "idea.h"
#include <string.h>
#include "config.h"

typedef blkcphr_u16_t idea_word_t;
typedef blkcphr_u64_t idea_text_t;

typedef idea_word_t idea_block_t[4];
typedef idea_word_t idea_chunk_t[8];

static struct {
    idea_word_t Kfwd[52];
    idea_word_t Kinv[52];
} ideai_ctx;

static idea_word_t ideai_mul(idea_word_t a, idea_word_t b) {
    idea_text_t out = (idea_text_t)a * (idea_text_t)b;
    if (out) return out % 0x10001;
    else     return 1 - a - b;
}

static idea_word_t ideai_inv(idea_text_t a) {
    idea_text_t o = 1; int i;
    for (i = 0; i < 16; i++) {
        o = (o * a) % 0x10001;
        a = (a * a) % 0x10001;
    }
    return o;
}

static void ideai_rotl25(idea_chunk_t in) {
    idea_chunk_t out;
    out[0] = in[1] << 9 | in[2] >> 7;
    out[1] = in[2] << 9 | in[3] >> 7;
    out[2] = in[3] << 9 | in[4] >> 7;
    out[3] = in[4] << 9 | in[5] >> 7;
    out[4] = in[5] << 9 | in[6] >> 7;
    out[5] = in[6] << 9 | in[7] >> 7;
    out[6] = in[7] << 9 | in[0] >> 7;
    out[7] = in[0] << 9 | in[1] >> 7;
    memcpy(in, out, sizeof out);
}

static void ideai_write_to_chunk(idea_chunk_t out, const void* src) {
    memcpy(out, src, sizeof(idea_chunk_t));
#if BLKCPHR_IS_LITTLE
    out[0] = blkcphr_bswap16(out[0]);
    out[1] = blkcphr_bswap16(out[1]);
    out[2] = blkcphr_bswap16(out[2]);
    out[3] = blkcphr_bswap16(out[3]);
    out[4] = blkcphr_bswap16(out[4]);
    out[5] = blkcphr_bswap16(out[5]);
    out[6] = blkcphr_bswap16(out[6]);
    out[7] = blkcphr_bswap16(out[7]);
#endif
}

static void ideai_write_to_block(idea_block_t out, const void* src) {
    memcpy(out, src, sizeof(idea_block_t));
#if BLKCPHR_IS_LITTLE
    out[0] = blkcphr_bswap16(out[0]);
    out[1] = blkcphr_bswap16(out[1]);
    out[2] = blkcphr_bswap16(out[2]);
    out[3] = blkcphr_bswap16(out[3]);
#endif
}

static void ideai_read_from_block(void* dst, const idea_block_t in) {
    idea_block_t T;
    memcpy(T, in, sizeof T);
#if BLKCPHR_IS_LITTLE
    T[0] = blkcphr_bswap16(T[0]);
    T[1] = blkcphr_bswap16(T[1]);
    T[2] = blkcphr_bswap16(T[2]);
    T[3] = blkcphr_bswap16(T[3]);
#endif
    memcpy(dst, T, sizeof T);
}

int idea_init(const void* key, int bits) {
    idea_chunk_t K; int i;

    if (bits != 128) return 1;
    ideai_write_to_chunk(K, key);

    for (i = 0; i < 6; i++) {
        memcpy(ideai_ctx.Kfwd + 8 * i, K, sizeof K);
        ideai_rotl25(K);
    }
    memcpy(ideai_ctx.Kfwd + 48, K, sizeof(idea_word_t) * 4);

    for (i = 0; i < 9; i++) {
        ideai_ctx.Kinv[6 * i + 0] = ideai_inv(ideai_ctx.Kfwd[6 * (8 - i) + 0]);
        ideai_ctx.Kinv[6 * i + 1] = -ideai_ctx.Kfwd[6 * (8 - i) + 1 + (0 < i && i < 8)];
        ideai_ctx.Kinv[6 * i + 2] = -ideai_ctx.Kfwd[6 * (8 - i) + 2 - (0 < i && i < 8)];
        ideai_ctx.Kinv[6 * i + 3] = ideai_inv(ideai_ctx.Kfwd[6 * (8 - i) + 3]);
        if (i < 8) {
            ideai_ctx.Kinv[6 * i + 4] = ideai_ctx.Kfwd[6 * (7 - i) + 4];
            ideai_ctx.Kinv[6 * i + 5] = ideai_ctx.Kfwd[6 * (7 - i) + 5];
        }
    }

    return 0;
}

void idea_block_encode(void* dst, const void* src) {
    idea_block_t block; int i;
    idea_word_t T1, T2, A, B, C, D, E, F;
    ideai_write_to_block(block, src);

    for (i = 0; i < 8; i++) {
        A = ideai_mul(block[0] , ideai_ctx.Kfwd[6 * i + 0]);
        B =           block[1] + ideai_ctx.Kfwd[6 * i + 1] ;
        C =           block[2] + ideai_ctx.Kfwd[6 * i + 2] ;
        D = ideai_mul(block[3] , ideai_ctx.Kfwd[6 * i + 3]);
        E = A ^ C;
        F = B ^ D;

        T1 = ideai_mul(E     , ideai_ctx.Kfwd[6 * i + 4]);
        T2 = ideai_mul(F + T1, ideai_ctx.Kfwd[6 * i + 5]);
        block[0] = A ^ T2;
        block[1] = C ^ T2;
        T2 = T1 + T2;
        block[2] = B ^ T2;
        block[3] = D ^ T2;
    }

    A = block[0]; B = block[1]; C = block[2]; D = block[3];
    block[0] = ideai_mul(A , ideai_ctx.Kfwd[48]);
    block[1] =           C + ideai_ctx.Kfwd[49] ;
    block[2] =           B + ideai_ctx.Kfwd[50] ;
    block[3] = ideai_mul(D , ideai_ctx.Kfwd[51]);

    ideai_read_from_block(dst, block);
}

void idea_block_decode(void* dst, const void* src) {
    idea_block_t block; int i;
    idea_word_t T1, T2, A, B, C, D, E, F;
    ideai_write_to_block(block, src);

    for (i = 0; i < 8; i++) {
        A = ideai_mul(block[0] , ideai_ctx.Kinv[6 * i + 0]);
        B =           block[1] + ideai_ctx.Kinv[6 * i + 1] ;
        C =           block[2] + ideai_ctx.Kinv[6 * i + 2] ;
        D = ideai_mul(block[3] , ideai_ctx.Kinv[6 * i + 3]);
        E = A ^ C;
        F = B ^ D;

        T1 = ideai_mul(E     , ideai_ctx.Kinv[6 * i + 4]);
        T2 = ideai_mul(F + T1, ideai_ctx.Kinv[6 * i + 5]);
        block[0] = A ^ T2;
        block[1] = C ^ T2;
        T2 = T1 + T2;
        block[2] = B ^ T2;
        block[3] = D ^ T2;
    }

    A = block[0]; B = block[1]; C = block[2]; D = block[3];
    block[0] = ideai_mul(A , ideai_ctx.Kinv[48]);
    block[1] =           C + ideai_ctx.Kinv[49] ;
    block[2] =           B + ideai_ctx.Kinv[50] ;
    block[3] = ideai_mul(D , ideai_ctx.Kinv[51]);

    ideai_read_from_block(dst, block);
}