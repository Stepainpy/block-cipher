/* LEA data intepretation
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
 *
 * 0    1            15   16                                        128-bit key
 * +----+---- ... ---+----+
 * | K0 | K1  ... KE | KF |                         ->  K3K2K1K0 K7K6K5K4 KBKAK9K8 KFKEKDKC
 * +----+---- ... ---+----+                               K[0]     K[1]     K[2]     K[3]
 * ^- key
 *
 * 0    1            15   16   17           23   24                 192-bit key
 * +----+---- ... ---+----+----+---- ... ---+----+
 * | K0 | K1  ... KE | KF | k0 | k1  ... k6 | k7 |  ->  K3K2K1K0 K7K6K5K4 KBKAK9K8 KFKEKDKC
 * +----+---- ... ---+----+----+---- ... ---+----+        K[0]     K[1]     K[2]     K[3]
 * ^- key                                               k3k2k1k0 k7k6k5k4
 *                                                        K[4]     K[5]
 *
 * 0    1            15   16   17           31   32                 256-bit key
 * +----+---- ... ---+----+----+---- ... ---+----+
 * | K0 | K1  ... KE | KF | k0 | k1  ... kE | kF |  ->  K3K2K1K0 K7K6K5K4 KBKAK9K8 KFKEKDKC
 * +----+---- ... ---+----+----+---- ... ---+----+        K[0]     K[1]     K[2]     K[3]
 * ^- key                                               k3k2k1k0 k7k6k5k4 kBkAk9k8 kFkEkDkC
 *                                                        K[4]     K[5]     K[6]     K[7]
 */

#include "lea.h"
#include <string.h>
#include "config.h"

typedef blkcphr_u32_t lea_word_t;

typedef lea_word_t lea_4block_t[4];
typedef lea_word_t lea_6block_t[6];
typedef lea_word_t lea_8block_t[8];

static const lea_word_t leai_delta[8];

static struct {
    lea_6block_t K[32];
    lea_word_t rounds;
} leai_ctx;

static lea_word_t leai_rotl(lea_word_t n, int s) { return n << s | n >> (-s & 31); }
static lea_word_t leai_rotr(lea_word_t n, int s) { return n >> s | n << (-s & 31); }

static void leai_write_to_4block(lea_4block_t out, const void* src) {
    memcpy(out, src, sizeof(lea_4block_t));
#if BLKCPHR_IS_BIG
    out[0] = blkcphr_bswap32(out[0]);
    out[1] = blkcphr_bswap32(out[1]);
    out[2] = blkcphr_bswap32(out[2]);
    out[3] = blkcphr_bswap32(out[3]);
#endif
}

static void leai_write_to_6block(lea_6block_t out, const void* src) {
    memcpy(out, src, sizeof(lea_6block_t));
#if BLKCPHR_IS_BIG
    out[0] = blkcphr_bswap32(out[0]);
    out[1] = blkcphr_bswap32(out[1]);
    out[2] = blkcphr_bswap32(out[2]);
    out[3] = blkcphr_bswap32(out[3]);
    out[4] = blkcphr_bswap32(out[4]);
    out[5] = blkcphr_bswap32(out[5]);
#endif
}

static void leai_write_to_8block(lea_8block_t out, const void* src) {
    memcpy(out, src, sizeof(lea_8block_t));
#if BLKCPHR_IS_BIG
    out[0] = blkcphr_bswap32(out[0]);
    out[1] = blkcphr_bswap32(out[1]);
    out[2] = blkcphr_bswap32(out[2]);
    out[3] = blkcphr_bswap32(out[3]);
    out[4] = blkcphr_bswap32(out[4]);
    out[5] = blkcphr_bswap32(out[5]);
    out[6] = blkcphr_bswap32(out[6]);
    out[7] = blkcphr_bswap32(out[7]);
#endif
}

static void leai_read_from_4block(void* dst, const lea_4block_t in) {
    lea_4block_t T;
    memcpy(T, in, LEA_BLOCK_BYTE);
#if BLKCPHR_IS_BIG
    T[0] = blkcphr_bswap32(T[0]);
    T[1] = blkcphr_bswap32(T[1]);
    T[2] = blkcphr_bswap32(T[2]);
    T[3] = blkcphr_bswap32(T[3]);
#endif
    memcpy(dst, T, LEA_BLOCK_BYTE);
}

static void leai_init_key128(const void* key) {
    lea_4block_t T; int i;
    leai_write_to_4block(T, key);

    leai_ctx.rounds = 24;
    for (i = 0; i < 24; i++) {
        T[0] = leai_rotl(T[0] + leai_rotl(leai_delta[i & 3], i + 0),  1);
        T[1] = leai_rotl(T[1] + leai_rotl(leai_delta[i & 3], i + 1),  3);
        T[2] = leai_rotl(T[2] + leai_rotl(leai_delta[i & 3], i + 2),  6);
        T[3] = leai_rotl(T[3] + leai_rotl(leai_delta[i & 3], i + 3), 11);

        leai_ctx.K[i][0] = T[0]; leai_ctx.K[i][1] = T[1];
        leai_ctx.K[i][2] = T[2]; leai_ctx.K[i][3] = T[1];
        leai_ctx.K[i][4] = T[3]; leai_ctx.K[i][5] = T[1];
    }
}

static void leai_init_key192(const void* key) {
    lea_6block_t T; int i;
    leai_write_to_6block(T, key);

    leai_ctx.rounds = 28;
    for (i = 0; i < 28; i++) {
        leai_ctx.K[i][0] = T[0] = leai_rotl(T[0] + leai_rotl(leai_delta[i % 6], i + 0),  1);
        leai_ctx.K[i][1] = T[1] = leai_rotl(T[1] + leai_rotl(leai_delta[i % 6], i + 1),  3);
        leai_ctx.K[i][2] = T[2] = leai_rotl(T[2] + leai_rotl(leai_delta[i % 6], i + 2),  6);
        leai_ctx.K[i][3] = T[3] = leai_rotl(T[3] + leai_rotl(leai_delta[i % 6], i + 3), 11);
        leai_ctx.K[i][4] = T[4] = leai_rotl(T[4] + leai_rotl(leai_delta[i % 6], i + 4), 13);
        leai_ctx.K[i][5] = T[5] = leai_rotl(T[5] + leai_rotl(leai_delta[i % 6], i + 5), 17);
    }
}

static void leai_init_key256(const void* key) {
    lea_8block_t T; int i;
    leai_write_to_8block(T, key);

    leai_ctx.rounds = 32;
    for (i = 0; i < 32; i++) {
        leai_ctx.K[i][0] = T[(6*i+0) & 7] = leai_rotl(T[(6*i+0) & 7] + leai_rotl(leai_delta[i & 7], i + 0),  1);
        leai_ctx.K[i][1] = T[(6*i+1) & 7] = leai_rotl(T[(6*i+1) & 7] + leai_rotl(leai_delta[i & 7], i + 1),  3);
        leai_ctx.K[i][2] = T[(6*i+2) & 7] = leai_rotl(T[(6*i+2) & 7] + leai_rotl(leai_delta[i & 7], i + 2),  6);
        leai_ctx.K[i][3] = T[(6*i+3) & 7] = leai_rotl(T[(6*i+3) & 7] + leai_rotl(leai_delta[i & 7], i + 3), 11);
        leai_ctx.K[i][4] = T[(6*i+4) & 7] = leai_rotl(T[(6*i+4) & 7] + leai_rotl(leai_delta[i & 7], i + 4), 13);
        leai_ctx.K[i][5] = T[(6*i+5) & 7] = leai_rotl(T[(6*i+5) & 7] + leai_rotl(leai_delta[i & 7], i + 5), 17);
    }
}

int lea_init(const void* key, int bits) {
    switch (bits) {
        case 128: leai_init_key128(key); return 0;
        case 192: leai_init_key192(key); return 0;
        case 256: leai_init_key256(key); return 0;
        default: return 1;
    }
}

void lea_block_encode(void* dst, const void* src) {
    lea_4block_t Xp, Xc; lea_word_t i;
    leai_write_to_4block(Xp, src);

    for (i = 0; i < leai_ctx.rounds; i++) {
        Xc[0] = leai_rotl((Xp[0] ^ leai_ctx.K[i][0]) + (Xp[1] ^ leai_ctx.K[i][1]), 9);
        Xc[1] = leai_rotr((Xp[1] ^ leai_ctx.K[i][2]) + (Xp[2] ^ leai_ctx.K[i][3]), 5);
        Xc[2] = leai_rotr((Xp[2] ^ leai_ctx.K[i][4]) + (Xp[3] ^ leai_ctx.K[i][5]), 3);
        Xc[3] = Xp[0];
        memcpy(Xp, Xc, LEA_BLOCK_BYTE);
    }

    leai_read_from_4block(dst, Xp);
}

void lea_block_decode(void* dst, const void* src) {
    lea_4block_t Xp, Xc; lea_word_t i;
    leai_write_to_4block(Xp, src);

    for (i = leai_ctx.rounds; i --> 0;) {
        Xc[0] = Xp[3];
        Xc[1] = (leai_rotr(Xp[0], 9) - (Xc[0] ^ leai_ctx.K[i][0])) ^ leai_ctx.K[i][1];
        Xc[2] = (leai_rotl(Xp[1], 5) - (Xc[1] ^ leai_ctx.K[i][2])) ^ leai_ctx.K[i][3];
        Xc[3] = (leai_rotl(Xp[2], 3) - (Xc[2] ^ leai_ctx.K[i][4])) ^ leai_ctx.K[i][5];
        memcpy(Xp, Xc, LEA_BLOCK_BYTE);
    }

    leai_read_from_4block(dst, Xp);
}

static const lea_word_t leai_delta[8] = {
    0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec,
    0x715ea49e, 0xc785da0a, 0xe04ef22a, 0xe5c40957
};