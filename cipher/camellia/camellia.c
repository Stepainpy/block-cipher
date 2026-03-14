/* Camellia data interpretation
 *
 * 0    1    2    3    4    5    6    7    8    9    10   11   12   13   14   15   16
 * +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
 * | P0 | P1 | P2 | P3 | P4 | P5 | P6 | P7 | P8 | P9 | PA | PB | PC | PD | PE | PF |  ->  0xP0P1P2P3P4P5P6P7 0xP8P9PAPBPCPDPEPF
 * +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+             D[0]               D[1]
 * ^- src
 *
 * 0    1    2    3    4    5    6    7    8    9    10   11   12   13   14   15   16
 * +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
 * | C0 | C1 | C2 | C3 | C4 | C5 | C6 | C7 | C8 | C9 | CA | CB | CC | CD | CE | CF |  ->  0xC0C1C2C3C4C5C6C7 0xC8C9CACBCCCDCECF
 * +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+             D[0]               D[1]
 * ^- dest
 *
 * 0    1            15   16                                       128-bit key
 * +----+---- ... ---+----+
 * | K0 | K1  ... KE | KF |                         ->  K0K1K2K3K4K5K6K7 K8K9KAKBKCKDKEKF
 * +----+---- ... ---+----+                                   KL[0]            KL[1]
 * ^- key
 *
 * 0    1            15   16   17           23   24                192-bit key
 * +----+---- ... ---+----+----+---- ... ---+----+
 * | K0 | K1  ... KE | KF | k0 | k1  ... k6 | k7 |  ->  K0K1K2K3K4K5K6K7 K8K9KAKBKCKDKEKF
 * +----+---- ... ---+----+----+---- ... ---+----+            KL[0]            KL[1]
 * ^- key                                               k0k1k2k3k4k5k6k7
 *                                                            KR[0]
 *
 * 0    1            15   16   17           31   32                256-bit key
 * +----+---- ... ---+----+----+---- ... ---+----+
 * | K0 | K1  ... KE | KF | k0 | k1  ... kE | kF |  ->  K0K1K2K3K4K5K6K7 K8K9KAKBKCKDKEKF
 * +----+---- ... ---+----+----+---- ... ---+----+            KL[0]            KL[1]
 * ^- key                                               k0k1k2k3k4k5k6k7 k8k9kAkBkCkDkEkF
 *                                                            KR[0]            KR[1]
 */

#define BLKCPHR_USE_ROTL32 camei_rotl

#include "camellia.h"
#include <string.h>
#include "config.h"

typedef blkcphr_u8_t  came_byte_t;
typedef blkcphr_u32_t came_half_t;
typedef blkcphr_u64_t came_word_t;

typedef came_byte_t came_brick_t[8];
typedef came_word_t came_block_t[2];

static const came_byte_t camei_S1[256];
static const came_byte_t camei_S2[256];
static const came_byte_t camei_S3[256];
static const came_byte_t camei_S4[256];

static const came_word_t camei_sigma[6];

static struct {
    came_word_t KR[24];
    came_word_t KE[ 6];
    came_word_t KW[ 4];
    came_byte_t rounds;
    came_byte_t flcnt;
} camei_ctx;

static void camei_rotl128(came_block_t in, came_word_t s) {
    came_block_t out; s &= 127;
    if (s < 64) {
        out[0] = in[0] << s | in[1] >> (-s & 63);
        out[1] = in[1] << s | in[0] >> (-s & 63);
    } else { s -= 64;
        out[0] = in[1] << s | in[0] >> (-s & 63);
        out[1] = in[0] << s | in[1] >> (-s & 63);
    }
    memcpy(in, out, sizeof out);
}

static void camei_write_to_block(came_block_t out, const void* src) {
    memcpy(out, src, sizeof(came_block_t));
    BLKCPHR_IF_LITTLE(BLKCPHR_BSWAP_64x2(out));
}

static void camei_read_from_block(void* dst, const came_block_t in) {
    came_block_t T;
    memcpy(T, in, sizeof T);
    BLKCPHR_IF_LITTLE(BLKCPHR_BSWAP_64x2(T));
    memcpy(dst, T, sizeof T);
}

static void camei_write_to_brick(came_brick_t out, const came_word_t src) {
    out[0] = (src >> 56) & 0xFF;
    out[1] = (src >> 48) & 0xFF;
    out[2] = (src >> 40) & 0xFF;
    out[3] = (src >> 32) & 0xFF;
    out[4] = (src >> 24) & 0xFF;
    out[5] = (src >> 16) & 0xFF;
    out[6] = (src >>  8) & 0xFF;
    out[7] = (src >>  0) & 0xFF;
}

static came_word_t camei_read_from_brick(const came_brick_t in) {
    came_word_t out = 0;
    out |= (came_word_t)in[0] << 56;
    out |= (came_word_t)in[1] << 48;
    out |= (came_word_t)in[2] << 40;
    out |= (came_word_t)in[3] << 32;
    out |= (came_word_t)in[4] << 24;
    out |= (came_word_t)in[5] << 16;
    out |= (came_word_t)in[6] <<  8;
    out |= (came_word_t)in[7] <<  0;
    return out;
}

static came_word_t camei_F(came_word_t x) {
    came_brick_t t, out;
    camei_write_to_brick(t, x);

    t[0] = camei_S1[t[0]]; t[1] = camei_S2[t[1]];
    t[2] = camei_S3[t[2]]; t[3] = camei_S4[t[3]];
    t[4] = camei_S2[t[4]]; t[5] = camei_S3[t[5]];
    t[6] = camei_S4[t[6]]; t[7] = camei_S1[t[7]];

    out[0] = t[0] ^ t[2] ^ t[3] ^ t[5] ^ t[6] ^ t[7];
    out[1] = t[0] ^ t[1] ^ t[3] ^ t[4] ^ t[6] ^ t[7];
    out[2] = t[0] ^ t[1] ^ t[2] ^ t[4] ^ t[5] ^ t[7];
    out[3] = t[1] ^ t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[6];
    out[4] = t[0] ^ t[1] ^ t[5] ^ t[6] ^ t[7];
    out[5] = t[1] ^ t[2] ^ t[4] ^ t[6] ^ t[7];
    out[6] = t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[7];
    out[7] = t[0] ^ t[3] ^ t[4] ^ t[5] ^ t[6];

    return camei_read_from_brick(out);
}

static came_word_t camei_FL_fwd(came_word_t in, came_word_t ke) {
    came_half_t x1, x2, k1, k2;
    x1 = in >> 32; x2 = in & 0xFFFFFFFF;
    k1 = ke >> 32; k2 = ke & 0xFFFFFFFF;

    x2 ^= camei_rotl(x1 & k1, 1);
    x1 ^= x2 | k2;

    return (came_word_t)x1 << 32 | x2;
}

static came_word_t camei_FL_inv(came_word_t in, came_word_t ke) {
    came_half_t y1, y2, k1, k2;
    y1 = in >> 32; y2 = in & 0xFFFFFFFF;
    k1 = ke >> 32; k2 = ke & 0xFFFFFFFF;

    y1 ^= y2 | k2;
    y2 ^= camei_rotl(y1 & k1, 1);

    return (came_word_t)y1 << 32 | y2;
}

static void camei_init_key128(const void* key) {
    came_block_t D, KL, KA;

    camei_write_to_block(KL, key);

    D[0] = KL[0]; D[1] = KL[1];
    D[1] ^= camei_F(D[0] ^ camei_sigma[0]);
    D[0] ^= camei_F(D[1] ^ camei_sigma[1]);

    D[0] ^= KL[0]; D[1] ^= KL[1];
    D[1] ^= camei_F(D[0] ^ camei_sigma[2]);
    D[0] ^= camei_F(D[1] ^ camei_sigma[3]);
    memcpy(KA, D, sizeof D);

    /* KL <<< 0 | KA <<< 0 */
    camei_ctx.KW[0] = KL[0]; camei_ctx.KW[1] = KL[1];
    camei_ctx.KR[0] = KA[0]; camei_ctx.KR[1] = KA[1];
    camei_rotl128(KL, 15);
    camei_rotl128(KA, 15);
    /* KL <<< 15 | KA <<< 15 */
    camei_ctx.KR[2] = KL[0]; camei_ctx.KR[3] = KL[1];
    camei_ctx.KR[4] = KA[0]; camei_ctx.KR[5] = KA[1];
    camei_rotl128(KA, 15);
    /* KL <<< 15 | KA <<< 30 */
    camei_ctx.KE[0] = KA[0]; camei_ctx.KE[1] = KA[1];
    camei_rotl128(KL, 30);
    /* KL <<< 45 | KA <<< 30 */
    camei_ctx.KR[6] = KL[0]; camei_ctx.KR[7] = KL[1];
    camei_rotl128(KL, 15);
    camei_rotl128(KA, 15);
    /* KL <<< 60 | KA <<< 45 */
    camei_ctx.KR[8] = KA[0]; camei_ctx.KR[9] = KL[1];
    camei_rotl128(KA, 15);
    /* KL <<< 60 | KA <<< 60 */
    camei_ctx.KR[10] = KA[0]; camei_ctx.KR[11] = KA[1];
    camei_rotl128(KL, 17);
    /* KL <<< 77 | KA <<< 60 */
    camei_ctx.KE[2] = KL[0]; camei_ctx.KE[3] = KL[1];
    camei_rotl128(KL, 17);
    camei_rotl128(KA, 34);
    /* KL <<< 94 | KA <<< 94 */
    camei_ctx.KR[12] = KL[0]; camei_ctx.KR[13] = KL[1];
    camei_ctx.KR[14] = KA[0]; camei_ctx.KR[15] = KA[1];
    camei_rotl128(KL, 17);
    camei_rotl128(KA, 17);
    /* KL <<< 111 | KA <<< 111 */
    camei_ctx.KR[16] = KL[0]; camei_ctx.KR[17] = KL[1];
    camei_ctx.KW[ 2] = KA[0]; camei_ctx.KW[ 3] = KA[1];

    camei_ctx.rounds = 18;
    camei_ctx.flcnt  =  4;
}

static void camei_init_key192(const void* key) {
    came_block_t D, KL, KR, KA, KB;
    came_word_t temp;

    camei_write_to_block(KL, key);
    temp = ((const came_word_t*)key)[2];
    BLKCPHR_IF_LITTLE(BLKCPHR_BSWAP_64_ONE(temp));
    KR[0] = temp; KR[1] = ~temp;

    D[0] = KL[0] ^ KR[0]; D[1] = KL[1] ^ KR[1];
    D[1] ^= camei_F(D[0] ^ camei_sigma[0]);
    D[0] ^= camei_F(D[1] ^ camei_sigma[1]);

    D[0] ^= KL[0]; D[1] ^= KL[1];
    D[1] ^= camei_F(D[0] ^ camei_sigma[2]);
    D[0] ^= camei_F(D[1] ^ camei_sigma[3]);
    memcpy(KA, D, sizeof D);

    D[0] = KA[0] ^ KR[0]; D[1] = KA[1] ^ KR[1];
    D[1] ^= camei_F(D[0] ^ camei_sigma[4]);
    D[0] ^= camei_F(D[1] ^ camei_sigma[5]);
    memcpy(KB, D, sizeof D);

    /* KL <<< 0 | KR <<< 0 | KA <<< 0 | KB <<< 0 */
    camei_ctx.KW[0] = KL[0]; camei_ctx.KW[1] = KL[1];
    camei_ctx.KR[0] = KB[0]; camei_ctx.KR[1] = KB[1];
    camei_rotl128(KR, 15);
    camei_rotl128(KA, 15);
    /* KL <<< 0 | KR <<< 15 | KA <<< 15 | KB <<< 0 */
    camei_ctx.KR[2] = KR[0]; camei_ctx.KR[3] = KR[1];
    camei_ctx.KR[4] = KA[0]; camei_ctx.KR[5] = KA[1];
    camei_rotl128(KR, 15);
    camei_rotl128(KB, 30);
    /* KL <<< 0 | KR <<< 30 | KA <<< 15 | KB <<< 30 */
    camei_ctx.KE[0] = KR[0]; camei_ctx.KE[1] = KR[1];
    camei_ctx.KR[6] = KB[0]; camei_ctx.KR[7] = KB[1];
    camei_rotl128(KL, 45);
    camei_rotl128(KA, 30);
    /* KL <<< 45 | KR <<< 30 | KA <<< 45 | KB <<< 30 */
    camei_ctx.KR[ 8] = KL[0]; camei_ctx.KR[ 9] = KL[1];
    camei_ctx.KR[10] = KA[0]; camei_ctx.KR[11] = KA[1];
    camei_rotl128(KL, 15);
    camei_rotl128(KR, 30);
    camei_rotl128(KB, 30);
    /* KL <<< 60 | KR <<< 60 | KA <<< 45 | KB <<< 60 */
    camei_ctx.KE[ 2] = KL[0]; camei_ctx.KE[ 3] = KL[1];
    camei_ctx.KR[12] = KR[0]; camei_ctx.KR[13] = KR[1];
    camei_ctx.KR[14] = KB[0]; camei_ctx.KR[15] = KB[1];
    camei_rotl128(KL, 17);
    camei_rotl128(KA, 32);
    /* KL <<< 77 | KR <<< 60 | KA <<< 77 | KB <<< 60 */
    camei_ctx.KR[16] = KL[0]; camei_ctx.KR[17] = KL[1];
    camei_ctx.KE[ 4] = KA[0]; camei_ctx.KE[ 5] = KA[1];
    camei_rotl128(KR, 34);
    camei_rotl128(KA, 17);
    /* KL <<< 77 | KR <<< 94 | KA <<< 94 | KB <<< 60 */
    camei_ctx.KR[18] = KR[0]; camei_ctx.KR[19] = KR[1];
    camei_ctx.KR[20] = KA[0]; camei_ctx.KR[21] = KA[1];
    camei_rotl128(KL, 34);
    camei_rotl128(KB, 51);
    /* KL <<< 111 | KR <<< 94 | KA <<< 94 | KB <<< 111 */
    camei_ctx.KR[22] = KL[0]; camei_ctx.KR[23] = KL[1];
    camei_ctx.KW[ 2] = KB[0]; camei_ctx.KW[ 3] = KB[1];

    camei_ctx.rounds = 24;
    camei_ctx.flcnt  =  6;
}

static void camei_init_key256(const void* key) {
    came_block_t D, KL, KR, KA, KB;

    camei_write_to_block(KL, (const char*)key +  0);
    camei_write_to_block(KR, (const char*)key + 16);

    D[0] = KL[0] ^ KR[0]; D[1] = KL[1] ^ KR[1];
    D[1] ^= camei_F(D[0] ^ camei_sigma[0]);
    D[0] ^= camei_F(D[1] ^ camei_sigma[1]);

    D[0] ^= KL[0]; D[1] ^= KL[1];
    D[1] ^= camei_F(D[0] ^ camei_sigma[2]);
    D[0] ^= camei_F(D[1] ^ camei_sigma[3]);
    memcpy(KA, D, sizeof D);

    D[0] = KA[0] ^ KR[0]; D[1] = KA[1] ^ KR[1];
    D[1] ^= camei_F(D[0] ^ camei_sigma[4]);
    D[0] ^= camei_F(D[1] ^ camei_sigma[5]);
    memcpy(KB, D, sizeof D);

    /* KL <<< 0 | KR <<< 0 | KA <<< 0 | KB <<< 0 */
    camei_ctx.KW[0] = KL[0]; camei_ctx.KW[1] = KL[1];
    camei_ctx.KR[0] = KB[0]; camei_ctx.KR[1] = KB[1];
    camei_rotl128(KR, 15);
    camei_rotl128(KA, 15);
    /* KL <<< 0 | KR <<< 15 | KA <<< 15 | KB <<< 0 */
    camei_ctx.KR[2] = KR[0]; camei_ctx.KR[3] = KR[1];
    camei_ctx.KR[4] = KA[0]; camei_ctx.KR[5] = KA[1];
    camei_rotl128(KR, 15);
    camei_rotl128(KB, 30);
    /* KL <<< 0 | KR <<< 30 | KA <<< 15 | KB <<< 30 */
    camei_ctx.KE[0] = KR[0]; camei_ctx.KE[1] = KR[1];
    camei_ctx.KR[6] = KB[0]; camei_ctx.KR[7] = KB[1];
    camei_rotl128(KL, 45);
    camei_rotl128(KA, 30);
    /* KL <<< 45 | KR <<< 30 | KA <<< 45 | KB <<< 30 */
    camei_ctx.KR[ 8] = KL[0]; camei_ctx.KR[ 9] = KL[1];
    camei_ctx.KR[10] = KA[0]; camei_ctx.KR[11] = KA[1];
    camei_rotl128(KL, 15);
    camei_rotl128(KR, 30);
    camei_rotl128(KB, 30);
    /* KL <<< 60 | KR <<< 60 | KA <<< 45 | KB <<< 60 */
    camei_ctx.KE[ 2] = KL[0]; camei_ctx.KE[ 3] = KL[1];
    camei_ctx.KR[12] = KR[0]; camei_ctx.KR[13] = KR[1];
    camei_ctx.KR[14] = KB[0]; camei_ctx.KR[15] = KB[1];
    camei_rotl128(KL, 17);
    camei_rotl128(KA, 32);
    /* KL <<< 77 | KR <<< 60 | KA <<< 77 | KB <<< 60 */
    camei_ctx.KR[16] = KL[0]; camei_ctx.KR[17] = KL[1];
    camei_ctx.KE[ 4] = KA[0]; camei_ctx.KE[ 5] = KA[1];
    camei_rotl128(KR, 34);
    camei_rotl128(KA, 17);
    /* KL <<< 77 | KR <<< 94 | KA <<< 94 | KB <<< 60 */
    camei_ctx.KR[18] = KR[0]; camei_ctx.KR[19] = KR[1];
    camei_ctx.KR[20] = KA[0]; camei_ctx.KR[21] = KA[1];
    camei_rotl128(KL, 34);
    camei_rotl128(KB, 51);
    /* KL <<< 111 | KR <<< 94 | KA <<< 94 | KB <<< 111 */
    camei_ctx.KR[22] = KL[0]; camei_ctx.KR[23] = KL[1];
    camei_ctx.KW[ 2] = KB[0]; camei_ctx.KW[ 3] = KB[1];

    camei_ctx.rounds = 24;
    camei_ctx.flcnt  =  6;
}

int camellia_init(const void* key, int bits) {
    switch (bits) {
        case 128: camei_init_key128(key); return 0;
        case 192: camei_init_key192(key); return 0;
        case 256: camei_init_key256(key); return 0;
        default: return 1;
    }
}

void camellia_block_encode(void* dst, const void* src) {
    came_block_t D; came_word_t i, j, temp;
    camei_write_to_block(D, src);

    D[0] ^= camei_ctx.KW[0]; D[1] ^= camei_ctx.KW[1];
    for (i = 0, j = 0; i < camei_ctx.rounds; i += 2) {
        D[1] ^= camei_F(D[0] ^ camei_ctx.KR[i + 0]);
        D[0] ^= camei_F(D[1] ^ camei_ctx.KR[i + 1]);
        if ((i + 2) % 6 == 0 && (i + 2) < camei_ctx.rounds) {
            D[0] = camei_FL_fwd(D[0], camei_ctx.KE[j++]);
            D[1] = camei_FL_inv(D[1], camei_ctx.KE[j++]);
        }
    }
    D[1] ^= camei_ctx.KW[2]; D[0] ^= camei_ctx.KW[3];

    temp = D[0]; D[0] = D[1]; D[1] = temp;
    camei_read_from_block(dst, D);
}

void camellia_block_decode(void* dst, const void* src) {
    came_block_t D; came_word_t i, j, temp;
    camei_write_to_block(D, src);

    D[0] ^= camei_ctx.KW[2]; D[1] ^= camei_ctx.KW[3];
    for (i = 0, j = 0; i < camei_ctx.rounds; i += 2) {
        D[1] ^= camei_F(D[0] ^ camei_ctx.KR[camei_ctx.rounds - i - 1]);
        D[0] ^= camei_F(D[1] ^ camei_ctx.KR[camei_ctx.rounds - i - 2]);
        if ((i + 2) % 6 == 0 && (i + 2) < camei_ctx.rounds) {
            D[0] = camei_FL_fwd(D[0], camei_ctx.KE[camei_ctx.flcnt - ++j]);
            D[1] = camei_FL_inv(D[1], camei_ctx.KE[camei_ctx.flcnt - ++j]);
        }
    }
    D[1] ^= camei_ctx.KW[0]; D[0] ^= camei_ctx.KW[1];

    temp = D[0]; D[0] = D[1]; D[1] = temp;
    camei_read_from_block(dst, D);
}

static const came_byte_t camei_S1[256] = {
    0x70, 0x82, 0x2c, 0xec, 0xb3, 0x27, 0xc0, 0xe5, 0xe4, 0x85, 0x57, 0x35, 0xea, 0x0c, 0xae, 0x41,
    0x23, 0xef, 0x6b, 0x93, 0x45, 0x19, 0xa5, 0x21, 0xed, 0x0e, 0x4f, 0x4e, 0x1d, 0x65, 0x92, 0xbd,
    0x86, 0xb8, 0xaf, 0x8f, 0x7c, 0xeb, 0x1f, 0xce, 0x3e, 0x30, 0xdc, 0x5f, 0x5e, 0xc5, 0x0b, 0x1a,
    0xa6, 0xe1, 0x39, 0xca, 0xd5, 0x47, 0x5d, 0x3d, 0xd9, 0x01, 0x5a, 0xd6, 0x51, 0x56, 0x6c, 0x4d,
    0x8b, 0x0d, 0x9a, 0x66, 0xfb, 0xcc, 0xb0, 0x2d, 0x74, 0x12, 0x2b, 0x20, 0xf0, 0xb1, 0x84, 0x99,
    0xdf, 0x4c, 0xcb, 0xc2, 0x34, 0x7e, 0x76, 0x05, 0x6d, 0xb7, 0xa9, 0x31, 0xd1, 0x17, 0x04, 0xd7,
    0x14, 0x58, 0x3a, 0x61, 0xde, 0x1b, 0x11, 0x1c, 0x32, 0x0f, 0x9c, 0x16, 0x53, 0x18, 0xf2, 0x22,
    0xfe, 0x44, 0xcf, 0xb2, 0xc3, 0xb5, 0x7a, 0x91, 0x24, 0x08, 0xe8, 0xa8, 0x60, 0xfc, 0x69, 0x50,
    0xaa, 0xd0, 0xa0, 0x7d, 0xa1, 0x89, 0x62, 0x97, 0x54, 0x5b, 0x1e, 0x95, 0xe0, 0xff, 0x64, 0xd2,
    0x10, 0xc4, 0x00, 0x48, 0xa3, 0xf7, 0x75, 0xdb, 0x8a, 0x03, 0xe6, 0xda, 0x09, 0x3f, 0xdd, 0x94,
    0x87, 0x5c, 0x83, 0x02, 0xcd, 0x4a, 0x90, 0x33, 0x73, 0x67, 0xf6, 0xf3, 0x9d, 0x7f, 0xbf, 0xe2,
    0x52, 0x9b, 0xd8, 0x26, 0xc8, 0x37, 0xc6, 0x3b, 0x81, 0x96, 0x6f, 0x4b, 0x13, 0xbe, 0x63, 0x2e,
    0xe9, 0x79, 0xa7, 0x8c, 0x9f, 0x6e, 0xbc, 0x8e, 0x29, 0xf5, 0xf9, 0xb6, 0x2f, 0xfd, 0xb4, 0x59,
    0x78, 0x98, 0x06, 0x6a, 0xe7, 0x46, 0x71, 0xba, 0xd4, 0x25, 0xab, 0x42, 0x88, 0xa2, 0x8d, 0xfa,
    0x72, 0x07, 0xb9, 0x55, 0xf8, 0xee, 0xac, 0x0a, 0x36, 0x49, 0x2a, 0x68, 0x3c, 0x38, 0xf1, 0xa4,
    0x40, 0x28, 0xd3, 0x7b, 0xbb, 0xc9, 0x43, 0xc1, 0x15, 0xe3, 0xad, 0xf4, 0x77, 0xc7, 0x80, 0x9e
};

static const came_byte_t camei_S2[256] = {
    0xe0, 0x05, 0x58, 0xd9, 0x67, 0x4e, 0x81, 0xcb, 0xc9, 0x0b, 0xae, 0x6a, 0xd5, 0x18, 0x5d, 0x82,
    0x46, 0xdf, 0xd6, 0x27, 0x8a, 0x32, 0x4b, 0x42, 0xdb, 0x1c, 0x9e, 0x9c, 0x3a, 0xca, 0x25, 0x7b,
    0x0d, 0x71, 0x5f, 0x1f, 0xf8, 0xd7, 0x3e, 0x9d, 0x7c, 0x60, 0xb9, 0xbe, 0xbc, 0x8b, 0x16, 0x34,
    0x4d, 0xc3, 0x72, 0x95, 0xab, 0x8e, 0xba, 0x7a, 0xb3, 0x02, 0xb4, 0xad, 0xa2, 0xac, 0xd8, 0x9a,
    0x17, 0x1a, 0x35, 0xcc, 0xf7, 0x99, 0x61, 0x5a, 0xe8, 0x24, 0x56, 0x40, 0xe1, 0x63, 0x09, 0x33,
    0xbf, 0x98, 0x97, 0x85, 0x68, 0xfc, 0xec, 0x0a, 0xda, 0x6f, 0x53, 0x62, 0xa3, 0x2e, 0x08, 0xaf,
    0x28, 0xb0, 0x74, 0xc2, 0xbd, 0x36, 0x22, 0x38, 0x64, 0x1e, 0x39, 0x2c, 0xa6, 0x30, 0xe5, 0x44,
    0xfd, 0x88, 0x9f, 0x65, 0x87, 0x6b, 0xf4, 0x23, 0x48, 0x10, 0xd1, 0x51, 0xc0, 0xf9, 0xd2, 0xa0,
    0x55, 0xa1, 0x41, 0xfa, 0x43, 0x13, 0xc4, 0x2f, 0xa8, 0xb6, 0x3c, 0x2b, 0xc1, 0xff, 0xc8, 0xa5,
    0x20, 0x89, 0x00, 0x90, 0x47, 0xef, 0xea, 0xb7, 0x15, 0x06, 0xcd, 0xb5, 0x12, 0x7e, 0xbb, 0x29,
    0x0f, 0xb8, 0x07, 0x04, 0x9b, 0x94, 0x21, 0x66, 0xe6, 0xce, 0xed, 0xe7, 0x3b, 0xfe, 0x7f, 0xc5,
    0xa4, 0x37, 0xb1, 0x4c, 0x91, 0x6e, 0x8d, 0x76, 0x03, 0x2d, 0xde, 0x96, 0x26, 0x7d, 0xc6, 0x5c,
    0xd3, 0xf2, 0x4f, 0x19, 0x3f, 0xdc, 0x79, 0x1d, 0x52, 0xeb, 0xf3, 0x6d, 0x5e, 0xfb, 0x69, 0xb2,
    0xf0, 0x31, 0x0c, 0xd4, 0xcf, 0x8c, 0xe2, 0x75, 0xa9, 0x4a, 0x57, 0x84, 0x11, 0x45, 0x1b, 0xf5,
    0xe4, 0x0e, 0x73, 0xaa, 0xf1, 0xdd, 0x59, 0x14, 0x6c, 0x92, 0x54, 0xd0, 0x78, 0x70, 0xe3, 0x49,
    0x80, 0x50, 0xa7, 0xf6, 0x77, 0x93, 0x86, 0x83, 0x2a, 0xc7, 0x5b, 0xe9, 0xee, 0x8f, 0x01, 0x3d
};

static const came_byte_t camei_S3[256] = {
    0x38, 0x41, 0x16, 0x76, 0xd9, 0x93, 0x60, 0xf2, 0x72, 0xc2, 0xab, 0x9a, 0x75, 0x06, 0x57, 0xa0,
    0x91, 0xf7, 0xb5, 0xc9, 0xa2, 0x8c, 0xd2, 0x90, 0xf6, 0x07, 0xa7, 0x27, 0x8e, 0xb2, 0x49, 0xde,
    0x43, 0x5c, 0xd7, 0xc7, 0x3e, 0xf5, 0x8f, 0x67, 0x1f, 0x18, 0x6e, 0xaf, 0x2f, 0xe2, 0x85, 0x0d,
    0x53, 0xf0, 0x9c, 0x65, 0xea, 0xa3, 0xae, 0x9e, 0xec, 0x80, 0x2d, 0x6b, 0xa8, 0x2b, 0x36, 0xa6,
    0xc5, 0x86, 0x4d, 0x33, 0xfd, 0x66, 0x58, 0x96, 0x3a, 0x09, 0x95, 0x10, 0x78, 0xd8, 0x42, 0xcc,
    0xef, 0x26, 0xe5, 0x61, 0x1a, 0x3f, 0x3b, 0x82, 0xb6, 0xdb, 0xd4, 0x98, 0xe8, 0x8b, 0x02, 0xeb,
    0x0a, 0x2c, 0x1d, 0xb0, 0x6f, 0x8d, 0x88, 0x0e, 0x19, 0x87, 0x4e, 0x0b, 0xa9, 0x0c, 0x79, 0x11,
    0x7f, 0x22, 0xe7, 0x59, 0xe1, 0xda, 0x3d, 0xc8, 0x12, 0x04, 0x74, 0x54, 0x30, 0x7e, 0xb4, 0x28,
    0x55, 0x68, 0x50, 0xbe, 0xd0, 0xc4, 0x31, 0xcb, 0x2a, 0xad, 0x0f, 0xca, 0x70, 0xff, 0x32, 0x69,
    0x08, 0x62, 0x00, 0x24, 0xd1, 0xfb, 0xba, 0xed, 0x45, 0x81, 0x73, 0x6d, 0x84, 0x9f, 0xee, 0x4a,
    0xc3, 0x2e, 0xc1, 0x01, 0xe6, 0x25, 0x48, 0x99, 0xb9, 0xb3, 0x7b, 0xf9, 0xce, 0xbf, 0xdf, 0x71,
    0x29, 0xcd, 0x6c, 0x13, 0x64, 0x9b, 0x63, 0x9d, 0xc0, 0x4b, 0xb7, 0xa5, 0x89, 0x5f, 0xb1, 0x17,
    0xf4, 0xbc, 0xd3, 0x46, 0xcf, 0x37, 0x5e, 0x47, 0x94, 0xfa, 0xfc, 0x5b, 0x97, 0xfe, 0x5a, 0xac,
    0x3c, 0x4c, 0x03, 0x35, 0xf3, 0x23, 0xb8, 0x5d, 0x6a, 0x92, 0xd5, 0x21, 0x44, 0x51, 0xc6, 0x7d,
    0x39, 0x83, 0xdc, 0xaa, 0x7c, 0x77, 0x56, 0x05, 0x1b, 0xa4, 0x15, 0x34, 0x1e, 0x1c, 0xf8, 0x52,
    0x20, 0x14, 0xe9, 0xbd, 0xdd, 0xe4, 0xa1, 0xe0, 0x8a, 0xf1, 0xd6, 0x7a, 0xbb, 0xe3, 0x40, 0x4f
};

static const came_byte_t camei_S4[256] = {
    0x70, 0x2c, 0xb3, 0xc0, 0xe4, 0x57, 0xea, 0xae, 0x23, 0x6b, 0x45, 0xa5, 0xed, 0x4f, 0x1d, 0x92,
    0x86, 0xaf, 0x7c, 0x1f, 0x3e, 0xdc, 0x5e, 0x0b, 0xa6, 0x39, 0xd5, 0x5d, 0xd9, 0x5a, 0x51, 0x6c,
    0x8b, 0x9a, 0xfb, 0xb0, 0x74, 0x2b, 0xf0, 0x84, 0xdf, 0xcb, 0x34, 0x76, 0x6d, 0xa9, 0xd1, 0x04,
    0x14, 0x3a, 0xde, 0x11, 0x32, 0x9c, 0x53, 0xf2, 0xfe, 0xcf, 0xc3, 0x7a, 0x24, 0xe8, 0x60, 0x69,
    0xaa, 0xa0, 0xa1, 0x62, 0x54, 0x1e, 0xe0, 0x64, 0x10, 0x00, 0xa3, 0x75, 0x8a, 0xe6, 0x09, 0xdd,
    0x87, 0x83, 0xcd, 0x90, 0x73, 0xf6, 0x9d, 0xbf, 0x52, 0xd8, 0xc8, 0xc6, 0x81, 0x6f, 0x13, 0x63,
    0xe9, 0xa7, 0x9f, 0xbc, 0x29, 0xf9, 0x2f, 0xb4, 0x78, 0x06, 0xe7, 0x71, 0xd4, 0xab, 0x88, 0x8d,
    0x72, 0xb9, 0xf8, 0xac, 0x36, 0x2a, 0x3c, 0xf1, 0x40, 0xd3, 0xbb, 0x43, 0x15, 0xad, 0x77, 0x80,
    0x82, 0xec, 0x27, 0xe5, 0x85, 0x35, 0x0c, 0x41, 0xef, 0x93, 0x19, 0x21, 0x0e, 0x4e, 0x65, 0xbd,
    0xb8, 0x8f, 0xeb, 0xce, 0x30, 0x5f, 0xc5, 0x1a, 0xe1, 0xca, 0x47, 0x3d, 0x01, 0xd6, 0x56, 0x4d,
    0x0d, 0x66, 0xcc, 0x2d, 0x12, 0x20, 0xb1, 0x99, 0x4c, 0xc2, 0x7e, 0x05, 0xb7, 0x31, 0x17, 0xd7,
    0x58, 0x61, 0x1b, 0x1c, 0x0f, 0x16, 0x18, 0x22, 0x44, 0xb2, 0xb5, 0x91, 0x08, 0xa8, 0xfc, 0x50,
    0xd0, 0x7d, 0x89, 0x97, 0x5b, 0x95, 0xff, 0xd2, 0xc4, 0x48, 0xf7, 0xdb, 0x03, 0xda, 0x3f, 0x94,
    0x5c, 0x02, 0x4a, 0x33, 0x67, 0xf3, 0x7f, 0xe2, 0x9b, 0x26, 0x37, 0x3b, 0x96, 0x4b, 0xbe, 0x2e,
    0x79, 0x8c, 0x6e, 0x8e, 0xf5, 0xb6, 0xfd, 0x59, 0x98, 0x6a, 0x46, 0xba, 0x25, 0x42, 0xa2, 0xfa,
    0x07, 0x55, 0xee, 0x0a, 0x49, 0x68, 0x38, 0xa4, 0x28, 0x7b, 0xc9, 0xc1, 0xe3, 0xf4, 0xc7, 0x9e
};

BLKCPHR_U64_WARN_BEGIN
static const came_word_t camei_sigma[6] = {
    0xa09e667f3bcc908b, 0xb67ae8584caa73b2,
    0xc6ef372fe94f82be, 0x54ff53a5f1d36f1c,
    0x10e527fade682d1d, 0xb05688c2b3e6c1fd
};
BLKCPHR_U64_WARN_END