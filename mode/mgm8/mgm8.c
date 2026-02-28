#include "mgm8.h"
#include <string.h>
#include "config.h"

typedef blkcphr_u8_t  mgm8_byte_t;
typedef blkcphr_u32_t mgm8_half_t;
typedef blkcphr_u64_t mgm8_word_t;

typedef mgm8_byte_t mgm8_block_t[8];

static struct {
    void (*enc)(void*, const void*);
    size_t (*rdfn)(      void*, size_t, size_t, void*); void* rud;
    size_t (*wrfn)(const void*, size_t, size_t, void*); void* wud;
    mgm8_byte_t init_vector[MGM8_INIT_VEC_BYTE];
    mgm8_byte_t auth_tag   [MGM8_AUTH_TAG_BYTE];
    const void* auth_data;
    size_t auth_data_sz;
} mgm8i_ctx;

int mgm8_set_reader(size_t (*rd)(void*, size_t, size_t, void*), void* ud) {
    if (!rd) return 1;
    mgm8i_ctx.rdfn = rd;
    mgm8i_ctx.rud  = ud;
    return 0;
}

int mgm8_set_writer(size_t (*wr)(const void*, size_t, size_t, void*), void* ud) {
    if (!wr) return 1;
    mgm8i_ctx.wrfn = wr;
    mgm8i_ctx.wud  = ud;
    return 0;
}

int mgm8_set_auth_data(const void* data, size_t size) {
    if (!data && size > 0) return 1;
    mgm8i_ctx.auth_data    = data;
    mgm8i_ctx.auth_data_sz = size;
    return 0;
}

int mgm8_set_init_vector(const void* data) {
    if (!data) return 1;
    memcpy(mgm8i_ctx.init_vector, data,
        sizeof mgm8i_ctx.init_vector);
    return 0;
}

int mgm8_set_auth_tag(const void* src) {
    if (!src) return 1;
    memcpy(mgm8i_ctx.auth_tag, src,
        sizeof mgm8i_ctx.auth_tag);
    return 0;
}

int mgm8_get_auth_tag(void* dst) {
    if (!dst) return 1;
    memcpy(dst, mgm8i_ctx.auth_tag,
        sizeof mgm8i_ctx.auth_tag);
    return 0;
}

int mgm8_set_encode_func(void (*enc)(void*, const void*)) {
    if (enc) mgm8i_ctx.enc = enc;
    return !enc;
}

static void mgm8i_gfmul(mgm8_block_t out, const mgm8_block_t lhs, const mgm8_block_t rhs) {
    mgm8_word_t L, R, T = 0; int i, msb;

    memcpy(&L, lhs, sizeof L);
    memcpy(&R, rhs, sizeof R);
#if BLKCPHR_IS_LITTLE
    L = blkcphr_bswap64(L);
    R = blkcphr_bswap64(R);
#endif

    for (i = 0; i < 64; i++) {
        if (R & 1) T ^= L;
        R >>= 1;

        msb = L >> 63; L <<= 1;
        /* x^64 + x^4 + x^3 + x + 1 */
        if (msb) L ^= 0x1b;
    }

#if BLKCPHR_IS_LITTLE
    T = blkcphr_bswap64(T);
#endif
    memcpy(out, &T, sizeof T);
}

static void mgm8i_xor(mgm8_block_t out, const mgm8_block_t arg) {
    /* */ mgm8_word_t* O = (/* */ void*)out;
    const mgm8_word_t* A = (const void*)arg;
    *O ^= *A;
}

static void mgm8i_incl(mgm8_block_t block) {
    mgm8_half_t* B = (void*)block;
#if BLKCPHR_IS_LITTLE
    B[0] = blkcphr_bswap32(B[0]);
#endif
    ++B[0];
#if BLKCPHR_IS_LITTLE
    B[0] = blkcphr_bswap32(B[0]);
#endif
}

static void mgm8i_incr(mgm8_block_t block) {
    mgm8_half_t* B = (void*)block;
#if BLKCPHR_IS_LITTLE
    B[1] = blkcphr_bswap32(B[1]);
#endif
    ++B[1];
#if BLKCPHR_IS_LITTLE
    B[1] = blkcphr_bswap32(B[1]);
#endif
}

static void mgm8i_set_lens(mgm8_block_t out, mgm8_half_t lenA, mgm8_half_t lenC) {
    lenA *= 8; lenC *= 8;
#if BLKCPHR_IS_LITTLE
    lenA = blkcphr_bswap32(lenA);
    lenC = blkcphr_bswap32(lenC);
#endif
    memcpy(out + 0, &lenA, sizeof lenA);
    memcpy(out + 4, &lenC, sizeof lenC);
}

int mgm8_encryption(void) {
    mgm8_block_t A, C, T;
    mgm8_block_t Y, Z, H, S;
    size_t got, cipher_size = 0;

    const mgm8_byte_t* auth = mgm8i_ctx.auth_data;
    size_t             size = mgm8i_ctx.auth_data_sz;

    memset(S, 0, sizeof S);
    memcpy(Y, mgm8i_ctx.init_vector, sizeof Y); Y[0] &= 0x7F;
    memcpy(Z, mgm8i_ctx.init_vector, sizeof Z); Z[0] |= 0x80;
    mgm8i_ctx.enc(Y, Y);
    mgm8i_ctx.enc(Z, Z);

    while (size > 0) {
        got = size > 8 ? 8 : size;
        memset(A, 0, sizeof A);
        memcpy(A, auth, got);
        auth += got;
        size -= got;

        mgm8i_ctx.enc(H, Z);
        mgm8i_incl(Z);
        mgm8i_gfmul(T, A, H);
        mgm8i_xor(S, T);
    }

    while (1) {
        memset(C, 0, sizeof C);
        got = mgm8i_ctx.rdfn(C, 1, sizeof C, mgm8i_ctx.rud);
        if (got == 0) break;
        cipher_size += got;

        mgm8i_ctx.enc(H, Y);
        mgm8i_incr(Y);
        mgm8i_xor(C, H);

        memset(C + got, 0, sizeof C - got);
        mgm8i_ctx.enc(H, Z);
        mgm8i_incl(Z);
        mgm8i_gfmul(T, C, H);
        mgm8i_xor(S, T);

        if (mgm8i_ctx.wrfn(C, 1, got, mgm8i_ctx.wud) != got)
            return 1;
    }

    mgm8i_ctx.enc(H, Z);
    mgm8i_set_lens(C, mgm8i_ctx.auth_data_sz, cipher_size);
    mgm8i_gfmul(T, C, H);
    mgm8i_xor(S, T);
    mgm8i_ctx.enc(mgm8i_ctx.auth_tag, S);

    return 0;
}

int mgm8_decryption(void) {
    mgm8_block_t A, C, T;
    mgm8_block_t Y, Z, H, S;
    size_t got, cipher_size = 0;

    const mgm8_byte_t* auth = mgm8i_ctx.auth_data;
    size_t             size = mgm8i_ctx.auth_data_sz;

    memset(S, 0, sizeof S);
    memcpy(Y, mgm8i_ctx.init_vector, sizeof Y); Y[0] &= 0x7F;
    memcpy(Z, mgm8i_ctx.init_vector, sizeof Z); Z[0] |= 0x80;
    mgm8i_ctx.enc(Y, Y);
    mgm8i_ctx.enc(Z, Z);

    while (size > 0) {
        got = size > 8 ? 8 : size;
        memset(A, 0, sizeof A);
        memcpy(A, auth, got);
        auth += got;
        size -= got;

        mgm8i_ctx.enc(H, Z);
        mgm8i_incl(Z);
        mgm8i_gfmul(T, A, H);
        mgm8i_xor(S, T);
    }

    while (1) {
        memset(C, 0, sizeof C);
        got = mgm8i_ctx.rdfn(C, 1, sizeof C, mgm8i_ctx.rud);
        if (got == 0) break;
        cipher_size += got;

        mgm8i_ctx.enc(H, Z);
        mgm8i_incl(Z);
        mgm8i_gfmul(T, C, H);
        mgm8i_xor(S, T);

        mgm8i_ctx.enc(H, Y);
        mgm8i_incr(Y);
        mgm8i_xor(C, H);

        if (mgm8i_ctx.wrfn(C, 1, got, mgm8i_ctx.wud) != got)
            return 1;
    }

    mgm8i_ctx.enc(H, Z);
    mgm8i_set_lens(C, mgm8i_ctx.auth_data_sz, cipher_size);
    mgm8i_gfmul(T, C, H);
    mgm8i_xor(S, T);
    mgm8i_ctx.enc(T, S);

    return memcmp(T, mgm8i_ctx.auth_tag, sizeof T) != 0;
}