#include "mgm16.h"
#include <string.h>
#include "config.h"

typedef blkcphr_u8_t  mgm16_byte_t;
typedef blkcphr_u64_t mgm16_word_t;

typedef mgm16_byte_t mgm16_block_t[16];

static struct {
    void (*enc)(void*, const void*);
    size_t (*rdfn)(      void*, size_t, size_t, void*); void* rud;
    size_t (*wrfn)(const void*, size_t, size_t, void*); void* wud;
    mgm16_byte_t init_vector[MGM16_INIT_VEC_BYTE];
    mgm16_byte_t auth_tag   [MGM16_AUTH_TAG_BYTE];
    const void* auth_data;
    size_t auth_data_sz;
} mgm16i_ctx;

int mgm16_set_reader(size_t (*rd)(void*, size_t, size_t, void*), void* ud) {
    if (!rd) return 1;
    mgm16i_ctx.rdfn = rd;
    mgm16i_ctx.rud  = ud;
    return 0;
}

int mgm16_set_writer(size_t (*wr)(const void*, size_t, size_t, void*), void* ud) {
    if (!wr) return 1;
    mgm16i_ctx.wrfn = wr;
    mgm16i_ctx.wud  = ud;
    return 0;
}

int mgm16_set_auth_data(const void* data, size_t size) {
    if (!data && size > 0) return 1;
    mgm16i_ctx.auth_data    = data;
    mgm16i_ctx.auth_data_sz = size;
    return 0;
}

int mgm16_set_init_vector(const void* data) {
    if (!data) return 1;
    memcpy(mgm16i_ctx.init_vector, data,
        sizeof mgm16i_ctx.init_vector);
    return 0;
}

int mgm16_set_auth_tag(const void* src) {
    if (!src) return 1;
    memcpy(mgm16i_ctx.auth_tag, src,
        sizeof mgm16i_ctx.auth_tag);
    return 0;
}

int mgm16_get_auth_tag(void* dst) {
    if (!dst) return 1;
    memcpy(dst, mgm16i_ctx.auth_tag,
        sizeof mgm16i_ctx.auth_tag);
    return 0;
}

int mgm16_set_encode_func(void (*enc)(void*, const void*)) {
    if (enc) mgm16i_ctx.enc = enc;
    return !enc;
}

static void mgm16i_gfmul(mgm16_block_t out, const mgm16_block_t lhs, const mgm16_block_t rhs) {
    mgm16_word_t Llo, Lup, Rlo, Rup;
    mgm16_word_t Tlo = 0, Tup = 0;
    int i, msb;

    memcpy(&Lup, lhs, sizeof Lup); memcpy(&Llo, lhs + 8, sizeof Llo);
    memcpy(&Rup, rhs, sizeof Rup); memcpy(&Rlo, rhs + 8, sizeof Rlo);

#if BLKCPHR_IS_LITTLE
    Lup = blkcphr_bswap64(Lup); Llo = blkcphr_bswap64(Llo);
    Rup = blkcphr_bswap64(Rup); Rlo = blkcphr_bswap64(Rlo);
#endif

    for (i = 0; i < 128; i++) {
        if (Rlo & 1)
            Tup ^= Lup, Tlo ^= Llo;

        Rlo = Rlo >> 1 | Rup << 63;
        Rup = Rup >> 1            ;

        msb =            Lup >> 63;
        Lup = Lup << 1 | Llo >> 63;
        Llo = Llo << 1            ;

        /* x^128 + x^7 + x^2 + x + 1 */
        if (msb) Llo ^= 0x87;
    }

#if BLKCPHR_IS_LITTLE
    Tup = blkcphr_bswap64(Tup);
    Tlo = blkcphr_bswap64(Tlo);
#endif

    memcpy(out + 0, &Tup, sizeof Tup);
    memcpy(out + 8, &Tlo, sizeof Tlo);
}

static void mgm16i_xor(mgm16_block_t out, const mgm16_block_t arg) {
    /* */ mgm16_word_t* O = (/* */ void*)out;
    const mgm16_word_t* A = (const void*)arg;
    O[0] ^= A[0]; O[1] ^= A[1];
}

static void mgm16i_incl(mgm16_block_t block) {
    mgm16_word_t* B = (void*)block;
#if BLKCPHR_IS_LITTLE
    B[0] = blkcphr_bswap64(B[0]);
#endif
    ++B[0];
#if BLKCPHR_IS_LITTLE
    B[0] = blkcphr_bswap64(B[0]);
#endif
}

static void mgm16i_incr(mgm16_block_t block) {
    mgm16_word_t* B = (void*)block;
#if BLKCPHR_IS_LITTLE
    B[1] = blkcphr_bswap64(B[1]);
#endif
    ++B[1];
#if BLKCPHR_IS_LITTLE
    B[1] = blkcphr_bswap64(B[1]);
#endif
}

static void mgm16i_set_lens(mgm16_block_t out, mgm16_word_t lenA, mgm16_word_t lenC) {
    lenA *= 8; lenC *= 8;
#if BLKCPHR_IS_LITTLE
    lenA = blkcphr_bswap64(lenA);
    lenC = blkcphr_bswap64(lenC);
#endif
    memcpy(out + 0, &lenA, sizeof lenA);
    memcpy(out + 8, &lenC, sizeof lenC);
}

int mgm16_encryption(void) {
    mgm16_block_t A, C, T;
    mgm16_block_t Y, Z, H, S;
    size_t got, cipher_size = 0;

    const mgm16_byte_t* auth = mgm16i_ctx.auth_data;
    size_t              size = mgm16i_ctx.auth_data_sz;

    memset(S, 0, sizeof S);
    memcpy(Y, mgm16i_ctx.init_vector, sizeof Y); Y[0] &= 0x7F;
    memcpy(Z, mgm16i_ctx.init_vector, sizeof Z); Z[0] |= 0x80;
    mgm16i_ctx.enc(Y, Y);
    mgm16i_ctx.enc(Z, Z);

    while (size > 0) {
        got = size > 16 ? 16 : size;
        memset(A, 0, sizeof A);
        memcpy(A, auth, got);
        auth += got;
        size -= got;

        mgm16i_ctx.enc(H, Z);
        mgm16i_incl(Z);
        mgm16i_gfmul(T, A, H);
        mgm16i_xor(S, T);
    }

    while (1) {
        memset(C, 0, sizeof C);
        got = mgm16i_ctx.rdfn(C, 1, sizeof C, mgm16i_ctx.rud);
        if (got == 0) break;
        cipher_size += got;

        mgm16i_ctx.enc(H, Y);
        mgm16i_incr(Y);
        mgm16i_xor(C, H);

        memset(C + got, 0, sizeof C - got);
        mgm16i_ctx.enc(H, Z);
        mgm16i_incl(Z);
        mgm16i_gfmul(T, C, H);
        mgm16i_xor(S, T);

        if (mgm16i_ctx.wrfn(C, 1, got, mgm16i_ctx.wud) != got)
            return 1;
    }

    mgm16i_ctx.enc(H, Z);
    mgm16i_set_lens(C, mgm16i_ctx.auth_data_sz, cipher_size);
    mgm16i_gfmul(T, C, H);
    mgm16i_xor(S, T);
    mgm16i_ctx.enc(mgm16i_ctx.auth_tag, S);

    return 0;
}

int mgm16_decryption(void) {
    mgm16_block_t A, C, T;
    mgm16_block_t Y, Z, H, S;
    size_t got, cipher_size = 0;

    const mgm16_byte_t* auth = mgm16i_ctx.auth_data;
    size_t              size = mgm16i_ctx.auth_data_sz;

    memset(S, 0, sizeof S);
    memcpy(Y, mgm16i_ctx.init_vector, sizeof Y); Y[0] &= 0x7F;
    memcpy(Z, mgm16i_ctx.init_vector, sizeof Z); Z[0] |= 0x80;
    mgm16i_ctx.enc(Y, Y);
    mgm16i_ctx.enc(Z, Z);

    while (size > 0) {
        got = size > 16 ? 16 : size;
        memset(A, 0, sizeof A);
        memcpy(A, auth, got);
        auth += got;
        size -= got;

        mgm16i_ctx.enc(H, Z);
        mgm16i_incl(Z);
        mgm16i_gfmul(T, A, H);
        mgm16i_xor(S, T);
    }

    while (1) {
        memset(C, 0, sizeof C);
        got = mgm16i_ctx.rdfn(C, 1, sizeof C, mgm16i_ctx.rud);
        if (got == 0) break;
        cipher_size += got;

        mgm16i_ctx.enc(H, Z);
        mgm16i_incl(Z);
        mgm16i_gfmul(T, C, H);
        mgm16i_xor(S, T);

        mgm16i_ctx.enc(H, Y);
        mgm16i_incr(Y);
        mgm16i_xor(C, H);

        if (mgm16i_ctx.wrfn(C, 1, got, mgm16i_ctx.wud) != got)
            return 1;
    }

    mgm16i_ctx.enc(H, Z);
    mgm16i_set_lens(C, mgm16i_ctx.auth_data_sz, cipher_size);
    mgm16i_gfmul(T, C, H);
    mgm16i_xor(S, T);
    mgm16i_ctx.enc(T, S);

    return memcmp(T, mgm16i_ctx.auth_tag, sizeof T) != 0;
}