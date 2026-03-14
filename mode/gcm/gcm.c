#include "gcm.h"
#include <string.h>
#include "config.h"

typedef blkcphr_u8_t  gcm_byte_t;
typedef blkcphr_u64_t gcm_word_t;

typedef gcm_byte_t gcm_block_t[16];

static struct {
    void (*enc)(void*, const void*);
    size_t (*rdfn)(      void*, size_t, size_t, void*); void* rud;
    size_t (*wrfn)(const void*, size_t, size_t, void*); void* wud;
    gcm_byte_t auth_tag   [GCM_AUTH_TAG_BYTE];
    gcm_byte_t init_vector[GCM_INIT_VEC_BYTE];
    const void* auth_data;
    size_t auth_data_sz;
} gcmi_ctx;

int gcm_set_reader(size_t (*rd)(void*, size_t, size_t, void*), void* ud) {
    if (!rd) return 1;
    gcmi_ctx.rdfn = rd;
    gcmi_ctx.rud  = ud;
    return 0;
}

int gcm_set_writer(size_t (*wr)(const void*, size_t, size_t, void*), void* ud) {
    if (!wr) return 1;
    gcmi_ctx.wrfn = wr;
    gcmi_ctx.wud  = ud;
    return 0;
}

int gcm_set_auth_data(const void* data, size_t size) {
    if (!data && size > 0) return 1;
    gcmi_ctx.auth_data    = data;
    gcmi_ctx.auth_data_sz = size;
    return 0;
}

int gcm_set_init_vector(const void* data) {
    if (!data) return 1;
    memcpy(gcmi_ctx.init_vector, data,
        sizeof gcmi_ctx.init_vector);
    return 0;
}

int gcm_set_auth_tag(const void* src) {
    if (!src) return 1;
    memcpy(gcmi_ctx.auth_tag, src,
        sizeof gcmi_ctx.auth_tag);
    return 0;
}

int gcm_get_auth_tag(void* dst) {
    if (!dst) return 1;
    memcpy(dst, gcmi_ctx.auth_tag,
        sizeof gcmi_ctx.auth_tag);
    return 0;
}

int gcm_set_encode_func(void (*enc)(void*, const void*)) {
    if (enc) gcmi_ctx.enc = enc;
    return !enc;
}

static void gcmi_gfmul(gcm_block_t out, const gcm_block_t arg) {
    gcm_word_t Llo, Lup, Rlo, Rup;
    gcm_word_t Tlo = 0, Tup = 0;
    int i, bit;

    memcpy(&Lup, out, sizeof Lup); memcpy(&Llo, out + 8, sizeof Llo);
    memcpy(&Rup, arg, sizeof Rup); memcpy(&Rlo, arg + 8, sizeof Rlo);
    BLKCPHR_IF_LITTLE(BLKCPHR_BSWAP_64_PAIR(Lup, Llo));
    BLKCPHR_IF_LITTLE(BLKCPHR_BSWAP_64_PAIR(Rup, Rlo));

    for (i = 0; i < 128; i++) {
        bit =            Lup >> 63;
        Lup = Lup << 1 | Llo >> 63;
        Llo = Llo << 1            ;

        if (bit) Tup ^= Rup, Tlo ^= Rlo;

        bit =       0 != Rlo << 63;
        Rlo = Rlo >> 1 | Rup << 63;
        Rup = Rup >> 1            ;

        /* x^128 + x^7 + x^2 + x + 1 */
        BLKCPHR_U64_WARN_BEGIN
        if (bit) Rup ^= 0xe100000000000000;
        BLKCPHR_U64_WARN_END
    }

    BLKCPHR_IF_LITTLE(BLKCPHR_BSWAP_64_PAIR(Tup, Tlo));
    memcpy(out + 0, &Tup, sizeof Tup);
    memcpy(out + 8, &Tlo, sizeof Tlo);
}

static void gcmi_xor(gcm_block_t out, const gcm_block_t arg) {
    /* */ gcm_word_t* O = (/* */ void*)out;
    const gcm_word_t* A = (const void*)arg;
    O[0] ^= A[0]; O[1] ^= A[1];
}

static void gcmi_inc(gcm_block_t block) {
    blkcphr_u32_t* B = (void*)block;
    BLKCPHR_IF_LITTLE(BLKCPHR_BSWAP_32_ONE(B[3]));
    ++B[3];
    BLKCPHR_IF_LITTLE(BLKCPHR_BSWAP_32_ONE(B[3]));
}

static void gcmi_set_lens(gcm_block_t out, gcm_word_t lenA, gcm_word_t lenC) {
    lenA *= 8; lenC *= 8;
    BLKCPHR_IF_LITTLE(BLKCPHR_BSWAP_64_PAIR(lenA, lenC));
    memcpy(out + 0, &lenA, sizeof lenA);
    memcpy(out + 8, &lenC, sizeof lenC);
}

int gcm_encryption(void) {
    gcm_block_t A, C, T;
    gcm_block_t Y, H, X;
    size_t got, cipher_size = 0;

    const gcm_byte_t* auth = gcmi_ctx.auth_data;
    size_t            size = gcmi_ctx.auth_data_sz;

    memset(T, 0, sizeof T);
    memset(H, 0, sizeof H);
    memset(Y, 0, sizeof Y);

    gcmi_ctx.enc(H, H);
    memcpy(Y, gcmi_ctx.init_vector, sizeof gcmi_ctx.init_vector); Y[15] = 1;

    while (size > 0) {
        got = size > 16 ? 16 : size;
        memset(A, 0, sizeof A);
        memcpy(A, auth, got);
        auth += got;
        size -= got;

        gcmi_xor(T, A);
        gcmi_gfmul(T, H);
    }

    while (1) {
        got = gcmi_ctx.rdfn(C, 1, sizeof C, gcmi_ctx.rud);
        if (got == 0) break;
        cipher_size += got;

        gcmi_inc(Y);
        gcmi_ctx.enc(X, Y);
        gcmi_xor(C, X);

        memset(C + got, 0, sizeof C - got);
        gcmi_xor(T, C);
        gcmi_gfmul(T, H);

        if (gcmi_ctx.wrfn(C, 1, got, gcmi_ctx.wud) != got)
            return 1;
    }

    gcmi_set_lens(C, gcmi_ctx.auth_data_sz, cipher_size);
    gcmi_xor(T, C);
    gcmi_gfmul(T, H);

    memset(Y + 12, 0, 4); Y[15] = 1;
    gcmi_ctx.enc(gcmi_ctx.auth_tag, Y);
    gcmi_xor(gcmi_ctx.auth_tag, T);

    return 0;
}

int gcm_decryption(void) {
    gcm_block_t A, C, T;
    gcm_block_t Y, H, X;
    size_t got, cipher_size = 0;

    const gcm_byte_t* auth = gcmi_ctx.auth_data;
    size_t            size = gcmi_ctx.auth_data_sz;

    memset(T, 0, sizeof T);
    memset(H, 0, sizeof H);
    memset(Y, 0, sizeof Y);

    gcmi_ctx.enc(H, H); Y[15] = 1;
    memcpy(Y, gcmi_ctx.init_vector, sizeof gcmi_ctx.init_vector);

    while (size > 0) {
        got = size > 16 ? 16 : size;
        memset(A, 0, sizeof A);
        memcpy(A, auth, got);
        auth += got;
        size -= got;

        gcmi_xor(T, A);
        gcmi_gfmul(T, H);
    }

    while (1) {
        memset(C, 0, sizeof C);
        got = gcmi_ctx.rdfn(C, 1, sizeof C, gcmi_ctx.rud);
        if (got == 0) break;
        cipher_size += got;

        gcmi_xor(T, C);
        gcmi_gfmul(T, H);

        gcmi_inc(Y);
        gcmi_ctx.enc(X, Y);
        gcmi_xor(C, X);

        if (gcmi_ctx.wrfn(C, 1, got, gcmi_ctx.wud) != got)
            return 1;
    }

    gcmi_set_lens(C, gcmi_ctx.auth_data_sz, cipher_size);
    gcmi_xor(T, C);
    gcmi_gfmul(T, H);

    memset(Y + 12, 0, 4); Y[15] = 1;
    gcmi_ctx.enc(X, Y);
    gcmi_xor(T, X);

    return memcmp(T, gcmi_ctx.auth_tag, sizeof T) != 0;
}