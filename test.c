#include <stdio.h>
#include <string.h>

#include "kuznyechik/kuznyechik.h"
#include "blowfish/blowfish.h"
#include "camellia/camellia.h"
#include "cast128/cast128.h"
#include "cast256/cast256.h"
#include "clefia/clefia.h"
#include "khazad/khazad.h"
#include "magma/magma.h"
#include "rtea/rtea.h"
#include "aes/aes.h"
#include "lea/lea.h"
#include "rc5/rc5.h"
#include "rc6/rc6.h"
#include "tea/tea.h"

#include "mgm16/mgm16.h"
#include "mgm8/mgm8.h"

/* use ANSI coloring */
#if 1
#  define OK   "\x1b[32mOK\x1b[0m"
#  define FAIL "\x1b[31mFAIL\x1b[0m"
#else
#  define OK   "OK"
#  define FAIL "FAIL"
#endif

#define cipher_test_case(name, blocksz, keysz, key, plain, cipher) \
do {                                                  \
    unsigned char P[blocksz], C[blocksz]; int i;      \
                                                      \
    printf("- Set key with %3i bits ... ", keysz);    \
    puts(name##_init(key, keysz) == 0 ? OK : FAIL);   \
                                                      \
    printf("- Check X = D(E(X))     ... ");           \
    memcpy(P, plain, blocksz);                        \
    name##_block_encode(C, P);                        \
    name##_block_decode(P, C);                        \
    puts(memcmp(P, plain, blocksz) == 0 ? OK : FAIL); \
                                                      \
    printf("- Check X = E(D(X))     ... ");           \
    memcpy(P, plain, blocksz);                        \
    name##_block_decode(C, P);                        \
    name##_block_encode(P, C);                        \
    puts(memcmp(P, plain, blocksz) == 0 ? OK : FAIL); \
                                                      \
    printf("- Check test vector     ... ");           \
    memcpy(P, plain, blocksz);                        \
    name##_block_encode(C, P);                        \
    if (memcmp(C, cipher, blocksz) == 0) puts(OK);    \
    else {                                            \
        puts(FAIL);                                   \
        printf("  > expected: ");                     \
        for (i = 0; i < blocksz; i++)                 \
            printf("%02x", cipher[i] & 0xFF);         \
        putchar('\n');                                \
        printf("  > received: ");                     \
        for (i = 0; i < blocksz; i++)                 \
            printf("%02x", C[i]);                     \
        putchar('\n');                                \
    }                                                 \
} while (0)

void cipher_test(void) {
    /* -------------------------------------------------------------------------------- */

    puts("Testing Advanced Encryption Standard (AES):");
    cipher_test_case(
        aes, AES_BLOCK_BYTE, 128,
        /* K */ "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
        /* P */ "\x32\x43\xf6\xa8\x88\x5a\x30\x8d\x31\x31\x98\xa2\xe0\x37\x07\x34",
        /* C */ "\x39\x25\x84\x1d\x02\xdc\x09\xfb\xdc\x11\x85\x97\x19\x6a\x0b\x32"
    );
    cipher_test_case(
        aes, AES_BLOCK_BYTE, 192,
        /* K */ "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5"
                "\x62\xf8\xea\xd2\x52\x2c\x6b\x7b",
        /* P */ "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a",
        /* C */ "\xbd\x33\x4f\x1d\x6e\x45\xf2\x5f\xf7\x12\xa2\x14\x57\x1f\xa5\xcc"
    );
    cipher_test_case(
        aes, AES_BLOCK_BYTE, 256,
        /* K */ "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
                "\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4",
        /* P */ "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a",
        /* C */ "\xf3\xee\xd1\xbd\xb5\xd2\xa0\x3c\x06\x4b\x5a\x7e\x3d\xb1\x81\xf8"
    );
    putchar('\n');

    /* -------------------------------------------------------------------------------- */

    puts("Testing Blowfish:");
    cipher_test_case(
        blowfish, BLOWFISH_BLOCK_BYTE, 64,
        /* K */ "\xfe\xdc\xba\x98\x76\x54\x32\x10",
        /* P */ "\x01\x23\x45\x67\x89\xab\xcd\xef",
        /* C */ "\x0a\xce\xab\x0f\xc6\xa0\xa2\x8d"
    );
    cipher_test_case(
        blowfish, BLOWFISH_BLOCK_BYTE, 64,
        /* K */ "\x01\x70\xf1\x75\x46\x8f\xb5\xe6",
        /* P */ "\x07\x56\xd8\xe0\x77\x47\x61\xd2",
        /* C */ "\x43\x21\x93\xb7\x89\x51\xfc\x98"
    );
    cipher_test_case(
        blowfish, BLOWFISH_BLOCK_BYTE, 128,
        /* K */ "\xf0\xe1\xd2\xc3\xb4\xa5\x96\x87\x78\x69\x5a\x4b\x3c\x2d\x1e\x0f",
        /* P */ "\xfe\xdc\xba\x98\x76\x54\x32\x10",
        /* C */ "\x93\x14\x28\x87\xee\x3b\xe1\x5c"
    );
    cipher_test_case(
        blowfish, BLOWFISH_BLOCK_BYTE, 160,
        /* K */ "\xf0\xe1\xd2\xc3\xb4\xa5\x96\x87\x78\x69\x5a\x4b\x3c\x2d\x1e\x0f"
                "\x00\x11\x22\x33",
        /* P */ "\xfe\xdc\xba\x98\x76\x54\x32\x10",
        /* C */ "\x10\x85\x1c\x0e\x38\x58\xda\x9f"
    );
    cipher_test_case(
        blowfish, BLOWFISH_BLOCK_BYTE, 192,
        /* K */ "\xf0\xe1\xd2\xc3\xb4\xa5\x96\x87\x78\x69\x5a\x4b\x3c\x2d\x1e\x0f"
                "\x00\x11\x22\x33\x44\x55\x66\x77",
        /* P */ "\xfe\xdc\xba\x98\x76\x54\x32\x10",
        /* C */ "\x05\x04\x4b\x62\xfa\x52\xd0\x80"
    );
    putchar('\n');

    /* -------------------------------------------------------------------------------- */

    puts("Testing CLEFIA:");
    cipher_test_case(
        clefia, CLEFIA_BLOCK_BYTE, 128,
        /* K */ "\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00",
        /* P */ "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
        /* C */ "\xde\x2b\xf2\xfd\x9b\x74\xaa\xcd\xf1\x29\x85\x55\x45\x94\x94\xfd"
    );
    cipher_test_case(
        clefia, CLEFIA_BLOCK_BYTE, 192,
        /* K */ "\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00"
                "\xf0\xe0\xd0\xc0\xb0\xa0\x90\x80",
        /* P */ "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
        /* C */ "\xe2\x48\x2f\x64\x9f\x02\x8d\xc4\x80\xdd\xa1\x84\xfd\xe1\x81\xad"
    );
    cipher_test_case(
        clefia, CLEFIA_BLOCK_BYTE, 256,
        /* K */ "\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00"
                "\xf0\xe0\xd0\xc0\xb0\xa0\x90\x80\x70\x60\x50\x40\x30\x20\x10\x00",
        /* P */ "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
        /* C */ "\xa1\x39\x78\x14\x28\x9d\xe8\x0c\x10\xda\x46\xd1\xfa\x48\xb3\x8a"
    );
    putchar('\n');

    /* -------------------------------------------------------------------------------- */

    puts("Testing KHAZAD:");
    cipher_test_case(
        khazad, KHAZAD_BLOCK_BYTE, 128,
        /* K */ "\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        /* P */ "\x00\x00\x00\x00\x00\x00\x00\x00",
        /* C */ "\x49\xa4\xce\x32\xac\x19\x0e\x3f"
    );
    cipher_test_case(
        khazad, KHAZAD_BLOCK_BYTE, 128,
        /* K */ "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        /* P */ "\x00\x00\x00\x20\x00\x00\x00\x00",
        /* C */ "\x3b\x89\x88\x9c\xe8\x06\xc5\x63"
    );
    cipher_test_case(
        khazad, KHAZAD_BLOCK_BYTE, 128,
        /* K */ "\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78",
        /* P */ "\x78\x78\x78\x78\x78\x78\x78\x78",
        /* C */ "\x23\x46\x21\x0d\x6a\x6c\xa0\xd1"
    );
    putchar('\n');

    /* -------------------------------------------------------------------------------- */

    puts("Testing Lightweight Encryption Algorithm (LEA):");
    cipher_test_case(
        lea, LEA_BLOCK_BYTE, 128,
        /* K */ "\x0f\x1e\x2d\x3c\x4b\x5a\x69\x78\x87\x96\xa5\xb4\xc3\xd2\xe1\xf0",
        /* P */ "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
        /* C */ "\x9f\xc8\x4e\x35\x28\xc6\xc6\x18\x55\x32\xc7\xa7\x04\x64\x8b\xfd"
    );
    cipher_test_case(
        lea, LEA_BLOCK_BYTE, 192,
        /* K */ "\x0f\x1e\x2d\x3c\x4b\x5a\x69\x78\x87\x96\xa5\xb4\xc3\xd2\xe1\xf0"
                "\xf0\xe1\xd2\xc3\xb4\xa5\x96\x87",
        /* P */ "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f",
        /* C */ "\x6f\xb9\x5e\x32\x5a\xad\x1b\x87\x8c\xdc\xf5\x35\x76\x74\xc6\xf2"
    );
    cipher_test_case(
        lea, LEA_BLOCK_BYTE, 256,
        /* K */ "\x0f\x1e\x2d\x3c\x4b\x5a\x69\x78\x87\x96\xa5\xb4\xc3\xd2\xe1\xf0"
                "\xf0\xe1\xd2\xc3\xb4\xa5\x96\x87\x78\x69\x5a\x4b\x3c\x2d\x1e\x0f",
        /* P */ "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f",
        /* C */ "\xd6\x51\xaf\xf6\x47\xb1\x89\xc1\x3a\x89\x00\xca\x27\xf9\xe1\x97"
    );
    putchar('\n');

    /* -------------------------------------------------------------------------------- */

    /* WARNIGN: I'm not find official test vectors,
     *          I use own result of encryption
     */
    puts("Testing Ruptor's TEA (RTEA):");
    cipher_test_case(
        rtea, RTEA_BLOCK_BYTE, 128,
        /* K */ "\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00",
        /* P */ "\x00\x01\x02\x03\x04\x05\x06\x07",
        /* C */ "\xf9\x34\xd2\x32\x10\x57\x83\x6b"
    );
    cipher_test_case(
        rtea, RTEA_BLOCK_BYTE, 256,
        /* K */ "\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00"
                "\xf0\xe0\xd0\xc0\xb0\xa0\x90\x80\x70\x60\x50\x40\x30\x20\x10\x00",
        /* P */ "\x00\x01\x02\x03\x04\x05\x06\x07",
        /* C */ "\xe4\xff\x5c\x41\x96\x9e\x10\xa8"
    );
    putchar('\n');

    /* -------------------------------------------------------------------------------- */

    puts("Testing Tiny Encryption Algorithm (TEA):");
    cipher_test_case(
        tea, TEA_BLOCK_BYTE, 128,
        /* K */ "\x33\x22\x11\x00\x77\x66\x55\x44\xbb\xaa\x99\x88\xff\xee\xdd\xcc",
        /* P */ "\x67\x45\x23\x01\xef\xcd\xab\x89",
        /* C */ "\x92\x6b\x6c\x12\x3e\x3a\x65\xc0"
    );
    putchar('\n');

    /* -------------------------------------------------------------------------------- */

    puts("Testing Kuznyechik:");
    cipher_test_case(
        kuznyechik, KUZNYECHIK_BLOCK_BYTE, 256,
        /* K */ "\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44\x55\x66\x77"
                "\xfe\xdc\xba\x98\x76\x54\x32\x10\x01\x23\x45\x67\x89\xab\xcd\xef",
        /* P */ "\x11\x22\x33\x44\x55\x66\x77\x00\xff\xee\xdd\xcc\xbb\xaa\x99\x88",
        /* C */ "\x7f\x67\x9d\x90\xbe\xbc\x24\x30\x5a\x46\x8d\x42\xb9\xd4\xed\xcd"
    );
    putchar('\n');

    /* -------------------------------------------------------------------------------- */

    puts("Testing Magma:");
    cipher_test_case(
        magma, MAGMA_BLOCK_BYTE, 256,
        /* K */ "\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00"
                "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
        /* P */ "\xfe\xdc\xba\x98\x76\x54\x32\x10",
        /* C */ "\x4e\xe9\x01\xe5\xc2\xd8\xca\x3d"
    );
    putchar('\n');

    /* -------------------------------------------------------------------------------- */

    puts("Testing Rivest's cipher 6 (RC6):");
    cipher_test_case(
        rc6, RC6_BLOCK_BYTE, 128,
        /* K */ "\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x12\x23\x34\x45\x56\x67\x78",
        /* P */ "\x02\x13\x24\x35\x46\x57\x68\x79\x8a\x9b\xac\xbd\xce\xdf\xe0\xf1",
        /* C */ "\x52\x4e\x19\x2f\x47\x15\xc6\x23\x1f\x51\xf6\x36\x7e\xa4\x3f\x18"
    );
    cipher_test_case(
        rc6, RC6_BLOCK_BYTE, 192,
        /* K */ "\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x12\x23\x34\x45\x56\x67\x78"
                "\x89\x9a\xab\xbc\xcd\xde\xef\xf0",
        /* P */ "\x02\x13\x24\x35\x46\x57\x68\x79\x8a\x9b\xac\xbd\xce\xdf\xe0\xf1",
        /* C */ "\x68\x83\x29\xd0\x19\xe5\x05\x04\x1e\x52\xe9\x2a\xf9\x52\x91\xd4"
    );
    cipher_test_case(
        rc6, RC6_BLOCK_BYTE, 256,
        /* K */ "\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x12\x23\x34\x45\x56\x67\x78"
                "\x89\x9a\xab\xbc\xcd\xde\xef\xf0\x10\x32\x54\x76\x98\xba\xdc\xfe",
        /* P */ "\x02\x13\x24\x35\x46\x57\x68\x79\x8a\x9b\xac\xbd\xce\xdf\xe0\xf1",
        /* C */ "\xc8\x24\x18\x16\xf0\xd7\xe4\x89\x20\xad\x16\xa1\x67\x4e\x5d\x48"
    );
    putchar('\n');

    /* -------------------------------------------------------------------------------- */

    puts("Testing Camellia:");
    cipher_test_case(
        camellia, CAMELLIA_BLOCK_BYTE, 128,
        /* K */ "\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10",
        /* P */ "\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10",
        /* C */ "\x67\x67\x31\x38\x54\x96\x69\x73\x08\x57\x06\x56\x48\xea\xbe\x43"
    );
    cipher_test_case(
        camellia, CAMELLIA_BLOCK_BYTE, 192,
        /* K */ "\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10"
                "\x00\x11\x22\x33\x44\x55\x66\x77",
        /* P */ "\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10",
        /* C */ "\xb4\x99\x34\x01\xb3\xe9\x96\xf8\x4e\xe5\xce\xe7\xd7\x9b\x09\xb9"
    );
    cipher_test_case(
        camellia, CAMELLIA_BLOCK_BYTE, 256,
        /* K */ "\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10"
                "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
        /* P */ "\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10",
        /* C */ "\x9a\xcc\x23\x7d\xff\x16\xd7\x6c\x20\xef\x7c\x91\x9e\x3a\x75\x09"
    );
    putchar('\n');

    /* -------------------------------------------------------------------------------- */

    puts("Testing Rivest's cipher 5 (RC5):");
    cipher_test_case(
        rc5, RC5_BLOCK_BYTE, 128,
        /* K */ "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
        /* P */ "\x00\x01\x02\x03\x04\x05\x06\x07",
        /* C */ "\x2a\x0e\xdc\x0e\x94\x31\xff\x73"
    );
    putchar('\n');

    /* -------------------------------------------------------------------------------- */

    puts("Testing CAST-128:");
    cipher_test_case(
        cast128, CAST128_BLOCK_BYTE, 128,
        /* K */ "\x01\x23\x45\x67\x12\x34\x56\x78\x23\x45\x67\x89\x34\x56\x78\x9a",
        /* P */ "\x01\x23\x45\x67\x89\xab\xcd\xef",
        /* C */ "\x23\x8b\x4f\xe5\x84\x7e\x44\xb2"
    );
    cipher_test_case(
        cast128, CAST128_BLOCK_BYTE, 80,
        /* K */ "\x01\x23\x45\x67\x12\x34\x56\x78\x23\x45",
        /* P */ "\x01\x23\x45\x67\x89\xab\xcd\xef",
        /* C */ "\xeb\x6a\x71\x1a\x2c\x02\x27\x1b"
    );
    cipher_test_case(
        cast128, CAST128_BLOCK_BYTE, 40,
        /* K */ "\x01\x23\x45\x67\x12",
        /* P */ "\x01\x23\x45\x67\x89\xab\xcd\xef",
        /* C */ "\x7a\xc8\x16\xd1\x6e\x9b\x30\x2e"
    );
    putchar('\n');

    /* -------------------------------------------------------------------------------- */

    puts("Testing CAST-256:");
    cipher_test_case(
        cast256, CAST256_BLOCK_BYTE, 128,
        /* K */ "\x23\x42\xbb\x9e\xfa\x38\x54\x2c\x0a\xf7\x56\x47\xf2\x9f\x61\x5d",
        /* P */ "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        /* C */ "\xc8\x42\xa0\x89\x72\xb4\x3d\x20\x83\x6c\x91\xd1\xb7\x53\x0f\x6b"
    );
    cipher_test_case(
        cast256, CAST256_BLOCK_BYTE, 192,
        /* K */ "\x23\x42\xbb\x9e\xfa\x38\x54\x2c\xbe\xd0\xac\x83\x94\x0a\xc2\x98"
                "\xba\xc7\x7a\x77\x17\x94\x28\x63",
        /* P */ "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        /* C */ "\x1b\x38\x6c\x02\x10\xdc\xad\xcb\xdd\x0e\x41\xaa\x08\xa7\xa7\xe8"
    );
    cipher_test_case(
        cast256, CAST256_BLOCK_BYTE, 256,
        /* K */ "\x23\x42\xbb\x9e\xfa\x38\x54\x2c\xbe\xd0\xac\x83\x94\x0a\xc2\x98"
                "\x8d\x7c\x47\xce\x26\x49\x08\x46\x1c\xc1\xb5\x13\x7a\xe6\xb6\x04",
        /* P */ "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        /* C */ "\x4f\x6a\x20\x38\x28\x68\x97\xb9\xc9\x87\x01\x36\x55\x33\x17\xfa"
    );
    putchar('\n');

    /* -------------------------------------------------------------------------------- */
}

typedef struct {
    unsigned char data[256];
    size_t count, cursor;
} buffer_t;

void buffer_init(buffer_t* buf, const void* data, size_t size) {
    memcpy(buf->data, data, size);
    buf->count = size;
    buf->cursor = 0;
}

size_t buffer_read(void* out, size_t sz, size_t cnt, void* ud) {
    size_t i, rd = 0; buffer_t* buf = ud;
    for (i = 0; i < cnt; i++) {
        if (buf->count - buf->cursor < sz) break;
        memcpy((char*)out + i * sz, buf->data + buf->cursor, sz);
        buf->cursor += sz; ++rd;
    }
    return rd;
}

size_t buffer_write(const void* out, size_t sz, size_t cnt, void* ud) {
    size_t i, wr = 0; buffer_t* buf = ud;
    for (i = 0; i < cnt; i++) {
        if (sizeof buf->data - buf->cursor < sz) break;
        memcpy(buf->data + buf->cursor, (const char*)out + i * sz, sz);
        buf->count += sz; buf->cursor += sz; ++wr;
    }
    return wr;
}

#define mode_test_case_aead(mname, cname, ksz, vsz, asz, psz, csz, tsz, key, iv, authdat, plain, cipher, tag) \
do {                                                             \
    unsigned char T[tsz]; buffer_t P, C; int i;                  \
                                                                 \
    puts("[=============== Encryption ===============]");        \
                                                                 \
    printf("- Setup cipher with %3i bits key    ... ", ksz);     \
    puts(mname##_set_encode_func(cname##_block_encode) == 0      \
        && cname##_init(key, ksz) == 0 ? OK : FAIL);             \
                                                                 \
    printf("- Set initialization vector         ... ");          \
    puts(mname##_set_init_vector(iv) == 0 ? OK : FAIL);          \
                                                                 \
    printf("- Set associated authenticated data ... ");          \
    puts(mname##_set_auth_data(authdat, asz) == 0 ? OK : FAIL);  \
                                                                 \
    buffer_init(&P, plain, psz); memset(&C, 0, sizeof C);        \
    printf("- Set reader (plaintext)            ... ");          \
    puts(mname##_set_reader(buffer_read , &P) == 0 ? OK : FAIL); \
    printf("- Set writer (ciphertext)           ... ");          \
    puts(mname##_set_writer(buffer_write, &C) == 0 ? OK : FAIL); \
                                                                 \
    printf("- Encryption process                ... ");          \
    puts(mname##_encryption() == 0 ? OK : FAIL);                 \
                                                                 \
    printf("- Check ciphertext                  ... ");          \
    if (memcmp(C.data, cipher, csz) == 0) puts(OK);              \
    else {                                                       \
        puts(FAIL);                                              \
        printf("  > expected: ");                                \
        for (i = 0; i < csz; i++)                                \
            printf("%02x", cipher[i] & 0xFF);                    \
        putchar('\n');                                           \
        printf("  > received: ");                                \
        for (i = 0; i < csz; i++)                                \
            printf("%02x", C.data[i]);                           \
        putchar('\n');                                           \
    }                                                            \
                                                                 \
    printf("- Get authentication tag            ... ");          \
    puts(mname##_get_auth_tag(T) == 0 ? OK : FAIL);              \
                                                                 \
    printf("- Check authentication tag          ... ");          \
    if (memcmp(T, tag, tsz) == 0) puts(OK);                      \
    else {                                                       \
        puts(FAIL);                                              \
        printf("  > expected: ");                                \
        for (i = 0; i < tsz; i++)                                \
            printf("%02x", tag[i] & 0xFF);                       \
        putchar('\n');                                           \
        printf("  > received: ");                                \
        for (i = 0; i < tsz; i++)                                \
            printf("%02x", T[i]);                                \
        putchar('\n');                                           \
    }                                                            \
                                                                 \
    puts("[=============== Decryption ===============]");        \
                                                                 \
    printf("- Setup cipher with %3i bits key    ... ", ksz);     \
    puts(mname##_set_encode_func(cname##_block_encode) == 0      \
        && cname##_init(key, ksz) == 0 ? OK : FAIL);             \
                                                                 \
    printf("- Set initialization vector         ... ");          \
    puts(mname##_set_init_vector(iv) == 0 ? OK : FAIL);          \
                                                                 \
    printf("- Set associated authenticated data ... ");          \
    puts(mname##_set_auth_data(authdat, asz) == 0 ? OK : FAIL);  \
                                                                 \
    printf("- Set authentication tag            ... ");          \
    puts(mname##_set_auth_tag(T) == 0 ? OK : FAIL);              \
                                                                 \
    memcpy(&P, &C, sizeof C); P.cursor = 0;                      \
    memset(&C, 0, sizeof C);                                     \
    printf("- Set reader (ciphertext)           ... ");          \
    puts(mname##_set_reader(buffer_read , &P) == 0 ? OK : FAIL); \
    printf("- Set writer (plaintext)            ... ");          \
    puts(mname##_set_writer(buffer_write, &C) == 0 ? OK : FAIL); \
                                                                 \
    printf("- Decryption process                ... ");          \
    puts(mname##_decryption() == 0 ? OK : FAIL);                 \
                                                                 \
    printf("- Check plaintext                   ... ");          \
    if (memcmp(C.data, plain, psz) == 0) puts(OK);               \
    else {                                                       \
        puts(FAIL);                                              \
        printf("  > expected: ");                                \
        for (i = 0; i < psz; i++)                                \
            printf("%02x", plain[i] & 0xFF);                     \
        putchar('\n');                                           \
        printf("  > received: ");                                \
        for (i = 0; i < psz; i++)                                \
            printf("%02x", C.data[i]);                           \
        putchar('\n');                                           \
    }                                                            \
} while (0)

void mode_test(void) {
    /* -------------------------------------------------------------------------------- */

    puts("Testing Multilinear Galois Mode (MGM), 128 bit:");
    mode_test_case_aead(
        mgm16, kuznyechik, 256, 16, 41, 67, 67, 16,
        /* K */ "\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44\x55\x66\x77"
                "\xfe\xdc\xba\x98\x76\x54\x32\x10\x01\x23\x45\x67\x89\xab\xcd\xef",
        /* V */ "\x11\x22\x33\x44\x55\x66\x77\x00\xff\xee\xdd\xcc\xbb\xaa\x99\x88",
        /* A */ "\x02\x02\x02\x02\x02\x02\x02\x02\x01\x01\x01\x01\x01\x01\x01\x01"
                "\x04\x04\x04\x04\x04\x04\x04\x04\x03\x03\x03\x03\x03\x03\x03\x03"
                "\xea\x05\x05\x05\x05\x05\x05\x05\x05",
        /* P */ "\x11\x22\x33\x44\x55\x66\x77\x00\xff\xee\xdd\xcc\xbb\xaa\x99\x88"
                "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xee\xff\x0a"
                "\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xee\xff\x0a\x00"
                "\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xee\xff\x0a\x00\x11"
                "\xaa\xbb\xcc",
        /* C */ "\xa9\x75\x7b\x81\x47\x95\x6e\x90\x55\xb8\xa3\x3d\xe8\x9f\x42\xfc"
                "\x80\x75\xd2\x21\x2b\xf9\xfd\x5b\xd3\xf7\x06\x9a\xad\xc1\x6b\x39"
                "\x49\x7a\xb1\x59\x15\xa6\xba\x85\x93\x6b\x5d\x0e\xa9\xf6\x85\x1c"
                "\xc6\x0c\x14\xd4\xd3\xf8\x83\xd0\xab\x94\x42\x06\x95\xc7\x6d\xeb"
                "\x2c\x75\x52",
        /* T */ "\xcf\x5d\x65\x6f\x40\xc3\x4f\x5c\x46\xe8\xbb\x0e\x29\xfc\xdb\x4c"
    );
    putchar('\n');
    mode_test_case_aead(
        mgm16, kuznyechik, 256, 16, 16, 0, 0, 16,
        /* K */ "\x99\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44\x55\x66\x77\xfe"
                "\xdc\xba\x98\x76\x54\x32\x10\x01\x23\x45\x67\x89\xab\xcd\xef\x88",
        /* V */ "\x11\x22\x33\x44\x55\x66\x77\x00\xff\xee\xdd\xcc\xbb\xaa\x99\x88",
        /* A */ "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01",
        /* P */ "",
        /* C */ "",
        /* T */ "\x79\x01\xe9\xea\x20\x85\xcd\x24\x7e\xd2\x49\x69\x5f\x9f\x8a\x85"
    );
    putchar('\n');

    /* -------------------------------------------------------------------------------- */

    puts("Testing Multilinear Galois Mode (MGM), 64 bit:");
    mode_test_case_aead(
        mgm8, magma, 256, 8, 41, 67, 67, 8,
        /* K */ "\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00"
                "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
        /* V */ "\x12\xde\xf0\x6b\x3c\x13\x0a\x59",
        /* A */ "\x01\x01\x01\x01\x01\x01\x01\x01\x02\x02\x02\x02\x02\x02\x02\x02"
                "\x03\x03\x03\x03\x03\x03\x03\x03\x04\x04\x04\x04\x04\x04\x04\x04"
                "\x05\x05\x05\x05\x05\x05\x05\x05\xea",
        /* P */ "\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x11\x22\x33\x44\x55\x66\x77\x00"
                "\x88\x99\xaa\xbb\xcc\xee\xff\x0a\x00\x11\x22\x33\x44\x55\x66\x77"
                "\x99\xaa\xbb\xcc\xee\xff\x0a\x00\x11\x22\x33\x44\x55\x66\x77\x88"
                "\xaa\xbb\xcc\xee\xff\x0a\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99"
                "\xaa\xbb\xcc",
        /* C */ "\xc7\x95\x06\x6c\x5f\x9e\xa0\x3b\x85\x11\x33\x42\x45\x91\x85\xae"
                "\x1f\x2e\x00\xd6\xbf\x2b\x78\x5d\x94\x04\x70\xb8\xbb\x9c\x8e\x7d"
                "\x9a\x5d\xd3\x73\x1f\x7d\xdc\x70\xec\x27\xcb\x0a\xce\x6f\xa5\x76"
                "\x70\xf6\x5c\x64\x6a\xbb\x75\xd5\x47\xaa\x37\xc3\xbc\xb5\xc3\x4e"
                "\x03\xbb\x9c",
        /* T */ "\xa7\x92\x80\x69\xaa\x10\xfd\x10"
    );
    putchar('\n');
    mode_test_case_aead(
        mgm8, magma, 256, 8, 0, 8, 8, 8,
        /* K */ "\x99\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44\x55\x66\x77\xfe"
                "\xdc\xba\x98\x76\x54\x32\x10\x01\x23\x45\x67\x89\xab\xcd\xef\x88",
        /* V */ "\x00\x77\x66\x55\x44\x33\x22\x11",
        /* A */ "",
        /* P */ "\x22\x33\x44\x55\x66\x77\x00\xff",
        /* C */ "\x6a\x95\xe1\x42\x6b\x25\x9d\x4e",
        /* T */ "\x33\x4e\xe2\x70\x45\x0b\xec\x9e"
    );
    putchar('\n');

    /* -------------------------------------------------------------------------------- */
}

int main(void) {
    putchar('\n');
    cipher_test();
    mode_test();
    return 0;
}