#include <stdio.h>
#include <string.h>

#include "blowfish/blowfish.h"
#include "clefia/clefia.h"
#include "khazad/khazad.h"
#include "rtea/rtea.h"
#include "aes/aes.h"
#include "lea/lea.h"
#include "tea/tea.h"

/* use ANSI coloring */
#if 1
#  define OK   "\x1b[32mOK\x1b[0m"
#  define FAIL "\x1b[31mFAIL\x1b[0m"
#else
#  define OK   "OK"
#  define FAIL "FAIL"
#endif

#define test_case(name, blocksz, keysz, key, plain, cipher) \
do {                                                  \
    unsigned char P[blocksz], C[blocksz]; int i;      \
                                                      \
    printf("- Set key with %i bits ... ", keysz);     \
    puts(name##_init(key, keysz) == 0 ? OK : FAIL);   \
                                                      \
    printf("- Check X = D(E(X)) ... ");               \
    memcpy(P, plain, blocksz);                        \
    name##_block_encode(C, P);                        \
    name##_block_decode(P, C);                        \
    puts(memcmp(P, plain, blocksz) == 0 ? OK : FAIL); \
                                                      \
    printf("- Check X = E(D(X)) ... ");               \
    memcpy(P, plain, blocksz);                        \
    name##_block_decode(C, P);                        \
    name##_block_encode(P, C);                        \
    puts(memcmp(P, plain, blocksz) == 0 ? OK : FAIL); \
                                                      \
    printf("- Check test vector ... ");               \
    memcpy(P, plain, blocksz);                        \
    name##_block_encode(C, P);                        \
    if (memcmp(C, cipher, blocksz) == 0) puts(OK);    \
    else {                                            \
        puts(FAIL);                                   \
        printf("  > expected: ");                     \
        for (i = 0; i < blocksz; i++)                 \
            printf("%02x", C[i]);                     \
        putchar('\n');                                \
        printf("  > received: ");                     \
        for (i = 0; i < blocksz; i++)                 \
            printf("%02x", cipher[i] & 0xFF);         \
        putchar('\n');                                \
    }                                                 \
} while (0)

int main(void) {
    putchar('\n');

    /* -------------------------------------------------------------------------------- */

    puts("Testing Advanced Encryption Standard (AES):");
    test_case(
        aes, AES_BLOCK_BYTE, 128,
        /* K */ "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
        /* P */ "\x32\x43\xf6\xa8\x88\x5a\x30\x8d\x31\x31\x98\xa2\xe0\x37\x07\x34",
        /* C */ "\x39\x25\x84\x1d\x02\xdc\x09\xfb\xdc\x11\x85\x97\x19\x6a\x0b\x32"
    );
    test_case(
        aes, AES_BLOCK_BYTE, 192,
        /* K */ "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5"
                "\x62\xf8\xea\xd2\x52\x2c\x6b\x7b",
        /* P */ "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a",
        /* C */ "\xbd\x33\x4f\x1d\x6e\x45\xf2\x5f\xf7\x12\xa2\x14\x57\x1f\xa5\xcc"
    );
    test_case(
        aes, AES_BLOCK_BYTE, 256,
        /* K */ "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
                "\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4",
        /* P */ "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a",
        /* C */ "\xf3\xee\xd1\xbd\xb5\xd2\xa0\x3c\x06\x4b\x5a\x7e\x3d\xb1\x81\xf8"
    );
    putchar('\n');

    /* -------------------------------------------------------------------------------- */

    puts("Testing Blowfish:");
    test_case(
        blowfish, BLOWFISH_BLOCK_BYTE, 64,
        /* K */ "\xfe\xdc\xba\x98\x76\x54\x32\x10",
        /* P */ "\x01\x23\x45\x67\x89\xab\xcd\xef",
        /* C */ "\x0a\xce\xab\x0f\xc6\xa0\xa2\x8d"
    );
    test_case(
        blowfish, BLOWFISH_BLOCK_BYTE, 64,
        /* K */ "\x01\x70\xf1\x75\x46\x8f\xb5\xe6",
        /* P */ "\x07\x56\xd8\xe0\x77\x47\x61\xd2",
        /* C */ "\x43\x21\x93\xb7\x89\x51\xfc\x98"
    );
    test_case(
        blowfish, BLOWFISH_BLOCK_BYTE, 128,
        /* K */ "\xf0\xe1\xd2\xc3\xb4\xa5\x96\x87\x78\x69\x5a\x4b\x3c\x2d\x1e\x0f",
        /* P */ "\xfe\xdc\xba\x98\x76\x54\x32\x10",
        /* C */ "\x93\x14\x28\x87\xee\x3b\xe1\x5c"
    );
    test_case(
        blowfish, BLOWFISH_BLOCK_BYTE, 160,
        /* K */ "\xf0\xe1\xd2\xc3\xb4\xa5\x96\x87\x78\x69\x5a\x4b\x3c\x2d\x1e\x0f"
                "\x00\x11\x22\x33",
        /* P */ "\xfe\xdc\xba\x98\x76\x54\x32\x10",
        /* C */ "\x10\x85\x1c\x0e\x38\x58\xda\x9f"
    );
    test_case(
        blowfish, BLOWFISH_BLOCK_BYTE, 192,
        /* K */ "\xf0\xe1\xd2\xc3\xb4\xa5\x96\x87\x78\x69\x5a\x4b\x3c\x2d\x1e\x0f"
                "\x00\x11\x22\x33\x44\x55\x66\x77",
        /* P */ "\xfe\xdc\xba\x98\x76\x54\x32\x10",
        /* C */ "\x05\x04\x4b\x62\xfa\x52\xd0\x80"
    );
    putchar('\n');

    /* -------------------------------------------------------------------------------- */

    puts("Testing CLEFIA:");
    test_case(
        clefia, CLEFIA_BLOCK_BYTE, 128,
        /* K */ "\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00",
        /* P */ "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
        /* C */ "\xde\x2b\xf2\xfd\x9b\x74\xaa\xcd\xf1\x29\x85\x55\x45\x94\x94\xfd"
    );
    test_case(
        clefia, CLEFIA_BLOCK_BYTE, 192,
        /* K */ "\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00"
                "\xf0\xe0\xd0\xc0\xb0\xa0\x90\x80",
        /* P */ "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
        /* C */ "\xe2\x48\x2f\x64\x9f\x02\x8d\xc4\x80\xdd\xa1\x84\xfd\xe1\x81\xad"
    );
    test_case(
        clefia, CLEFIA_BLOCK_BYTE, 256,
        /* K */ "\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00"
                "\xf0\xe0\xd0\xc0\xb0\xa0\x90\x80\x70\x60\x50\x40\x30\x20\x10\x00",
        /* P */ "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
        /* C */ "\xa1\x39\x78\x14\x28\x9d\xe8\x0c\x10\xda\x46\xd1\xfa\x48\xb3\x8a"
    );
    putchar('\n');

    /* -------------------------------------------------------------------------------- */

    puts("Testing KHAZAD:");
    test_case(
        khazad, KHAZAD_BLOCK_BYTE, 128,
        /* K */ "\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        /* P */ "\x00\x00\x00\x00\x00\x00\x00\x00",
        /* C */ "\x49\xa4\xce\x32\xac\x19\x0e\x3f"
    );
    test_case(
        khazad, KHAZAD_BLOCK_BYTE, 128,
        /* K */ "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        /* P */ "\x00\x00\x00\x20\x00\x00\x00\x00",
        /* C */ "\x3b\x89\x88\x9c\xe8\x06\xc5\x63"
    );
    test_case(
        khazad, KHAZAD_BLOCK_BYTE, 128,
        /* K */ "\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78",
        /* P */ "\x78\x78\x78\x78\x78\x78\x78\x78",
        /* C */ "\x23\x46\x21\x0d\x6a\x6c\xa0\xd1"
    );
    putchar('\n');

    /* -------------------------------------------------------------------------------- */

    puts("Testing Lightweight Encryption Algorithm (LEA):");
    test_case(
        lea, LEA_BLOCK_BYTE, 128,
        /* K */ "\x0f\x1e\x2d\x3c\x4b\x5a\x69\x78\x87\x96\xa5\xb4\xc3\xd2\xe1\xf0",
        /* P */ "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
        /* C */ "\x9f\xc8\x4e\x35\x28\xc6\xc6\x18\x55\x32\xc7\xa7\x04\x64\x8b\xfd"
    );
    test_case(
        lea, LEA_BLOCK_BYTE, 192,
        /* K */ "\x0f\x1e\x2d\x3c\x4b\x5a\x69\x78\x87\x96\xa5\xb4\xc3\xd2\xe1\xf0"
                "\xf0\xe1\xd2\xc3\xb4\xa5\x96\x87",
        /* P */ "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f",
        /* C */ "\x6f\xb9\x5e\x32\x5a\xad\x1b\x87\x8c\xdc\xf5\x35\x76\x74\xc6\xf2"
    );
    test_case(
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
    test_case(
        rtea, RTEA_BLOCK_BYTE, 128,
        /* K */ "\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00",
        /* P */ "\x00\x01\x02\x03\x04\x05\x06\x07",
        /* C */ "\xf9\x34\xd2\x32\x10\x57\x83\x6b"
    );
    test_case(
        rtea, RTEA_BLOCK_BYTE, 256,
        /* K */ "\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00"
                "\xf0\xe0\xd0\xc0\xb0\xa0\x90\x80\x70\x60\x50\x40\x30\x20\x10\x00",
        /* P */ "\x00\x01\x02\x03\x04\x05\x06\x07",
        /* C */ "\xe4\xff\x5c\x41\x96\x9e\x10\xa8"
    );
    putchar('\n');

    /* -------------------------------------------------------------------------------- */

    puts("Testing Tiny Encryption Algorithm (TEA):");
    test_case(
        tea, TEA_BLOCK_BYTE, 128,
        /* K */ "\x33\x22\x11\x00\x77\x66\x55\x44\xbb\xaa\x99\x88\xff\xee\xdd\xcc",
        /* P */ "\x67\x45\x23\x01\xef\xcd\xab\x89",
        /* C */ "\x92\x6b\x6c\x12\x3e\x3a\x65\xc0"
    );
    putchar('\n');

    /* -------------------------------------------------------------------------------- */

    return 0;
}