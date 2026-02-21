#ifndef CLEFIA_BLOCK_CIPHER_H
#define CLEFIA_BLOCK_CIPHER_H

#define CLEFIA_BLOCK_BITS 128
#define CLEFIA_BLOCK_BYTE 16

int clefia_init(const void* key, int key_bits);

void clefia_block_encode(void* dest, const void* src);
void clefia_block_decode(void* dest, const void* src);

#endif /* CLEFIA_BLOCK_CIPHER_H */