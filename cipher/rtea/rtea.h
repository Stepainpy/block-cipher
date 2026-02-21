#ifndef RTEA_BLOCK_CIPHER_H
#define RTEA_BLOCK_CIPHER_H

#define RTEA_BLOCK_BITS 64
#define RTEA_BLOCK_BYTE 8

int rtea_init(const void* key, int key_bits);

void rtea_block_encode(void* dest, const void* src);
void rtea_block_decode(void* dest, const void* src);

#endif /* RTEA_BLOCK_CIPHER_H */