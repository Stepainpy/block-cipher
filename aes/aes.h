#ifndef AES_BLOCK_CIPHER_H
#define AES_BLOCK_CIPHER_H

#define AES_BLOCK_BITS 128
#define AES_BLOCK_BYTE 16

int aes_init(const void* key, int key_bits);

void aes_block_encode(void* dest, const void* src);
void aes_block_decode(void* dest, const void* src);

#endif /* AES_BLOCK_CIPHER_H */