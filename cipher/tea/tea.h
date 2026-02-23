/* Tiny Encryption Algorithm (TEA)
 *
 * Length of block - 64 bit
 * Length of key   - 128 bit
 * Sources:
 *   https://ru.wikipedia.org/wiki/TEA
 */

#ifndef TEA_BLOCK_CIPHER_H
#define TEA_BLOCK_CIPHER_H

#define TEA_BLOCK_BITS 64
#define TEA_BLOCK_BYTE 8

int tea_init(const void* key, int key_bits);

void tea_block_encode(void* dest, const void* src);
void tea_block_decode(void* dest, const void* src);

#endif /* TEA_BLOCK_CIPHER_H */