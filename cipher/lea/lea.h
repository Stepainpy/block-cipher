/* Lightweight Encryption Algorithm (LEA)
 *
 * Length of block - 128 bit
 * Length of key   - 128, 192 or 256 bit
 * Sources:
 *   https://en.wikipedia.org/wiki/LEA_(cipher)
 */

#ifndef LEA_BLOCK_CIPHER_H
#define LEA_BLOCK_CIPHER_H

#define LEA_BLOCK_BITS 128
#define LEA_BLOCK_BYTE 16

int lea_init(const void* key, int key_bits);

void lea_block_encode(void* dest, const void* src);
void lea_block_decode(void* dest, const void* src);

#endif /* LEA_BLOCK_CIPHER_H */