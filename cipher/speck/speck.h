/* Speck
 *
 * Length of block - 128 bit
 * Length of key   - 128, 192 or 256 bit
 * Sources:
 *   https://eprint.iacr.org/2013/404.pdf
 *   https://en.wikipedia.org/wiki/Speck_(cipher)
 */

#ifndef SPECK_BLOCK_CIPHER_H
#define SPECK_BLOCK_CIPHER_H

#define SPECK_BLOCK_BITS 128
#define SPECK_BLOCK_BYTE 16

int speck_init(const void* key, int key_bits);

void speck_block_encode(void* dest, const void* src);
void speck_block_decode(void* dest, const void* src);

#endif /* SPECK_BLOCK_CIPHER_H */