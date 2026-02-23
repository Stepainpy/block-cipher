/* Blowfish
 *
 * Length of block - 64 bit
 * Length of key   - from 32 to 448 bit
 * Sources:
 *   https://ru.wikipedia.org/wiki/Blowfish
 *   https://en.wikipedia.org/wiki/Blowfish_(cipher)
 */

#ifndef BLOWFISH_BLOCK_CIPHER_H
#define BLOWFISH_BLOCK_CIPHER_H

#define BLOWFISH_BLOCK_BITS 64
#define BLOWFISH_BLOCK_BYTE 8

int blowfish_init(const void* key, int key_bits);

void blowfish_block_encode(void* dest, const void* src);
void blowfish_block_decode(void* dest, const void* src);

#endif /* BLOWFISH_BLOCK_CIPHER_H */