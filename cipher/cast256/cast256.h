/* CAST-256
 *
 * Length of block - 128 bit
 * Length of key   - 128, 160, 192, 224 or 256 bit
 * Sources:
 *   https://datatracker.ietf.org/doc/html/rfc2612
 *   https://ru.wikipedia.org/wiki/CAST-256
 */

#ifndef CAST256_BLOCK_CIPHER_H
#define CAST256_BLOCK_CIPHER_H

#define CAST256_BLOCK_BITS 128
#define CAST256_BLOCK_BYTE 16

int cast256_init(const void* key, int key_bits);

void cast256_block_encode(void* dest, const void* src);
void cast256_block_decode(void* dest, const void* src);

#endif /* CAST256_BLOCK_CIPHER_H */