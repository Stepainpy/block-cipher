/* Camellia
 *
 * Length of block - 128 bit
 * Length of key   - 128, 192 or 256 bit
 * Sources:
 *   https://datatracker.ietf.org/doc/html/rfc3713
 */

#ifndef CAMELLIA_BLOCK_CIPHER_H
#define CAMELLIA_BLOCK_CIPHER_H

#define CAMELLIA_BLOCK_BITS 128
#define CAMELLIA_BLOCK_BYTE 16

int camellia_init(const void* key, int key_bits);

void camellia_block_encode(void* dest, const void* src);
void camellia_block_decode(void* dest, const void* src);

#endif /* CAMELLIA_BLOCK_CIPHER_H */