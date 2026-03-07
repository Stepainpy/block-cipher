/* CAST-128
 *
 * Length of block - 64 bit
 * Length of key   - from 40 to 128 bit
 * Sources:
 *   https://datatracker.ietf.org/doc/html/rfc2144
 *   https://ru.wikipedia.org/wiki/CAST-128
 */

#ifndef CAST128_BLOCK_CIPHER_H
#define CAST128_BLOCK_CIPHER_H

#define CAST128_BLOCK_BITS 64
#define CAST128_BLOCK_BYTE 8

int cast128_init(const void* key, int key_bits);

void cast128_block_encode(void* dest, const void* src);
void cast128_block_decode(void* dest, const void* src);

#endif /* CAST128_BLOCK_CIPHER_H */