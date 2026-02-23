/* KHAZAD
 *
 * Length of block - 64 bit
 * Length of key   - 128 bit
 * Sources:
 *   https://ru.wikipedia.org/wiki/KHAZAD
 */

#ifndef KHAZAD_BLOCK_CIPHER_H
#define KHAZAD_BLOCK_CIPHER_H

#define KHAZAD_BLOCK_BITS 64
#define KHAZAD_BLOCK_BYTE 8

int khazad_init(const void* key, int key_bits);

void khazad_block_encode(void* dest, const void* src);
void khazad_block_decode(void* dest, const void* src);

#endif /* KHAZAD_BLOCK_CIPHER_H */