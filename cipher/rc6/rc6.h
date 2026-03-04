/* Rivest's cipher 6 (RC6)
 *
 * Length of block - 128 bit
 * Length of key   - from 0 to 2040 bit
 * Sources:
 *   https://people.csail.mit.edu/rivest/pubs/RRSY98.pdf
 *   https://people.csail.mit.edu/rivest/pubs/Riv94.pdf
 *   https://ru.wikipedia.org/wiki/RC6
 */

#ifndef RC6_BLOCK_CIPHER_H
#define RC6_BLOCK_CIPHER_H

#define RC6_BLOCK_BITS 128
#define RC6_BLOCK_BYTE 16

int rc6_init(const void* key, int key_bits);

void rc6_block_encode(void* dest, const void* src);
void rc6_block_decode(void* dest, const void* src);

#endif /* RC6_BLOCK_CIPHER_H */