/* Rivest's cipher 5 (RC5) (with 20 rounds)
 *
 * Length of block - 64 bit
 * Length of key   - from 0 to 2040 bit
 * Sources:
 *   https://people.csail.mit.edu/rivest/pubs/Riv94.pdf
 *   https://datatracker.ietf.org/doc/html/draft-krovetz-rc6-rc5-vectors
 */

#ifndef RC5_BLOCK_CIPHER_H
#define RC5_BLOCK_CIPHER_H

#define RC5_BLOCK_BITS 64
#define RC5_BLOCK_BYTE 8

int rc5_init(const void* key, int key_bits);

void rc5_block_encode(void* dest, const void* src);
void rc5_block_decode(void* dest, const void* src);

#endif /* RC5_BLOCK_CIPHER_H */