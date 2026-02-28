/* Magma
 *
 * Length of block - 64 bit
 * Length of key   - 256 bit
 * Sources:
 *   https://datatracker.ietf.org/doc/html/rfc8891
 *   https://ru.wikipedia.org/wiki/ГОСТ_28147-89#Магма
 */

#ifndef MAGMA_BLOCK_CIPHER_H
#define MAGMA_BLOCK_CIPHER_H

#define MAGMA_BLOCK_BITS 64
#define MAGMA_BLOCK_BYTE 8

int magma_init(const void* key, int key_bits);

void magma_block_encode(void* dest, const void* src);
void magma_block_decode(void* dest, const void* src);

#endif /* MAGMA_BLOCK_CIPHER_H */