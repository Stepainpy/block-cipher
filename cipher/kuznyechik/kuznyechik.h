/* Kuznyechik
 *
 * Length of block - 128 bit
 * length of key   - 256 bit
 * Sources:
 *   https://datatracker.ietf.org/doc/html/rfc7801
 *   https://ru.wikipedia.org/wiki/Кузнечик_(шифр)
 */

#ifndef KUZNYECHIK_BLOCK_CIPHER_H
#define KUZNYECHIK_BLOCK_CIPHER_H

#define KUZNYECHIK_BLOCK_BITS 128
#define KUZNYECHIK_BLOCK_BYTE 16

int kuznyechik_init(const void* key, int key_bits);

void kuznyechik_block_encode(void* dest, const void* src);
void kuznyechik_block_decode(void* dest, const void* src);

#endif /* KUZNYECHIK_BLOCK_CIPHER_H */