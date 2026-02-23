/* Advanced Encryption Standard (AES)
 *
 * Length of block - 128 bit
 * Length of key   - 128, 192 or 256 bit
 * Sources:
 *   https://ru.wikipedia.org/wiki/AES_(стандарт_шифрования)
 *   https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
 *   https://en.wikipedia.org/wiki/AES_key_schedule
 */

#ifndef AES_BLOCK_CIPHER_H
#define AES_BLOCK_CIPHER_H

#define AES_BLOCK_BITS 128
#define AES_BLOCK_BYTE 16

int aes_init(const void* key, int key_bits);

void aes_block_encode(void* dest, const void* src);
void aes_block_decode(void* dest, const void* src);

#endif /* AES_BLOCK_CIPHER_H */