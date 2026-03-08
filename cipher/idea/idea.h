/* International Data Encryption Algorithm (IDEA)
 *
 * Length of block - 64 bit
 * Length of key   - 128 bit
 * Sources:
 *   https://ru.wikipedia.org/wiki/IDEA
 *   https://www.source-code.biz/idea/java/Idea.java
 *   https://crypto.stackexchange.com/questions/91973/test-vectors-for-idea
 */

#ifndef IDEA_BLOCK_CIPHER_H
#define IDEA_BLOCK_CIPHER_H

#define IDEA_BLOCK_BITS 64
#define IDEA_BLOCK_BYTE 8

int idea_init(const void* key, int key_bits);

void idea_block_encode(void* dest, const void* src);
void idea_block_decode(void* dest, const void* src);

#endif /* IDEA_BLOCK_CIPHER_H */