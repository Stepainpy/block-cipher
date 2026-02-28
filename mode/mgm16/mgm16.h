/* Multilinear Galois Mode (MGM)
 *
 * Bits   - 128 bits
 * Type   - Authenticated Encryption with Associated Data (AEAD)
 * Source - https://datatracker.ietf.org/doc/html/rfc9058
 */

/* Instructions for use
 *
 * Encryption:
 * 1. Setup external state
 *   - reader
 *   - writer
 *   - encode
 * 2. Set external data
 *   - initialization vector
 *   - associated authenticated data
 * 3. Set reader (plaintext)
 * 4. Set writer (ciphertext)
 * 5. Set encode function
 * 6. Run `mgm16_encryption`
 * 7. Get tag by `mgm16_get_auth_tag`
 *
 * Decryption:
 * 1. Setup external state
 *   - reader
 *   - writer
 *   - encode
 * 2. Set external data
 *   - initialization vector
 *   - associated authenticated data
 *   - authentication tag
 * 3. Set reader (ciphertext)
 * 4. Set writer (plaintext)
 * 5. Set encode function
 * 6. Run `mgm16_decryption`
 */

#ifndef MULTILINEAR_GALOIS_MODE_H
#define MULTILINEAR_GALOIS_MODE_H

#include <stddef.h>

#define MGM16_INIT_VEC_BYTE 16
#define MGM16_AUTH_TAG_BYTE 16

int mgm16_set_reader(size_t (*rdfunc)(      void*, size_t, size_t, void*), void* userdata);
int mgm16_set_writer(size_t (*wrfunc)(const void*, size_t, size_t, void*), void* userdata);

int mgm16_set_auth_data(const void* data, size_t size);
int mgm16_set_init_vector(const void* data);

int mgm16_set_auth_tag(const void* src);
int mgm16_get_auth_tag(      void* dst);

int mgm16_set_encode_func(void (*enc)(void*, const void*));

int mgm16_encryption(void);
int mgm16_decryption(void);

#endif /* MULTILINEAR_GALOIS_MODE_H */