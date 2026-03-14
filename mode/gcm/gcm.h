/* Galois/Counter Mode (GCM)
 *
 * Bits   - 128 bits
 * Type   - Authenticated Encryption with Associated Data (AEAD)
 * Source - https://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf
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
 * 6. Run `gcm_encryption`
 * 7. Get tag by `gcm_get_auth_tag`
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
 * 6. Run `gcm_decryption`
 */

#ifndef GALOIS_COUNTER_MODE_H
#define GALOIS_COUNTER_MODE_H

#include <stddef.h>

#define GCM_INIT_VEC_BYTE 12
#define GCM_AUTH_TAG_BYTE 16

int gcm_set_reader(size_t (*rdfunc)(      void*, size_t, size_t, void*), void* userdata);
int gcm_set_writer(size_t (*wrfunc)(const void*, size_t, size_t, void*), void* userdata);

int gcm_set_auth_data(const void* data, size_t size);
int gcm_set_init_vector(const void* data);

int gcm_set_auth_tag(const void* src);
int gcm_get_auth_tag(      void* dst);

int gcm_set_encode_func(void (*enc)(void*, const void*));

int gcm_encryption(void);
int gcm_decryption(void);

#endif /* GALOIS_COUNTER_MODE_H */