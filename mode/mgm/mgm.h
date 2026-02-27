/* Multilinear Galois Mode (MGM)
 *
 * Bits   - 128 bits
 * Type   - Authenticated Encryption with Associated Data (AEAD)
 * Source - https://datatracker.ietf.org/doc/html/rfc9058
 */

#ifndef MULTILINEAR_GALOIS_MODE_H
#define MULTILINEAR_GALOIS_MODE_H

#include <stddef.h>

int mgm_set_reader(size_t (*rdfunc)(      void*, size_t, size_t, void*), void* userdata);
int mgm_set_writer(size_t (*wrfunc)(const void*, size_t, size_t, void*), void* userdata);

int mgm_set_auth_data(const void* data, size_t size);
int mgm_set_init_vector(const void* data);

int mgm_set_auth_tag(const void* src);
int mgm_get_auth_tag(      void* dst);

int mgm_set_encode_func(void (*enc)(void*, const void*));

int mgm_encryption(void);
int mgm_decryption(void);

#endif /* MULTILINEAR_GALOIS_MODE_H */