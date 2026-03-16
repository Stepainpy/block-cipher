# Block ciphers

> [!Warning]
> This code is not intended to provide true protection against real-world attacks. Instead, it serves as a demonstration of the algorithms.

Implementation of several block ciphers.

## Documentation

All functions that return a value return `0` upon success, nonzero value otherwise.

### Ciphers

**`#define <NANE>_BLOCK_BITS <integer-literal>`**  
The length of the encrypted block in bits.

**`#define <NANE>_BLOCK_BYTE <integer-literal>`**  
The length of the encrypted block in bytes.

**`int <name>_init(const void* key, int key_bits)`**  
Initializes the internal state using a key at the `key` pointer with a length of `key_bits` bits.

**`void <name>_block_encode(void* dest, const void* src)`**  
Encrypts the block by the `src` pointer and stores it by the `dest` pointer (`src` and `dest` can be the same).

**`void <name>_block_decode(void* dest, const void* src)`**  
Decrypts the block by the `src` pointer and stores it by the `dest` pointer (`src` and `dest` can be the same).

### Modes

#### Authenticated Encryption with Associated Data

**`#define <NAME>_INIT_VEC_BYTE <integer-literal>`**  
The length of the initialization vector in bytes.

**`#define <NAME>_AUTH_TAG_BYTE <integer-literal>`**  
The length of the authentication tag in bytes.

**`int <name>_set_reader(size_t (*func)(void* dst, size_t size, size_t count, void* userdata), void* userdata)`**  
Sets the reading callback for plain/cipher text.

**`int <name>_set_writer(size_t (*func)(const void* src, size_t size, size_t count, void* userdata), void* userdata)`**  
Sets the writing callback for cipher/plain text.

**`int <name>_set_auth_data(const void* data, size_t size)`**  
Sets the authentication data, it may be empty.

**`int <name>_set_init_vector(const void* data)`**  
Sets the initialization vector, expect `<NAME>_INIT_VEC_BYTE` bytes.

**`int <name>_set_auth_tag(const void* src)`**  
Sets the authentication tag for checking in decryption, expect `<NAME>_AUTH_TAG_BYTE` bytes.

**`int <name>_get_auth_tag(void* dst)`**  
Сopies the value of the authentication tag after encryption, expect `<NAME>_AUTH_TAG_BYTE` bytes.

**`int <name>_set_encode_func(void (*func)(void* dst, const void* src))`**  
Sets the encryption function with behaviour like a ciphers before.

**`void <name>_encryption(void)`**  
Encrypts the plaintext from the reader and write the result to writer.

**`void <name>_decryption(void)`**  
Decrypts the ciphertext from the reader and write the result to writer.