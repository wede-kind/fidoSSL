#ifndef FIDO_COMMON_H
#define FIDO_COMMON_H

#include <openssl/ssl.h>
#include "types.h"

const char* get_ssl_ext_context_code(unsigned int context);

int sha256_hash(const u8 *in, size_t inlen, u8 **out, size_t *outlen);

int aes_gcm_encrypt(const u8 *plain, size_t plain_len, u8 **cypher, size_t *cypher_len, const u8 *key, size_t key_len);

int aes_gcm_decrypt(const u8 *cypher, size_t cypher_len, u8 **plain, size_t *plain_len, const u8 *key, size_t key_len);

int create_random_bytes(size_t len, u8 **out);

int hex_to_u8(const char *hex, u8 **out, size_t *outlen);

const char *get_action_policy_name(unsigned int type);

const char *get_cose_algorithm_name(unsigned int alg);

void printBits(unsigned char byte);

#endif // FIDO_COMMON_H
