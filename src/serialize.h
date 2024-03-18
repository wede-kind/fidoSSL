#ifndef SERIALIZE_H
#define SERIALIZE_H

#include <stddef.h>
#include <openssl/bio.h>
#include "types.h"

int cbor_build(const void *input, enum packet_type type, const u8 **out_buf, size_t *out_len);

int cbor_parse(const u8 *in_buf, size_t in_len, enum packet_type *type, void *out);

#endif // SERIALIZE_H
