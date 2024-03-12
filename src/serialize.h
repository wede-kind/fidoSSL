#ifndef SERIALIZE_H
#define SERIALIZE_H

#include <stddef.h>
#include <openssl/bio.h>
#include "types.h"

struct cbor_values {

    enum packet_type type;

    u8 *challenge;
    size_t challenge_len;
    char *rp_id;
    char *rp_name;
    char *user_verification;
    char *clientdata_json;
    u8 *authdata;
    size_t authdata_len;
    u8 *signature;
    size_t signature_len;
    u8 *user_id;
    size_t user_id_len;
    u8 *eph_user_id;
    size_t eph_user_id_len;
    u8 *user_id_key;
    size_t user_id_key_len;
    char *user_name;
    u8 *cred_id;
    size_t cred_id_len;
    int cred_param;
    u8 *enc_user_id;
    size_t enc_user_id_len;
    u8 *enc_user_name;
    size_t enc_user_name_len;
    u8 *att_stmt;
    size_t att_stmt_len;
    u8 *pubkey;
    size_t pubkey_len;
};

int cbor_parse(const u8 *in_buf, size_t in_len, struct cbor_values *out_values);

int cbor_build(const struct cbor_values *in_values, const u8 **out_buf, size_t *out_len);

int build(const void *input, enum packet_type type, const u8 **out_buf, size_t *out_len);

int parse(const u8 *in_buf, size_t in_len, enum packet_type *type, void *out);

void cbor_values_free(struct cbor_values *values);

int cbor_decode_att_obj(const u8 *cbor_data, size_t cbor_data_len, struct fido_data *data);

#endif // SERIALIZE_H
