#include "serialize.h"
#include "common.h"
#include "debug.h"
#include "types.h"
#include <cbor.h>
#include <openssl/crypto.h>

#define CBOR_ATTR_PACKET_TYPE 0
#define CBOR_ATTR_CHALLENGE 1
#define CBOR_ATTR_RP_ID 2
#define CBOR_ATTR_RP_NAME 3
#define CBOR_ATTR_USER_VERIFICATION 4
#define CBOR_ATTR_CLIENT_DATA 5
#define CBOR_ATTR_AUTHENTICATOR_DATA 6
#define CBOR_ATTR_SIGNATURE 7
#define CBOR_ATTR_USER_ID 8
#define CBOR_ATTR_CRED_ID 9
#define CBOR_ATTR_CRED_PARAMS 10
#define CBOR_ATTR_EPH_USER_ID 11
#define CBOR_ATTR_USER_ID_KEY 12
#define CBOR_ATTR_USER_NAME 13
#define CBOR_ATTR_ENC_USER_ID 14
#define CBOR_ATTR_ENC_USER_NAME 15
#define CBOR_ATTR_ATT_STMT 16
#define CBOR_ATTR_PUBKEY 17

#define TIMEOUT 1
#define AUTH_SEL_ATTACHMENT 2
#define AUTH_SEL_RESIDENT_KEY 3
#define AUTH_SEL_USER_VERIFICATION 4
#define EXCLUDE_CREDS 5
#define RPID 2
#define USER_VERIFICATION 3

const char *get_package_type_name(unsigned int type) {
    switch (type) {
    case FIDO_PRE_REG_INDICATION:
        return "PRE_REG_INDICATION";
    case FIDO_PRE_REG_REQUEST:
        return "PRE_REG_REQUEST";
    case FIDO_PRE_REG_RESPONSE:
        return "PRE_REG_RESPONSE";
    case FIDO_REG_INDICATION:
        return "REG_INDICATION";
    case FIDO_REG_REQUEST:
        return "REG_REQUEST";
    case FIDO_REG_RESPONSE:
        return "REG_RESPONSE";
    case FIDO_AUTH_INDICATION:
        return "AUTH_INDICATION";
    case FIDO_AUTH_REQUEST:
        return "AUTH_REQUEST";
    case FIDO_AUTH_RESPONSE:
        return "AUTH_RESPONSE";
    default:
        return "Unknown Type";
    }
}

int cbor_parse(const u8 *in_buf, size_t in_len,
               struct cbor_values *out_values) {
    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Trace %s", __func__);
    CborParser parser;
    CborValue value;
    CborValue map_value;
    CborError err;
    size_t len;
    memset(out_values, 0, sizeof(*out_values));

    if (in_len <= 0) {
        debug_printf(DEBUG_LEVEL_ERROR,
                     "Could not extract data from BIO object");
        return -1;
    }

    err = cbor_parser_init(in_buf, in_len, 0, &parser, &value);
    if (err != CborNoError) {
        debug_printf(DEBUG_LEVEL_ERROR, "Error initializing CBOR parser");
        return -1;
    }
    if (!cbor_value_is_map(&value)) {
        debug_printf(DEBUG_LEVEL_ERROR, "CBOR Payload was not a map");
        return -1;
    }
    err = cbor_value_enter_container(&value, &map_value);
    if (err != CborNoError) {
        debug_printf(DEBUG_LEVEL_ERROR, "Cbor parsing error");
        return -1;
    }

    int map_key;
    while (!cbor_value_at_end(&map_value)) {
        if (!cbor_value_is_integer(&map_value)) {
            debug_printf(DEBUG_LEVEL_ERROR, "Map key was not an integer");
            return -1;
        }
        err = cbor_value_get_int_checked(&map_value, &map_key);
        if (err != CborNoError) {
            debug_printf(DEBUG_LEVEL_ERROR, "Map key get int failed");
            return -1;
        }
        err = cbor_value_advance(&map_value);
        if (err != CborNoError) {
            debug_printf(DEBUG_LEVEL_ERROR, "Advancing failed");
            return -1;
        }
        switch (map_key) {
        case CBOR_ATTR_PACKET_TYPE:
            if (out_values->type != 0) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Already seen the packet type attribute");
                return -1;
            }
            if (!cbor_value_is_integer(&map_value)) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Packet type value is not an integer");
                return -1;
            }
            int packet_type;
            err = cbor_value_get_int_checked(&map_value, &packet_type);
            if (err != CborNoError) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Could not get packet type value");
                return -1;
            }
            out_values->type = (enum packet_type)packet_type;
            debug_printf(DEBUG_LEVEL_VERBOSE, "Received packet: %s",
                         get_package_type_name(out_values->type));
            break;
        case CBOR_ATTR_CHALLENGE:
            if (out_values->challenge) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Already seen the challenge attribute");
                return -1;
            }
            if (!cbor_value_is_byte_string(&map_value)) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Challenge value is not a byte string");
                return -1;
            }
            err = cbor_value_calculate_string_length(
                &map_value, &out_values->challenge_len);
            if (err != CborNoError) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Could not calculate length of challenge");
                return -1;
            }
            out_values->challenge = OPENSSL_zalloc(out_values->challenge_len);
            err = cbor_value_copy_byte_string(&map_value, out_values->challenge,
                                              &out_values->challenge_len, NULL);
            if (err != CborNoError) {
                debug_printf(DEBUG_LEVEL_ERROR, "Could not copy challenge");
                return -1;
            }
            debug_print_hex(DEBUG_LEVEL_VERBOSE,
                            "    challenge: ", out_values->challenge,
                            out_values->challenge_len);
            break;
        case CBOR_ATTR_RP_ID:
            if (out_values->rp_id) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Already seen the RPID attribute");
                return -1;
            }
            if (!cbor_value_is_text_string(&map_value)) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "RPID value is not a text string");
                return -1;
            }
            err = cbor_value_calculate_string_length(&map_value, &len);
            if (err != CborNoError) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Could not calculate length of RPID");
                return -1;
            }
            out_values->rp_id =
                OPENSSL_zalloc(len + 1); // +1 for null terminator
            err = cbor_value_copy_text_string(&map_value, out_values->rp_id,
                                              &len, NULL);
            if (err != CborNoError) {
                debug_printf(DEBUG_LEVEL_ERROR, "Could not copy RPID");
                return -1;
            }
            debug_printf(DEBUG_LEVEL_VERBOSE, "    rp id: %s",
                         out_values->rp_id);
            break;
        case CBOR_ATTR_RP_NAME:
            if (out_values->rp_name) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Already seen the RP name attribute");
                return -1;
            }
            if (!cbor_value_is_text_string(&map_value)) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "RP name value is not a text string");
                return -1;
            }
            err = cbor_value_calculate_string_length(&map_value, &len);
            if (err != CborNoError) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Could not calculate length of RP name");
                return -1;
            }
            out_values->rp_name =
                OPENSSL_zalloc(len + 1); // +1 for null terminator
            err = cbor_value_copy_text_string(&map_value, out_values->rp_name,
                                              &len, NULL);
            if (err != CborNoError) {
                debug_printf(DEBUG_LEVEL_ERROR, "Could not copy RP name");
                return -1;
            }
            debug_printf(DEBUG_LEVEL_VERBOSE, "    rp name: %s",
                         out_values->rp_name);
            break;
        case CBOR_ATTR_USER_VERIFICATION:
            if (out_values->user_verification) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Already seen the user verification attribute");
                return -1;
            }
            if (!cbor_value_is_text_string(&map_value)) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "User verification value is not a text string");
                return -1;
            }
            err = cbor_value_calculate_string_length(&map_value, &len);
            if (err != CborNoError) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Could not calculate length of user verification");
                return -1;
            }
            out_values->user_verification =
                OPENSSL_zalloc(len + 1); // +1 for null terminator
            err = cbor_value_copy_text_string(
                &map_value, out_values->user_verification, &len, NULL);
            if (err != CborNoError) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Could not copy user verification");
                return -1;
            }
            debug_printf(DEBUG_LEVEL_VERBOSE, "    user verification: %s",
                         out_values->user_verification);
            break;
        case CBOR_ATTR_CLIENT_DATA:
            if (out_values->clientdata_json) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Already seen the client data attribute");
                return -1;
            }
            if (!cbor_value_is_text_string(&map_value)) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Client data value is not a byte string");
                return -1;
            }
            err = cbor_value_calculate_string_length(&map_value, &len);
            if (err != CborNoError) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Could not calculate length of client data");
                return -1;
            }
            out_values->clientdata_json =
                OPENSSL_zalloc(len + 1); // +1 for null terminator
            err = cbor_value_copy_text_string(
                &map_value, out_values->clientdata_json, &len, NULL);
            if (err != CborNoError) {
                debug_printf(DEBUG_LEVEL_ERROR, "Could not copy client data");
                return -1;
            }
            debug_printf(DEBUG_LEVEL_VERBOSE, "    clientdata: %s",
                         out_values->clientdata_json);
            break;
        case CBOR_ATTR_AUTHENTICATOR_DATA:
            if (out_values->authdata) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Already seen the authdata attribute");
                return -1;
            }
            if (!cbor_value_is_byte_string(&map_value)) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Authdata value is not a byte string");
                return -1;
            }
            err = cbor_value_calculate_string_length(&map_value,
                                                     &out_values->authdata_len);
            if (err != CborNoError) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Could not calculate length of authdata");
                return -1;
            }
            out_values->authdata = OPENSSL_zalloc(out_values->authdata_len);
            err = cbor_value_copy_byte_string(&map_value, out_values->authdata,
                                              &out_values->authdata_len, NULL);
            if (err != CborNoError) {
                debug_printf(DEBUG_LEVEL_ERROR, "Could not copy authdata");
                return -1;
            }
            debug_print_hex(DEBUG_LEVEL_VERBOSE,
                            "    authdata: ", out_values->authdata,
                            out_values->authdata_len);
            break;
        case CBOR_ATTR_SIGNATURE:
            if (out_values->signature) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Already seen the signature attribute");
                return -1;
            }
            if (!cbor_value_is_byte_string(&map_value)) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Signature value is not a byte string");
                return -1;
            }
            err = cbor_value_calculate_string_length(
                &map_value, &out_values->signature_len);
            if (err != CborNoError) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Could not calculate length of signature");
                return -1;
            }
            out_values->signature = OPENSSL_zalloc(out_values->signature_len);
            err = cbor_value_copy_byte_string(&map_value, out_values->signature,
                                              &out_values->signature_len, NULL);
            if (err != CborNoError) {
                debug_printf(DEBUG_LEVEL_ERROR, "Could not copy signature");
                return -1;
            }
            debug_print_hex(DEBUG_LEVEL_VERBOSE,
                            "    signature: ", out_values->signature,
                            out_values->signature_len);
            break;
        case CBOR_ATTR_USER_ID:
            if (out_values->user_id) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Already seen the user id attribute");
                return -1;
            }
            if (!cbor_value_is_byte_string(&map_value)) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "User id value is not a byte string");
                return -1;
            }
            err = cbor_value_calculate_string_length(&map_value,
                                                     &out_values->user_id_len);
            if (err != CborNoError) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Could not calculate length of user id");
                return -1;
            }
            out_values->user_id = OPENSSL_zalloc(out_values->user_id_len);
            err = cbor_value_copy_byte_string(&map_value, out_values->user_id,
                                              &out_values->user_id_len, NULL);
            if (err != CborNoError) {
                debug_printf(DEBUG_LEVEL_ERROR, "Could not copy user id");
                return -1;
            }
            debug_print_hex(DEBUG_LEVEL_VERBOSE,
                            "    user id: ", out_values->user_id,
                            out_values->user_id_len);
            break;
        case CBOR_ATTR_CRED_ID:
            if (out_values->cred_id) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Already seen the cred id attribute");
                return -1;
            }
            if (!cbor_value_is_byte_string(&map_value)) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Cred id value is not a byte string");
                return -1;
            }
            err = cbor_value_calculate_string_length(&map_value,
                                                     &out_values->cred_id_len);
            if (err != CborNoError) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Could not calculate length of cred id");
                return -1;
            }
            out_values->cred_id = OPENSSL_zalloc(out_values->cred_id_len);
            err = cbor_value_copy_byte_string(&map_value, out_values->cred_id,
                                              &out_values->cred_id_len, NULL);
            if (err != CborNoError) {
                debug_printf(DEBUG_LEVEL_ERROR, "Could not copy cred id");
                return -1;
            }
            debug_print_hex(DEBUG_LEVEL_VERBOSE,
                            "    cred id: ", out_values->cred_id,
                            out_values->cred_id_len);
            break;
        case CBOR_ATTR_CRED_PARAMS:
            if (out_values->cred_param != 0) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Already seen the cred params attribute");
                return -1;
            }
            if (!cbor_value_is_integer(&map_value)) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Cred params value is not an integer");
                return -1;
            }
            err =
                cbor_value_get_int_checked(&map_value, &out_values->cred_param);
            if (err != CborNoError) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Could not get cred params value");
                return -1;
            }
            debug_printf(DEBUG_LEVEL_VERBOSE, "    cred params: %d",
                         out_values->cred_param);
            break;
        case CBOR_ATTR_EPH_USER_ID:
            if (out_values->eph_user_id) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Already seen the eph user id attribute");
                return -1;
            }
            if (!cbor_value_is_byte_string(&map_value)) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Eph user id value is not a byte string");
                return -1;
            }
            err = cbor_value_calculate_string_length(
                &map_value, &out_values->eph_user_id_len);
            if (err != CborNoError) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Could not calculate length of eph user id");
                return -1;
            }
            out_values->eph_user_id =
                OPENSSL_zalloc(out_values->eph_user_id_len);
            err =
                cbor_value_copy_byte_string(&map_value, out_values->eph_user_id,
                                            &out_values->eph_user_id_len, NULL);
            if (err != CborNoError) {
                debug_printf(DEBUG_LEVEL_ERROR, "Could not copy eph user id");
                return -1;
            }
            debug_print_hex(DEBUG_LEVEL_VERBOSE,
                            "    eph user id: ", out_values->eph_user_id,
                            out_values->eph_user_id_len);
            break;
        case CBOR_ATTR_USER_ID_KEY:
            if (out_values->user_id_key) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Already seen the user id key attribute");
                return -1;
            }
            if (!cbor_value_is_byte_string(&map_value)) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "User id key value is not a byte string");
                return -1;
            }
            err = cbor_value_calculate_string_length(
                &map_value, &out_values->user_id_key_len);
            if (err != CborNoError) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Could not calculate length of user id key");
                return -1;
            }
            out_values->user_id_key =
                OPENSSL_zalloc(out_values->user_id_key_len);
            err =
                cbor_value_copy_byte_string(&map_value, out_values->user_id_key,
                                            &out_values->user_id_key_len, NULL);
            if (err != CborNoError) {
                debug_printf(DEBUG_LEVEL_ERROR, "Could not copy user id key");
                return -1;
            }
            debug_print_hex(DEBUG_LEVEL_VERBOSE,
                            "    user id key: ", out_values->user_id_key,
                            out_values->user_id_key_len);
            break;
        case CBOR_ATTR_USER_NAME:
            if (out_values->user_name) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Already seen the user name attribute");
                return -1;
            }
            if (!cbor_value_is_text_string(&map_value)) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "User name value is not a text string");
                return -1;
            }
            err = cbor_value_calculate_string_length(&map_value, &len);
            if (err != CborNoError) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Could not calculate length of user name");
                return -1;
            }
            out_values->user_name =
                OPENSSL_zalloc(len + 1); // +1 for null terminator
            err = cbor_value_copy_text_string(&map_value, out_values->user_name,
                                              &len, NULL);
            if (err != CborNoError) {
                debug_printf(DEBUG_LEVEL_ERROR, "Could not copy user name");
                return -1;
            }
            debug_printf(DEBUG_LEVEL_VERBOSE, "    user name: %s",
                         out_values->user_name);
            break;
        case CBOR_ATTR_ENC_USER_ID:
            if (out_values->enc_user_id) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Already seen the enc user id attribute");
                return -1;
            }
            if (!cbor_value_is_byte_string(&map_value)) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Enc user id value is not a byte string");
                return -1;
            }
            err = cbor_value_calculate_string_length(
                &map_value, &out_values->enc_user_id_len);
            if (err != CborNoError) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Could not calculate length of enc user id");
                return -1;
            }
            out_values->enc_user_id =
                OPENSSL_zalloc(out_values->enc_user_id_len);
            err =
                cbor_value_copy_byte_string(&map_value, out_values->enc_user_id,
                                            &out_values->enc_user_id_len, NULL);
            if (err != CborNoError) {
                debug_printf(DEBUG_LEVEL_ERROR, "Could not copy enc user id");
                return -1;
            }
            debug_print_hex(DEBUG_LEVEL_VERBOSE,
                            "    enc user id: ", out_values->enc_user_id,
                            out_values->enc_user_id_len);
            break;
        case CBOR_ATTR_ENC_USER_NAME:
            if (out_values->enc_user_name) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Already seen the enc user name attribute");
                return -1;
            }
            if (!cbor_value_is_byte_string(&map_value)) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Enc user name value is not a byte string");
                return -1;
            }
            err = cbor_value_calculate_string_length(
                &map_value, &out_values->enc_user_name_len);
            if (err != CborNoError) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Could not calculate length of enc user name");
                return -1;
            }
            out_values->enc_user_name =
                OPENSSL_zalloc(out_values->enc_user_name_len);
            err = cbor_value_copy_byte_string(
                &map_value, out_values->enc_user_name,
                &out_values->enc_user_name_len, NULL);
            if (err != CborNoError) {
                debug_printf(DEBUG_LEVEL_ERROR, "Could not copy enc user name");
                return -1;
            }
            debug_print_hex(DEBUG_LEVEL_VERBOSE,
                            "    enc user name: ", out_values->enc_user_name,
                            out_values->enc_user_name_len);
            break;
        case CBOR_ATTR_ATT_STMT:
            if (out_values->att_stmt) {
                debug_printf(
                    DEBUG_LEVEL_ERROR,
                    "Already seen the attestation statement attribute");
                return -1;
            }
            if (!cbor_value_is_byte_string(&map_value)) {
                debug_printf(
                    DEBUG_LEVEL_ERROR,
                    "Attestation statement value is not a byte string");
                return -1;
            }
            err = cbor_value_calculate_string_length(&map_value,
                                                     &out_values->att_stmt_len);
            if (err != CborNoError) {
                debug_printf(
                    DEBUG_LEVEL_ERROR,
                    "Could not calculate length of attestation statement");
                return -1;
            }
            out_values->att_stmt = OPENSSL_zalloc(out_values->att_stmt_len);
            err = cbor_value_copy_byte_string(&map_value, out_values->att_stmt,
                                              &out_values->att_stmt_len, NULL);
            if (err != CborNoError) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Could not copy attestation statement");
                return -1;
            }
            debug_print_hex(DEBUG_LEVEL_VERBOSE,
                            "    attestation statement: ", out_values->att_stmt,
                            out_values->att_stmt_len);
            break;
        case CBOR_ATTR_PUBKEY:
            if (out_values->pubkey) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Already seen the pubkey attribute");
                return -1;
            }
            if (!cbor_value_is_byte_string(&map_value)) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Pubkey value is not a byte string");
                return -1;
            }
            err = cbor_value_calculate_string_length(&map_value,
                                                     &out_values->pubkey_len);
            if (err != CborNoError) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Could not calculate length of pubkey");
                return -1;
            }
            out_values->pubkey = OPENSSL_zalloc(out_values->pubkey_len);
            err = cbor_value_copy_byte_string(&map_value, out_values->pubkey,
                                              &out_values->pubkey_len, NULL);
            if (err != CborNoError) {
                debug_printf(DEBUG_LEVEL_ERROR, "Could not copy pubkey");
                return -1;
            }
            debug_print_hex(DEBUG_LEVEL_VERBOSE,
                            "    pubkey: ", out_values->pubkey,
                            out_values->pubkey_len);
            break;
        }

        err = cbor_value_advance(&map_value);
        if (err != CborNoError) {
            debug_printf(DEBUG_LEVEL_ERROR, "Advancing failed");
            return -1;
        }
    }
    return 0;
}

int parse(const u8 *in_buf, size_t in_len, enum packet_type *type, void *out) {
    CborParser parser;
    CborValue root, it, sub_it, map_it;
    CborError err;
    size_t len, array_len;
    if (in_len <= 0) {
        debug_printf(DEBUG_LEVEL_ERROR, "No data to parse");
        return -1;
    }
    err = cbor_parser_init(in_buf, in_len, 0, &parser, &root);
    if (err != CborNoError) {
        debug_printf(DEBUG_LEVEL_ERROR, "Error initializing CBOR parser");
        goto err;
    }
    if (!cbor_value_is_array(&root)) {
        debug_printf(DEBUG_LEVEL_ERROR, "Root container is not an array\n");
        return -1;
    }
    cbor_value_get_array_length(&root, &array_len);
    cbor_value_enter_container(&root, &it);
    if (!cbor_value_is_integer(&it)) {
        debug_printf(DEBUG_LEVEL_ERROR, "Packet type is not an integer");
        goto err;
    }
    int packet_type;
    cbor_value_get_int_checked(&it, &packet_type);
    // If the caller does not specify the expected packet type, we accept any
    // packet type and return the actual packet type in the type parameter
    if (*type == UNDEFINED) {
        *type = packet_type;
    } else if (packet_type != *type) {
        debug_printf(DEBUG_LEVEL_ERROR,
                     "Received packet type: %d, expected: %d", packet_type,
                     *type);
        goto err;
    }
    debug_printf(DEBUG_LEVEL_VERBOSE, "Received packet: %s",
                 get_package_type_name(*type));
    switch (*type) {
    case FIDO_PRE_REG_INDICATION: {
        out = NULL;
        break;
    }
    case FIDO_PRE_REG_REQUEST: {
        if (array_len < 3) {
            debug_printf(DEBUG_LEVEL_ERROR, "Malformed pre-reg request");
            goto err;
        }
        struct pre_reg_request *p = (struct pre_reg_request *)out;
        if (!p) {
            debug_printf(DEBUG_LEVEL_ERROR, "Memory allocation failed");
            goto err;
        }
        cbor_value_advance(&it);
        if (!cbor_value_is_byte_string(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR,
                         "Ephemeral user id is not a byte string");
            goto err;
        }
        cbor_value_calculate_string_length(&it, &p->eph_user_id_len);
        p->eph_user_id = OPENSSL_zalloc(p->eph_user_id_len);
        cbor_value_copy_byte_string(&it, p->eph_user_id, &p->eph_user_id_len,
                                    &it);
        debug_print_hex(DEBUG_LEVEL_VERBOSE,
                        "    eph user id: ", p->eph_user_id,
                        p->eph_user_id_len);
        if (!cbor_value_is_byte_string(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR, "GCM key is not a byte string");
            goto err;
        }
        cbor_value_calculate_string_length(&it, &p->gcm_key_len);
        p->gcm_key = OPENSSL_zalloc(p->gcm_key_len);
        cbor_value_copy_byte_string(&it, p->gcm_key, &p->gcm_key_len, &it);
        debug_print_hex(DEBUG_LEVEL_VERBOSE, "    gcm key: ", p->gcm_key,
                        p->gcm_key_len);
        break;
    }
    case FIDO_PRE_REG_RESPONSE: {
        if (array_len < 4) {
            debug_printf(DEBUG_LEVEL_ERROR, "Malformed pre-reg response");
            goto err;
        }
        struct pre_reg_response *p = (struct pre_reg_response *)out;
        if (!p) {
            debug_printf(DEBUG_LEVEL_ERROR, "Memory allocation failed!");
            goto err;
        }
        cbor_value_advance(&it);
        if (!cbor_value_is_text_string(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR,
                         "User name value is not a text string");
            goto err;
        }
        cbor_value_calculate_string_length(&it, &len);
        p->user_name = OPENSSL_zalloc(len + 1); // +1 for null terminator
        cbor_value_copy_text_string(&it, p->user_name, &len, &it);
        debug_printf(DEBUG_LEVEL_VERBOSE, "    user name: %s", p->user_name);
        if (!cbor_value_is_text_string(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR,
                         "User display name value is not a text string");
            goto err;
        }
        cbor_value_calculate_string_length(&it, &len);
        p->user_display_name =
            OPENSSL_zalloc(len + 1); // +1 for null terminator
        cbor_value_copy_text_string(&it, p->user_display_name, &len, &it);
        debug_printf(DEBUG_LEVEL_VERBOSE, "    user display name: %s",
                     p->user_display_name);
        if (!cbor_value_is_byte_string(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR, "Ticket is not a byte string");
            goto err;
        }
        cbor_value_calculate_string_length(&it, &p->ticket_len);
        p->ticket = OPENSSL_zalloc(p->ticket_len);
        cbor_value_copy_byte_string(&it, p->ticket, &p->ticket_len, &it);
        debug_print_hex(DEBUG_LEVEL_VERBOSE, "    ticket: ", p->ticket,
                        p->ticket_len);
        break;
    }
    case FIDO_REG_INDICATION: {
        if (array_len < 1) {
            debug_printf(DEBUG_LEVEL_ERROR, "Malformed reg indication");
            goto err;
        }
        struct reg_indication *p = (struct reg_indication *)out;
        if (!p) {
            debug_printf(DEBUG_LEVEL_ERROR, "Memory allocation failed!");
            goto err;
        }
        cbor_value_advance(&it);
        if (!cbor_value_is_byte_string(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR,
                         "Ephemeral user id is not a byte string");
            goto err;
        }
        cbor_value_calculate_string_length(&it, &p->eph_user_id_len);
        p->eph_user_id = OPENSSL_zalloc(p->eph_user_id_len);
        cbor_value_copy_byte_string(&it, p->eph_user_id, &p->eph_user_id_len,
                                    &it);
        debug_print_hex(DEBUG_LEVEL_VERBOSE,
                        "    eph user id: ", p->eph_user_id,
                        p->eph_user_id_len);
        break;
    }
    case FIDO_REG_REQUEST: {
        if (array_len < 8) {
            debug_printf(DEBUG_LEVEL_ERROR, "Malformed reg request");
            goto err;
        }
        struct reg_request *p = (struct reg_request *)out;
        if (!p) {
            debug_printf(DEBUG_LEVEL_ERROR, "Memory allocation failed!");
            goto err;
        }
        cbor_value_advance(&it);
        if (!cbor_value_is_byte_string(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR, "Challenge is not a byte string");
            goto err;
        }
        cbor_value_calculate_string_length(&it, &p->challenge_len);
        p->challenge = OPENSSL_zalloc(p->challenge_len);
        cbor_value_copy_byte_string(&it, p->challenge, &p->challenge_len, &it);
        debug_print_hex(DEBUG_LEVEL_VERBOSE, "    challenge: ", p->challenge,
                        p->challenge_len);
        if (!cbor_value_is_text_string(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR, "RP ID is not a text string");
            goto err;
        }
        cbor_value_calculate_string_length(&it, &len);
        p->rp_id = OPENSSL_zalloc(len + 1); // +1 for null terminator
        cbor_value_copy_text_string(&it, p->rp_id, &len, &it);
        debug_printf(DEBUG_LEVEL_VERBOSE, "    rp id: %s", p->rp_id);
        if (!cbor_value_is_text_string(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR, "RP name is not a text string");
            goto err;
        }
        cbor_value_calculate_string_length(&it, &len);
        p->rp_name = OPENSSL_zalloc(len + 1); // +1 for null terminator
        cbor_value_copy_text_string(&it, p->rp_name, &len, &it);
        debug_printf(DEBUG_LEVEL_VERBOSE, "    rp name: %s", p->rp_name);
        if (!cbor_value_is_byte_string(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR,
                         "GCM user name is not a byte string");
            goto err;
        }
        cbor_value_calculate_string_length(&it, &p->gcm_user_name_len);
        p->gcm_user_name = OPENSSL_zalloc(p->gcm_user_name_len);
        cbor_value_copy_byte_string(&it, p->gcm_user_name,
                                    &p->gcm_user_name_len, &it);
        debug_print_hex(DEBUG_LEVEL_VERBOSE,
                        "    gcm user name: ", p->gcm_user_name,
                        p->gcm_user_name_len);
        if (!cbor_value_is_byte_string(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR,
                         "GCM user display name is not a byte string");
            goto err;
        }
        cbor_value_calculate_string_length(&it, &p->gcm_user_display_name_len);
        p->gcm_user_display_name = OPENSSL_zalloc(p->gcm_user_display_name_len);
        cbor_value_copy_byte_string(&it, p->gcm_user_display_name,
                                    &p->gcm_user_display_name_len, &it);
        debug_print_hex(DEBUG_LEVEL_VERBOSE,
                        "    gcm user display name: ", p->gcm_user_display_name,
                        p->gcm_user_display_name_len);
        if (!cbor_value_is_byte_string(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR, "GCM user id is not a byte string");
            goto err;
        }
        cbor_value_calculate_string_length(&it, &p->gcm_user_id_len);
        p->gcm_user_id = OPENSSL_zalloc(p->gcm_user_id_len);
        cbor_value_copy_byte_string(&it, p->gcm_user_id, &p->gcm_user_id_len,
                                    &it);
        debug_print_hex(DEBUG_LEVEL_VERBOSE,
                        "    gcm user id: ", p->gcm_user_id,
                        p->gcm_user_id_len);
        if (!cbor_value_is_array(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR,
                         "Pubkey cred params is not an array");
            goto err;
        }
        cbor_value_get_array_length(&it, &p->pubkey_cred_params_len);
        p->pubkey_cred_params =
            OPENSSL_zalloc(p->pubkey_cred_params_len * sizeof(int));
        if (p->pubkey_cred_params_len < 1) {
            debug_printf(DEBUG_LEVEL_ERROR,
                         "Pubkey cred params array is empty");
            goto err;
        }
        cbor_value_enter_container(&it, &sub_it);
        debug_printf(DEBUG_LEVEL_VERBOSE, "    pubkey cred params:");
        for (size_t i = 0; i < p->pubkey_cred_params_len; i++) {
            if (!cbor_value_is_integer(&sub_it)) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "Pubkey cred params value is not an integer");
                goto err;
            }
            cbor_value_get_int_checked(&sub_it, &p->pubkey_cred_params[i]);
            cbor_value_advance(&sub_it);
            debug_printf(DEBUG_LEVEL_VERBOSE, "        %s",
                         get_cose_algorithm_name(p->pubkey_cred_params[i]));
        }
        // leave the sub container
        err = cbor_value_leave_container(&it, &sub_it);
        if (err != CborNoError) {
            debug_printf(DEBUG_LEVEL_ERROR, "Leaving sub container failed");
            goto err;
        }
        if (cbor_value_at_end(&it)) {
            break;
        }
        // Optional values
        if (!cbor_value_is_map(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR,
                         "Expected a map container for optional values");
            goto err;
        }
        cbor_value_enter_container(&it, &map_it);
        while (!cbor_value_at_end(&map_it)) {
            int key;
            if (!cbor_value_is_integer(&map_it)) {
                debug_printf(DEBUG_LEVEL_ERROR, "Map key is not an integer");
                goto err;
            }
            cbor_value_get_int_checked(&map_it, &key);
            cbor_value_advance(&map_it);
            switch (key) {
            case TIMEOUT:
                if (!cbor_value_is_integer(&map_it)) {
                    debug_printf(DEBUG_LEVEL_ERROR,
                                 "Timeout is not an integer");
                    goto err;
                }
                cbor_value_get_int_checked(&map_it, &p->timeout);
                debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    timeout: %d ms",
                             p->timeout);
                break;
            case EXCLUDE_CREDS:
                if (!cbor_value_is_array(&map_it)) {
                    debug_printf(DEBUG_LEVEL_ERROR,
                                 "Exclude creds is not an array");
                    goto err;
                }
                cbor_value_get_array_length(&map_it, &p->exclude_creds_len);
                // Divide by 2, because the array contains type and id for each
                // credential
                p->exclude_creds_len /= 2;
                p->exclude_creds = OPENSSL_zalloc(p->exclude_creds_len *
                                                  sizeof(struct credential));
                cbor_value_enter_container(&map_it, &sub_it);
                debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    exclude creds:");
                for (size_t i = 0; i < p->exclude_creds_len; i++) {
                    if (!cbor_value_is_text_string(&sub_it)) {
                        debug_printf(DEBUG_LEVEL_ERROR,
                                     "Exclude cred type is not a text string");
                        goto err;
                    }
                    cbor_value_calculate_string_length(&sub_it, &len);
                    p->exclude_creds[i].type = OPENSSL_zalloc(len + 1);
                    cbor_value_copy_text_string(
                        &sub_it, p->exclude_creds[i].type, &len, &sub_it);
                    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "        type: %s",
                                 p->exclude_creds[i].type);
                    if (!cbor_value_is_byte_string(&sub_it)) {
                        debug_printf(DEBUG_LEVEL_ERROR,
                                     "Exclude cred id is not a byte string");
                        goto err;
                    }
                    cbor_value_calculate_string_length(
                        &sub_it, &p->exclude_creds[i].id_len);
                    p->exclude_creds[i].id =
                        OPENSSL_zalloc(p->exclude_creds[i].id_len);
                    cbor_value_copy_byte_string(&sub_it, p->exclude_creds[i].id,
                                                &p->exclude_creds[i].id_len,
                                                &sub_it);
                    debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE,
                                    "        id: ", p->exclude_creds[i].id,
                                    p->exclude_creds[i].id_len);
                }
                break;
            case AUTH_SEL_ATTACHMENT:
                if (!cbor_value_is_integer(&map_it)) {
                    debug_printf(DEBUG_LEVEL_ERROR,
                                 "Auth selection attachment is not an integer");
                    goto err;
                }
                int attachment;
                cbor_value_get_int_checked(&map_it, &attachment);
                p->auth_sel.attachment = attachment;
                debug_printf(DEBUG_LEVEL_MORE_VERBOSE,
                             "    authenticator attachment: %s",
                             attachment == 0 ? "PLATFORM" : "CROSS-PLATFORM");
                break;
            case AUTH_SEL_RESIDENT_KEY:
                if (!cbor_value_is_integer(&map_it)) {
                    debug_printf(
                        DEBUG_LEVEL_ERROR,
                        "Auth selection resident key is not an integer");
                    goto err;
                }
                int resident_key;
                cbor_value_get_int_checked(&map_it, &resident_key);
                p->auth_sel.resident_key = resident_key;
                debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    resident key: %s",
                             get_action_policy_name(resident_key));
                break;
            case AUTH_SEL_USER_VERIFICATION:
                if (!cbor_value_is_integer(&map_it)) {
                    debug_printf(
                        DEBUG_LEVEL_ERROR,
                        "Auth selection user verification is not an integer");
                    goto err;
                }
                int user_verification;
                cbor_value_get_int_checked(&map_it, &user_verification);
                p->auth_sel.user_verification = user_verification;
                debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    user verification: %s",
                             get_action_policy_name(user_verification));
                break;
            default:
                // We dont error out here, because the fido spec mandates to be
                // graceful with unknown keys, as the spec might be extended in
                // the future.
                debug_printf(DEBUG_LEVEL_VERBOSE, "Unknown map key");
                break;
            }
            cbor_value_advance(&map_it);
        }
        err = cbor_value_leave_container(&it, &map_it);
        if (err != CborNoError) {
            debug_printf(DEBUG_LEVEL_ERROR, "Leaving map container failed");
            goto err;
        }
        break;
    }
    case FIDO_REG_RESPONSE: {
        if (array_len < 2) {
            debug_printf(DEBUG_LEVEL_ERROR, "Malformed reg response");
            goto err;
        }
        struct reg_response *p = (struct reg_response *)out;
        if (!p) {
            debug_printf(DEBUG_LEVEL_ERROR, "Memory allocation failed!");
            goto err;
        }
        cbor_value_advance(&it);
        if (!cbor_value_is_byte_string(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR, "Authdata is not a byte string");
            goto err;
        }
        cbor_value_calculate_string_length(&it, &p->authdata_len);
        p->authdata = OPENSSL_zalloc(p->authdata_len);
        cbor_value_copy_byte_string(&it, p->authdata, &p->authdata_len, &it);
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE, "    authdata: ", p->authdata,
                        p->authdata_len);
        if (!cbor_value_is_text_string(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR, "Clientdata is not a text string");
            goto err;
        }
        cbor_value_calculate_string_length(&it, &len);
        p->clientdata_json = OPENSSL_zalloc(len + 1); // +1 for null terminator
        cbor_value_copy_text_string(&it, p->clientdata_json, &len, &it);
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    clientdata: %s",
                     p->clientdata_json);
        break;
    }
    case FIDO_AUTH_INDICATION: {
        out = NULL;
        break;
    }
    case FIDO_AUTH_REQUEST: {
        struct auth_request *p = (struct auth_request *)out;
        if (!p) {
            debug_printf(DEBUG_LEVEL_ERROR, "Memory allocation failed!");
            goto err;
        }
        err = cbor_value_advance(&it);
        if (err != CborNoError) {
            debug_printf(DEBUG_LEVEL_ERROR, "Advancing failed");
            goto err;
        }
        if (!cbor_value_is_byte_string(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR, "Challenge is not a byte string");
            goto err;
        }
        cbor_value_calculate_string_length(&it, &p->challenge_len);
        p->challenge = OPENSSL_zalloc(p->challenge_len);
        cbor_value_copy_byte_string(&it, p->challenge, &p->challenge_len, &it);
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE, "    challenge: ", p->challenge,
                        p->challenge_len);
        if (cbor_value_at_end(&it)) {
            break;
        }
        // Optional values
        if (!cbor_value_is_map(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR,
                         "Expected a map for optional values");
            goto err;
        }
        cbor_value_enter_container(&it, &map_it);
        while (!cbor_value_at_end(&map_it)) {
            int key;
            if (!cbor_value_is_integer(&map_it)) {
                debug_printf(DEBUG_LEVEL_ERROR, "Map key is not an integer");
                goto err;
            }
            cbor_value_get_int_checked(&map_it, &key);
            cbor_value_advance(&map_it);
            switch (key) {
            case TIMEOUT:
                if (!cbor_value_is_integer(&map_it)) {
                    debug_printf(DEBUG_LEVEL_ERROR,
                                 "Timeout is not an integer");
                    goto err;
                }
                cbor_value_get_int_checked(&map_it, &p->timeout);
                debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    timeout: %d ms",
                             p->timeout);
                cbor_value_advance(&map_it);
                break;
            case RPID:
                if (!cbor_value_is_text_string(&map_it)) {
                    debug_printf(DEBUG_LEVEL_ERROR,
                                 "RP ID is not a text string");
                    goto err;
                }
                cbor_value_calculate_string_length(&map_it, &len);
                p->rp_id = OPENSSL_zalloc(len + 1); // +1 for null terminator
                cbor_value_copy_text_string(&map_it, p->rp_id, &len, &map_it);
                debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    rp id: %s", p->rp_id);
                break;
            case USER_VERIFICATION:
                if (!cbor_value_is_integer(&map_it)) {
                    debug_printf(DEBUG_LEVEL_ERROR,
                                 "User verification is not an integer");
                    goto err;
                }
                int user_verification;
                cbor_value_get_int_checked(&map_it, &user_verification);
                p->user_verification = user_verification;
                debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    user verification: %s",
                             get_action_policy_name(user_verification));
                cbor_value_advance(&map_it);
                break;
            }
        }
        break;
    }
    case FIDO_AUTH_RESPONSE: {
        struct auth_response *p = (struct auth_response *)out;
        if (!p) {
            debug_printf(DEBUG_LEVEL_ERROR, "Memory allocation failed!");
            goto err;
        }
        err = cbor_value_advance(&it);
        if (err != CborNoError) {
            debug_printf(DEBUG_LEVEL_ERROR, "Advancing failed");
            goto err;
        }
        if (!cbor_value_is_text_string(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR, "Clientdata is not a text string");
            goto err;
        }
        cbor_value_calculate_string_length(&it, &len);
        p->clientdata_json = OPENSSL_zalloc(len + 1); // +1 for null terminator
        cbor_value_copy_text_string(&it, p->clientdata_json, &len, &it);
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    clientdata: %s",
                     p->clientdata_json);
        if (!cbor_value_is_byte_string(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR,
                         "Authenticator data is not a byte string");
            goto err;
        }
        cbor_value_calculate_string_length(&it, &p->authdata_len);
        p->authdata = OPENSSL_zalloc(p->authdata_len);
        cbor_value_copy_byte_string(&it, p->authdata, &p->authdata_len, &it);
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE,
                        "    authenticator data: ", p->authdata,
                        p->authdata_len);
        if (!cbor_value_is_byte_string(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR, "Signature is not a byte string");
            goto err;
        }
        cbor_value_calculate_string_length(&it, &p->signature_len);
        p->signature = OPENSSL_zalloc(p->signature_len);
        cbor_value_copy_byte_string(&it, p->signature, &p->signature_len, &it);
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE, "    signature: ", p->signature,
                        p->signature_len);
        if (!cbor_value_is_byte_string(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR, "User id is not a byte string");
            goto err;
        }
        cbor_value_calculate_string_length(&it, &p->user_id_len);
        p->user_id = OPENSSL_zalloc(p->user_id_len);
        cbor_value_copy_byte_string(&it, p->user_id, &p->user_id_len, &it);
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE, "    user id: ", p->user_id,
                        p->user_id_len);
        if (!cbor_value_is_byte_string(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR, "Cred id is not a byte string");
            goto err;
        }
        cbor_value_calculate_string_length(&it, &p->cred_id_len);
        p->cred_id = OPENSSL_zalloc(p->cred_id_len);
        cbor_value_copy_byte_string(&it, p->cred_id, &p->cred_id_len, &it);
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE, "    cred id: ", p->cred_id,
                        p->cred_id_len);
        break;
    }
    default:
        debug_printf(DEBUG_LEVEL_ERROR, "Unknown packet type");
        goto err;
    }
    return 0;
err:
    // TODO cleanup
    return -1;
}

int build(const void *input, enum packet_type type, const u8 **out_buf,
          size_t *out_len) {
    assert(type != UNDEFINED);

    // TODO: make this a constant, mention it in thesis that is is theoreticaly
    // constaint by the TLS record size.
    u8 *buf = OPENSSL_zalloc(1500);
    if (!buf) {
        debug_printf(DEBUG_LEVEL_ERROR,
                     "Could not allocate memory for CBOR encoding");
        return -1;
    }
    CborEncoder encoder, array, sub_array, map;
    cbor_encoder_init(&encoder, buf, 1500, 0);
    CborError err;

    debug_printf(DEBUG_LEVEL_VERBOSE, "Sending packet: %s",
                 get_package_type_name(type));
    switch (type) {
    case FIDO_PRE_REG_INDICATION: {
        // Encode just the packet type
        cbor_encoder_create_array(&encoder, &array, 1);
        cbor_encode_int(&array, FIDO_PRE_REG_INDICATION);
        break;
    }
    case FIDO_PRE_REG_REQUEST: {
        struct pre_reg_request *in = (struct pre_reg_request *)input;
        assert(in->eph_user_id != NULL && in->eph_user_id_len != 0 &&
               in->gcm_key != NULL && in->gcm_key_len != 0);
        // Required fields are packet type, eph_user_id and gcm_key
        cbor_encoder_create_array(&encoder, &array, 3);
        cbor_encode_int(&array, FIDO_PRE_REG_REQUEST);
        cbor_encode_byte_string(&array, in->eph_user_id, in->eph_user_id_len);
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE,
                        "    eph user id: ", in->eph_user_id,
                        in->eph_user_id_len);
        cbor_encode_byte_string(&array, in->gcm_key, in->gcm_key_len);
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE, "    gcm key: ", in->gcm_key,
                        in->gcm_key_len);
        break;
    }
    case FIDO_PRE_REG_RESPONSE: {
        struct pre_reg_response *in = (struct pre_reg_response *)input;
        assert(in->user_name != NULL && in->user_display_name != NULL &&
               in->ticket != NULL && in->ticket_len != 0);
        // Required fields are packet type, user_name, user_display_name and
        // ticket
        cbor_encoder_create_array(&encoder, &array, 4);
        cbor_encode_int(&array, FIDO_PRE_REG_RESPONSE);
        cbor_encode_text_stringz(&array, in->user_name);
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    user name: %s", in->user_name);
        cbor_encode_text_stringz(&array, in->user_display_name);
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    user display name: %s",
                     in->user_display_name);
        cbor_encode_byte_string(&array, in->ticket, in->ticket_len);
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE, "    ticket: ", in->ticket, in->ticket_len);
        break;
    }
    case FIDO_REG_INDICATION: {
        struct reg_indication *in = (struct reg_indication *)input;
        assert(in->eph_user_id != NULL && in->eph_user_id_len != 0);
        // Required fields are packet type and eph_user_id
        cbor_encoder_create_array(&encoder, &array, 2);
        cbor_encode_int(&array, FIDO_REG_INDICATION);
        cbor_encode_byte_string(&array, in->eph_user_id, in->eph_user_id_len);
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE,
                        "    eph user id: ", in->eph_user_id,
                        in->eph_user_id_len);
        break;
    }
    case FIDO_REG_REQUEST: {
        struct reg_request *in = (struct reg_request *)input;
        assert(in->challenge != NULL && in->challenge_len > 0 &&
               in->rp_id != NULL && in->rp_name != NULL &&
               in->gcm_user_name != NULL && in->gcm_user_name_len != 0 &&
               in->gcm_user_display_name != NULL &&
               in->gcm_user_display_name_len != 0 && in->gcm_user_id != NULL &&
               in->gcm_user_id_len != 0 && in->pubkey_cred_params != NULL &&
               in->pubkey_cred_params_len != 0);
        // Count optional parameters
        size_t num_optionals = 0;
        if (in->timeout != 0)
            ++num_optionals;
        if (in->exclude_creds_len != 0)
            ++num_optionals;
        if (in->auth_sel.attachment != 0)
            ++num_optionals;
        if (in->auth_sel.resident_key != 0)
            ++num_optionals;
        if (in->auth_sel.user_verification != 0)
            ++num_optionals;

        // Required fields are packet type, challenge, rp_id, rp_name,
        // gcm_user_name, gcm_user_display_name, gcm_user_id and
        // pubkey_cred_params. If there are optional parameters, the last field
        // of the arrays is a map
        cbor_encoder_create_array(&encoder, &array, num_optionals > 0 ? 9 : 8);
        cbor_encode_int(&array, FIDO_REG_REQUEST);
        cbor_encode_byte_string(&array, in->challenge, in->challenge_len);
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE, "    challenge: ", in->challenge,
                        in->challenge_len);
        cbor_encode_text_stringz(&array, in->rp_id);
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    rp id: %s", in->rp_id);
        cbor_encode_text_stringz(&array, in->rp_name);
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    rp name: %s", in->rp_name);
        cbor_encode_byte_string(&array, in->gcm_user_name,
                                in->gcm_user_name_len);
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE,
                        "    gcm user name: ", in->gcm_user_name,
                        in->gcm_user_name_len);
        cbor_encode_byte_string(&array, in->gcm_user_display_name,
                                in->gcm_user_display_name_len);
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE, "    gcm user display name: ",
                        in->gcm_user_display_name,
                        in->gcm_user_display_name_len);
        cbor_encode_byte_string(&array, in->gcm_user_id, in->gcm_user_id_len);
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE,
                        "    gcm user id: ", in->gcm_user_id,
                        in->gcm_user_id_len);
        // The pubkey_cred_params is an array itself
        cbor_encoder_create_array(&array, &sub_array,
                                  in->pubkey_cred_params_len);
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    pubkey cred params:");
        for (size_t i = 0; i < in->pubkey_cred_params_len; i++) {
            cbor_encode_int(&sub_array, in->pubkey_cred_params[i]);
            debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "        %s",
                         get_cose_algorithm_name(in->pubkey_cred_params[i]));
        }
        err = cbor_encoder_close_container(&array, &sub_array);
        if (err) {
            debug_printf(DEBUG_LEVEL_ERROR, "Could not close CBOR array");
            goto err;
        }
        // If there are optional parameters, we encode them in a map
        if (num_optionals > 0) {
            cbor_encoder_create_map(&array, &map, num_optionals);
            if (in->timeout != 0) {
                cbor_encode_int(&map, TIMEOUT);
                cbor_encode_int(&map, in->timeout);
                debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    timeout: %d ms",
                             in->timeout);
            }
            if (in->auth_sel.attachment != 0) {
                cbor_encode_int(&map, AUTH_SEL_ATTACHMENT);
                cbor_encode_int(&map, in->auth_sel.attachment);
                debug_printf(DEBUG_LEVEL_MORE_VERBOSE,
                             "    authenticator attachment: %s",
                             in->auth_sel.attachment == 1 ? "PLATFORM"
                                                          : "CROSS-PLATFORM");
            }
            if (in->auth_sel.resident_key != 0) {
                cbor_encode_int(&map, AUTH_SEL_RESIDENT_KEY);
                cbor_encode_int(&map, in->auth_sel.resident_key);
                debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    resident key: %s",
                             get_action_policy_name(in->auth_sel.resident_key));
            }
            if (in->auth_sel.user_verification != 0) {
                cbor_encode_int(&map, AUTH_SEL_USER_VERIFICATION);
                cbor_encode_int(&map, in->auth_sel.user_verification);
                debug_printf(
                    DEBUG_LEVEL_MORE_VERBOSE, "    user verification: %s",
                    get_action_policy_name(in->auth_sel.user_verification));
            }
            // Excluded creds is an optional array of fields. Each item of the
            // array (if present) must contain all of the following fields:
            // type, id and transports
            if (in->exclude_creds_len != 0) {
                cbor_encode_int(&map, EXCLUDE_CREDS);
                cbor_encoder_create_array(&map, &sub_array,
                                          in->exclude_creds_len * 2);
                debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    exclude creds:");
                for (size_t i = 0; i < in->exclude_creds_len; i++) {
                    cbor_encode_text_stringz(&sub_array,
                                             in->exclude_creds[i].type);
                    cbor_encode_byte_string(&sub_array, in->exclude_creds[i].id,
                                            in->exclude_creds[i].id_len);
                    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "        type: %s",
                                 in->exclude_creds[i].type);
                    debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE, "        id: ",
                                    in->exclude_creds[i].id,
                                    in->exclude_creds[i].id_len);
                }
                err = cbor_encoder_close_container(&map, &sub_array);
                if (err) {
                    debug_printf(DEBUG_LEVEL_ERROR,
                                 "Could not close CBOR array");
                    goto err;
                }
            }
            err = cbor_encoder_close_container(&array, &map);
            if (err) {
                debug_printf(DEBUG_LEVEL_ERROR, "Could not close CBOR map");
                goto err;
            }
        }
        break;
    }
    case FIDO_REG_RESPONSE: {
        struct reg_response *in = (struct reg_response *)input;
        assert(in->authdata != NULL && in->authdata_len != 0 &&
               in->clientdata_json != NULL);
        // Required fields are packet type, att_obj and clientdata_json
        cbor_encoder_create_array(&encoder, &array, 3);
        cbor_encode_int(&array, FIDO_REG_RESPONSE);
        cbor_encode_byte_string(&array, in->authdata, in->authdata_len);
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE,
                        "    authenticator data: ", in->authdata,
                        in->authdata_len);
        cbor_encode_text_stringz(&array, in->clientdata_json);
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    clientdata: %s",
                     in->clientdata_json);
        break;
    }
    case FIDO_AUTH_INDICATION: {
        // Encode just the packet type
        cbor_encoder_create_array(&encoder, &array, 1);
        cbor_encode_int(&array, FIDO_AUTH_INDICATION);
        break;
    }
    case FIDO_AUTH_REQUEST: {
        struct auth_request *in = (struct auth_request *)input;
        assert(in->challenge != NULL && in->challenge_len > 0);
        // Count optional parameters
        size_t num_optionals = 0;
        if (in->rp_id != NULL)
            ++num_optionals;
        if (in->user_verification != 0)
            ++num_optionals;
        if (in->timeout != 0)
            ++num_optionals;
        // Required fields are packet type and challenge. The last field of the
        // array is a map if there are optional parameters
        cbor_encoder_create_array(&encoder, &array, num_optionals > 0 ? 3 : 2);
        cbor_encode_int(&array, FIDO_AUTH_REQUEST);
        cbor_encode_byte_string(&array, in->challenge, in->challenge_len);
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE, "    challenge: ", in->challenge,
                        in->challenge_len);
        if (num_optionals > 0) {
            cbor_encoder_create_map(&array, &map, num_optionals);
            if (in->timeout != 0) {
                cbor_encode_int(&map, TIMEOUT);
                cbor_encode_int(&map, in->timeout);
                debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    timeout: %d ms",
                             in->timeout);
            }
            if (in->rp_id != NULL) {
                cbor_encode_int(&map, RPID);
                cbor_encode_text_stringz(&map, in->rp_id);
                debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    rp id: %s", in->rp_id);
            }
            if (in->user_verification != 0) {
                cbor_encode_int(&map, USER_VERIFICATION);
                cbor_encode_int(&map, in->user_verification);
                debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    user verification: %s",
                             get_action_policy_name(in->user_verification));
            }
            err = cbor_encoder_close_container(&array, &map);
            if (err) {
                debug_printf(DEBUG_LEVEL_ERROR, "Could not close CBOR map");
                goto err;
            }
        }
        break;
    }
    case FIDO_AUTH_RESPONSE: {
        struct auth_response *in = (struct auth_response *)input;
        assert(in->authdata != NULL && in->authdata_len != 0 &&
               in->clientdata_json != NULL && in->signature != NULL &&
               in->signature_len != 0 && in->user_id != NULL &&
               in->user_id_len != 0 && in->cred_id != NULL &&
               in->cred_id_len != 0);
        // Required fields are packet type, clientdata_json, authdata, signature
        // user_id and cred_id
        cbor_encoder_create_array(&encoder, &array, 6);
        cbor_encode_int(&array, FIDO_AUTH_RESPONSE);
        cbor_encode_text_stringz(&array, in->clientdata_json);
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    clientdata: %s",
                     in->clientdata_json);
        cbor_encode_byte_string(&array, in->authdata, in->authdata_len);
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE,
                        "    authenticator data: ", in->authdata,
                        in->authdata_len);
        cbor_encode_byte_string(&array, in->signature, in->signature_len);
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE, "    signature: ", in->signature,
                        in->signature_len);
        cbor_encode_byte_string(&array, in->user_id, in->user_id_len);
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE, "    user id: ", in->user_id,
                        in->user_id_len);
        cbor_encode_byte_string(&array, in->cred_id, in->cred_id_len);
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE, "    cred id: ", in->cred_id,
                        in->cred_id_len);
        break;
    }
    default:
        debug_printf(DEBUG_LEVEL_ERROR, "Unknown packet type");
        goto err;
    }
    // Close the array
    err = cbor_encoder_close_container(&encoder, &array);
    if (err != CborNoError) {
        debug_printf(DEBUG_LEVEL_ERROR, "Could not close CBOR array");
        debug_printf(DEBUG_LEVEL_ERROR, "Error: %s", cbor_error_string(err));
        goto err;
    }
    // Output is meant to be passed to the out parameter of the openssl custom
    // ext callback functions. Casting away of const is safe, as we're
    // immediately transferring ownership to openssl, which understands thats
    // it's now responsible for freeing the memory.
    *out_buf = buf;
    *out_len = cbor_encoder_get_buffer_size(&encoder, buf);
    return 0;
err:
    OPENSSL_free(buf);
    return -1;
}

int cbor_build(const struct cbor_values *in_values, const u8 **out_buf,
               size_t *out_len) {
    // TODO: make this a constant, mention it in thesis that is is theoreticaly
    // constaint by the TLS record size.
    u8 *buf = OPENSSL_zalloc(1500);
    if (!buf) {
        debug_printf(DEBUG_LEVEL_ERROR,
                     "Could not allocate memory for CBOR encoding");
        return -1;
    }
    CborEncoder encoder, mapEncoder;
    cbor_encoder_init(&encoder, buf, 1500, 0);
    CborError err;

    size_t length = 1; // Packet type is always present
    if (in_values->challenge)
        length += 1;
    if (in_values->rp_id)
        length += 1;
    if (in_values->rp_name)
        length += 1;
    if (in_values->user_verification)
        length += 1;
    if (in_values->clientdata_json)
        length += 1;
    if (in_values->authdata)
        length += 1;
    if (in_values->signature)
        length += 1;
    if (in_values->user_id)
        length += 1;
    if (in_values->cred_id)
        length += 1;
    if (in_values->cred_param)
        length += 1;
    if (in_values->eph_user_id)
        length += 1;
    if (in_values->user_id_key)
        length += 1;
    if (in_values->user_name)
        length += 1;
    if (in_values->enc_user_id)
        length += 1;
    if (in_values->enc_user_name)
        length += 1;
    if (in_values->att_stmt)
        length += 1;
    if (in_values->pubkey)
        length += 1;

    err = cbor_encoder_create_map(&encoder, &mapEncoder, length);
    if (err) {
        debug_printf(DEBUG_LEVEL_ERROR, "Could not create CBOR map");
        OPENSSL_free(buf);
        return -1;
    }

    // Always encode the package type
    if (in_values->type == UNDEFINED) {
        debug_printf(DEBUG_LEVEL_ERROR, "Cbor packet type not set");
        OPENSSL_free(buf);
        return -1;
    }
    cbor_encode_int(&mapEncoder, CBOR_ATTR_PACKET_TYPE);
    cbor_encode_int(&mapEncoder, in_values->type);
    debug_printf(DEBUG_LEVEL_VERBOSE, "Sending packet: %s",
                 get_package_type_name(in_values->type));

    // Encode the rest of the values, depending on their presence
    if (in_values->challenge) {
        cbor_encode_int(&mapEncoder, CBOR_ATTR_CHALLENGE);
        cbor_encode_byte_string(&mapEncoder, in_values->challenge,
                                in_values->challenge_len);
    }
    if (in_values->rp_id) {
        cbor_encode_int(&mapEncoder, CBOR_ATTR_RP_ID);
        cbor_encode_text_stringz(&mapEncoder, in_values->rp_id);
    }
    if (in_values->rp_name) {
        cbor_encode_int(&mapEncoder, CBOR_ATTR_RP_NAME);
        cbor_encode_text_stringz(&mapEncoder, in_values->rp_name);
    }
    if (in_values->user_verification) {
        cbor_encode_int(&mapEncoder, CBOR_ATTR_USER_VERIFICATION);
        cbor_encode_text_stringz(&mapEncoder, in_values->user_verification);
    }
    if (in_values->clientdata_json) {
        cbor_encode_int(&mapEncoder, CBOR_ATTR_CLIENT_DATA);
        cbor_encode_text_stringz(&mapEncoder, in_values->clientdata_json);
    }
    if (in_values->authdata) {
        cbor_encode_int(&mapEncoder, CBOR_ATTR_AUTHENTICATOR_DATA);
        cbor_encode_byte_string(&mapEncoder, in_values->authdata,
                                in_values->authdata_len);
    }
    if (in_values->signature) {
        cbor_encode_int(&mapEncoder, CBOR_ATTR_SIGNATURE);
        cbor_encode_byte_string(&mapEncoder, in_values->signature,
                                in_values->signature_len);
    }
    if (in_values->user_id) {
        cbor_encode_int(&mapEncoder, CBOR_ATTR_USER_ID);
        cbor_encode_byte_string(&mapEncoder, in_values->user_id,
                                in_values->user_id_len);
    }
    if (in_values->cred_id) {
        cbor_encode_int(&mapEncoder, CBOR_ATTR_CRED_ID);
        cbor_encode_byte_string(&mapEncoder, in_values->cred_id,
                                in_values->cred_id_len);
    }
    if (in_values->cred_param) {
        cbor_encode_int(&mapEncoder, CBOR_ATTR_CRED_PARAMS);
        cbor_encode_int(&mapEncoder, in_values->cred_param);
    }
    if (in_values->eph_user_id) {
        cbor_encode_int(&mapEncoder, CBOR_ATTR_EPH_USER_ID);
        cbor_encode_byte_string(&mapEncoder, in_values->eph_user_id,
                                in_values->eph_user_id_len);
    }
    if (in_values->user_id_key) {
        cbor_encode_int(&mapEncoder, CBOR_ATTR_USER_ID_KEY);
        cbor_encode_byte_string(&mapEncoder, in_values->user_id_key,
                                in_values->user_id_key_len);
    }
    if (in_values->user_name) {
        cbor_encode_int(&mapEncoder, CBOR_ATTR_USER_NAME);
        cbor_encode_text_stringz(&mapEncoder, in_values->user_name);
    }
    if (in_values->enc_user_id) {
        cbor_encode_int(&mapEncoder, CBOR_ATTR_ENC_USER_ID);
        cbor_encode_byte_string(&mapEncoder, in_values->enc_user_id,
                                in_values->enc_user_id_len);
    }
    if (in_values->enc_user_name) {
        cbor_encode_int(&mapEncoder, CBOR_ATTR_ENC_USER_NAME);
        cbor_encode_byte_string(&mapEncoder, in_values->enc_user_name,
                                in_values->enc_user_name_len);
    }
    if (in_values->att_stmt) {
        cbor_encode_int(&mapEncoder, CBOR_ATTR_ATT_STMT);
        cbor_encode_byte_string(&mapEncoder, in_values->att_stmt,
                                in_values->att_stmt_len);
    }
    if (in_values->pubkey) {
        cbor_encode_int(&mapEncoder, CBOR_ATTR_PUBKEY);
        cbor_encode_byte_string(&mapEncoder, in_values->pubkey,
                                in_values->pubkey_len);
    }

    err = cbor_encoder_close_container(&encoder, &mapEncoder);
    if (err) {
        debug_printf(DEBUG_LEVEL_ERROR, "Could not close CBOR map");
        OPENSSL_free(buf);
        return -1;
    }

    // Output is meant to be passed to the out parameter of the openssl custom
    // ext callback functions. Casting away of const is safe, as we're
    // immediately transferring ownership to openssl, which understands thats
    // it's now responsible for freeing the memory.
    *out_buf = buf;
    *out_len = cbor_encoder_get_buffer_size(&encoder, buf);
    return 0;
}

void cbor_values_free(struct cbor_values *values) {
    if (values->challenge) {
        OPENSSL_free(values->challenge);
        values->challenge = NULL;
    }
    if (values->rp_id) {
        OPENSSL_free(values->rp_id);
        values->rp_id = NULL;
    }
    if (values->rp_name) {
        OPENSSL_free(values->rp_name);
        values->rp_name = NULL;
    }
    if (values->user_verification) {
        OPENSSL_free(values->user_verification);
        values->user_verification = NULL;
    }
    if (values->clientdata_json) {
        OPENSSL_free(values->clientdata_json);
        values->clientdata_json = NULL;
    }
    if (values->authdata) {
        OPENSSL_free(values->authdata);
        values->authdata = NULL;
    }
    if (values->signature) {
        OPENSSL_free(values->signature);
        values->signature = NULL;
    }
    if (values->user_id) {
        OPENSSL_free(values->user_id);
        values->user_id = NULL;
    }
    if (values->cred_id) {
        OPENSSL_free(values->cred_id);
        values->cred_id = NULL;
    }
    if (values->eph_user_id) {
        OPENSSL_free(values->eph_user_id);
        values->eph_user_id = NULL;
    }
    if (values->user_id_key) {
        OPENSSL_free(values->user_id_key);
        values->user_id_key = NULL;
    }
    if (values->user_name) {
        OPENSSL_free(values->user_name);
        values->user_name = NULL;
    }
    if (values->enc_user_id) {
        OPENSSL_free(values->enc_user_id);
        values->enc_user_id = NULL;
    }
    if (values->enc_user_name) {
        OPENSSL_free(values->enc_user_name);
        values->enc_user_name = NULL;
    }
    if (values->att_stmt) {
        OPENSSL_free(values->att_stmt);
        values->att_stmt = NULL;
    }
    if (values->pubkey) {
        OPENSSL_free(values->pubkey);
        values->pubkey = NULL;
    }
}
