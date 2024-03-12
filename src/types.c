#include "types.h"
#include <openssl/crypto.h>

void free_auth_request(struct auth_request *auth_request) {
    if (auth_request == NULL) {
        return;
    }
    OPENSSL_free(auth_request->challenge);
    OPENSSL_free(auth_request->rp_id);
    OPENSSL_free(auth_request);
}

void free_auth_response(struct auth_response *auth_response) {
    if (auth_response == NULL) {
        return;
    }
    OPENSSL_free(auth_response->authdata);
    OPENSSL_free(auth_response->clientdata_json);
    OPENSSL_free(auth_response->signature);
    OPENSSL_free(auth_response->user_id);
    OPENSSL_free(auth_response);
}

void free_pre_reg_request(struct pre_reg_request *pre_reg_request) {
    if (pre_reg_request == NULL) {
        return;
    }
    OPENSSL_free(pre_reg_request->eph_user_id);
    OPENSSL_free(pre_reg_request->gcm_key);
    OPENSSL_free(pre_reg_request);
}

void free_pre_reg_response(struct pre_reg_response *pre_reg_response) {
    if (pre_reg_response == NULL) {
        return;
    }
    OPENSSL_free(pre_reg_response->user_name);
    OPENSSL_free(pre_reg_response->user_display_name);
    OPENSSL_free(pre_reg_response->ticket);
    OPENSSL_free(pre_reg_response);
}

void free_reg_indication(struct reg_indication *reg_indication) {
    if (reg_indication == NULL) {
        return;
    }
    OPENSSL_free(reg_indication->eph_user_id);
    OPENSSL_free(reg_indication);
}

void free_reg_request(struct reg_request *reg_request) {
    if (reg_request == NULL) {
        return;
    }
    OPENSSL_free(reg_request->challenge);
    OPENSSL_free(reg_request->rp_id);
    OPENSSL_free(reg_request->rp_name);
    OPENSSL_free(reg_request->gcm_user_name);
    OPENSSL_free(reg_request->gcm_user_display_name);
    OPENSSL_free(reg_request->gcm_user_id);
    OPENSSL_free(reg_request->pubkey_cred_params);
    if (reg_request->exclude_creds != NULL && reg_request->exclude_creds_len > 0) {
        for (size_t i = 0; i < reg_request->exclude_creds_len; i++) {
            OPENSSL_free(reg_request->exclude_creds[i].type);
            OPENSSL_free(reg_request->exclude_creds[i].id);
            OPENSSL_free(reg_request->exclude_creds[i].transports);
        }
    }
    OPENSSL_free(reg_request->exclude_creds);
    OPENSSL_free(reg_request);
}

void free_reg_response(struct reg_response *reg_response) {
    if (reg_response == NULL) {
        return;
    }
    OPENSSL_free(reg_response->authdata);
    OPENSSL_free(reg_response->clientdata_json);
    OPENSSL_free(reg_response);
}

void free_authdata(struct authdata *authdata) {
    if (authdata == NULL) {
        return;
    }
    OPENSSL_free(authdata->rp_id_hash);
    OPENSSL_free(authdata->aaguid);
    OPENSSL_free(authdata->cred_id);
    OPENSSL_free(authdata->pubkey);
    OPENSSL_free(authdata);
}

void free_credential(struct credential *cred) {
    OPENSSL_free(cred->type);
    OPENSSL_free(cred->id);
    OPENSSL_free(cred->transports);
    OPENSSL_free(cred->pubkey_cose);
    OPENSSL_free(cred);
}
