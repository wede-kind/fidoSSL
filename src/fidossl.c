#include "fidossl.h"
#include "debug.h"
#include "rp.h"
#include "types.h"
#include "ud.h"
#include <fido.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

int fidossl_client_add_cb(
    SSL *ssl,
    unsigned int ext_type,
    unsigned int context,
    const unsigned char **out,
    size_t *outlen,
    X509 *x,
    size_t chainidx,
    int *al,
    void *add_arg
) {
    //  If the application wishes to include the extension ext_type it should
    //  set out to the extension data, set outlen to the length of the extension
    //  data and return 1. If the add_cb does not wish to include the extension
    //  it must return 0.
    if (ext_type != FIDOSSL_EXT_TYPE) {
        return 0; // Silently ignore unknown extensions
    }
    if (context == SSL_EXT_CLIENT_HELLO) {
        struct fido_data *data = get_ud_fido_data(ssl, add_arg);

        switch (data->state) {
        case STATE_REG_INITIAL:
            if (create_pre_reg_indication(data, out, outlen) != 0) {
                debug_printf(DEBUG_LEVEL_ERROR, "Failed to create pre registration indication");
                return -1;
            }
            data->state = STATE_PRE_REG_INDICATION_SENT;
            break;
        case STATE_PRE_REG_RESPONSE_SENT:
            if (create_reg_indication(data, out, outlen) != 0) {
                debug_printf(DEBUG_LEVEL_ERROR, "Failed to create registration indication");
                return -1;
            }
            data->state = STATE_REG_INDICATION_SENT;
            break;
        case STATE_AUTH_INITIAL:
            if (create_auth_indication(data, out, outlen) != 0) {
                debug_printf(DEBUG_LEVEL_ERROR, "Failed to create authentication indication");
                return -1;
            }
            data->state = STATE_AUTH_INDICATION_SENT;
            break;
        default:
            debug_printf(DEBUG_LEVEL_ERROR, "Invalid state");
            // TODO: find a better error code and apply for all invalid states
            *al = SSL_AD_INTERNAL_ERROR;
            return -1;
        }
    } else if (context == SSL_EXT_TLS1_3_CERTIFICATE) {
        struct fido_data *data = get_ud_fido_data(ssl, add_arg);

        switch (data->state) {
        case STATE_PRE_REG_REQUEST_RECEIVED:
            if (create_pre_reg_response(data, ssl, out, outlen) != 0) {
                debug_printf(DEBUG_LEVEL_ERROR, "Failed to create pre registration response");
                return -1;
            }
            data->state = STATE_PRE_REG_RESPONSE_SENT;
            break;
        case STATE_REG_REQUEST_RECEIVED:
            if (create_reg_response(data, ssl, out, outlen) != 0) {
                debug_printf(DEBUG_LEVEL_ERROR, "Failed to create registration response");
                return -1;
            }
            data->state = STATE_REG_RESPONSE_SENT;
            break;
        case STATE_AUTH_REQUEST_RECEIVED:
            if (create_auth_response(data, ssl, out, outlen) != 0) {
                debug_printf(DEBUG_LEVEL_ERROR, "Failed to create authentication response");
                return -1;
            }
            data->state = STATE_AUTH_RESPONSE_SENT;
            break;
        case STATE_PRE_REG_RESPONSE_SENT:
            // TODO: investigate why this context is called twice
            return 0;
        case STATE_AUTH_RESPONSE_SENT:
            // TODO: investigate why this context is called twice
            return 0;
        default:
            debug_printf(DEBUG_LEVEL_ERROR, "Invalid state");
            return -1;
        }
    } else {
        // debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Unhandeled context event in %s: %s", __func__, get_ssl_ext_context_code(context));
        return 0;
    }
    return 1;
}

int fidossl_client_parse_cb(
    SSL *ssl,
    unsigned int ext_type,
    unsigned int context,
    const unsigned char *in,
    size_t inlen,
    X509 *x,
    size_t chainidx,
    int *al,
    void *parse_arg
) {
    if (ext_type != FIDOSSL_EXT_TYPE) {
        return 0; // Silently ignore unknown extensions
    }

    if (context == SSL_EXT_TLS1_3_CERTIFICATE_REQUEST) {
        struct fido_data *data = get_ud_fido_data(ssl, NULL);

        switch (data->state) {
            case STATE_PRE_REG_INDICATION_SENT:
                if (process_pre_reg_request(in, inlen, data) != 0) {
                    debug_printf(DEBUG_LEVEL_ERROR, "Failed to process pre registration request");
                    return -1;
                }
                data->state = STATE_PRE_REG_REQUEST_RECEIVED;
                break;
            case STATE_REG_INDICATION_SENT:
                if (process_reg_request(in, inlen, data) != 0) {
                    debug_printf(DEBUG_LEVEL_ERROR, "Failed to process registration request");
                    return -1;
                }
                data->state = STATE_REG_REQUEST_RECEIVED;
                break;
            case STATE_AUTH_INDICATION_SENT:
                if (process_auth_request(in, inlen, data) != 0) {
                    debug_printf(DEBUG_LEVEL_ERROR, "Failed to process authentication request");
                    return -1;
                }
                data->state = STATE_AUTH_REQUEST_RECEIVED;
                break;
            default:
                debug_printf(DEBUG_LEVEL_ERROR, "Invalid state");
                return -1;
        }
        return 1;
    } else {
        // debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Unhandeled context event in %s: %s", __func__, get_ssl_ext_context_code(context));
        return 0;
    }
}

void fidossl_client_free_cb(SSL *ssl, unsigned int ext_type, unsigned int context,
                            const unsigned char *out, void *add_arg) {
    // Clean up the debug system
    // TODO: where to free?
    // debug_cleanup();
}

int fidossl_server_add_cb(
    SSL *ssl,
    unsigned int ext_type,
    unsigned int context,
    const unsigned char **out,
    size_t *outlen,
    X509 *x,
    size_t chainidx,
    int *al,
    void *add_arg
) {
    if (ext_type != FIDOSSL_EXT_TYPE) {
        return 0; // Silently ignore unknown extensions
    }
    if (context == SSL_EXT_TLS1_3_CERTIFICATE_REQUEST) {
        struct fido_data *data = get_rp_fido_data(ssl, NULL);
        if (data == NULL) {
            // No FIDO data for this connection. This means that the client
            // does not support the fido extension. This is not an error.
            return 0;
        }
        switch (data->state) {
            case STATE_PRE_REG_INDICATION_RECEIVED:
                if (create_pre_reg_request(data, out, outlen) != 0) {
                    debug_printf(DEBUG_LEVEL_ERROR, "Failed to create pre registration request");
                    return -1;
                }
                data->state = STATE_PRE_REG_REQUEST_SENT;
                break;
            case STATE_REG_INDICATION_RECEIVED:
                if (create_reg_request(data, out, outlen) != 0) {
                    debug_printf(DEBUG_LEVEL_ERROR, "Failed to create registration request");
                    return -1;
                }
                data->state = STATE_REG_REQUEST_SENT;
                break;
            case STATE_AUTH_INDICATION_RECEIVED:
                if (create_auth_request(data, out, outlen) != 0) {
                    debug_printf(DEBUG_LEVEL_ERROR, "Failed to create authentication request");
                    return -1;
                }
                data->state = STATE_AUTH_REQUEST_SENT;
                break;
            default:
                debug_printf(DEBUG_LEVEL_ERROR, "Invalid state");
                return -1;
        }
    } else {
        // debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Unhandeled context event in %s: %s", __func__, get_ssl_ext_context_code(context));
        return 0;
    }
    return 1;
}

int fidossl_server_parse_cb(
    SSL *ssl,
    unsigned int ext_type,
    unsigned int context,
    const unsigned char *in,
    size_t inlen,
    X509 *x,
    size_t chainidx,
    int *al,
    void *parse_arg
) {
    if (ext_type != FIDOSSL_EXT_TYPE) {
        return 0; // Silently ignore unknown extensions
    }
    if (context == SSL_EXT_CLIENT_HELLO) {
        struct fido_data *data = get_rp_fido_data(ssl, parse_arg);
        // The server has no state yet and can accept any indication. The
        // process_inication function will set the state accordingly.
        if (process_indication(in, inlen, data) != 0) {
            debug_printf(DEBUG_LEVEL_ERROR, "Failed to parse FIDO indication");
            return -1;
        }
    } else if (context == SSL_EXT_TLS1_3_CERTIFICATE) {
        struct fido_data *data = get_rp_fido_data(ssl, parse_arg);
        switch (data->state) {
            case STATE_PRE_REG_REQUEST_SENT:
                if (process_pre_reg_response(in, inlen, data) != 0) {
                    debug_printf(DEBUG_LEVEL_ERROR, "Failed to parse pre registration response");
                    return -1;
                }
                data->state = STATE_PRE_REG_RESPONSE_RECEIVED;
                // TODO: Should we error out here to denote that a second
                // handshake is required?
                break;
            case STATE_REG_REQUEST_SENT:
                if (process_reg_response(in, inlen, data) != 0) {
                    debug_printf(DEBUG_LEVEL_ERROR, "Failed to parse registration response");
                    return -1;
                }
                // data->state = STATE_REG_SUCCESS;
                debug_printf(DEBUG_LEVEL_VERBOSE, "FIDO registration success!");
                break;
            case STATE_AUTH_REQUEST_SENT:
                if (process_auth_response(in, inlen, data) != 0) {
                    debug_printf(DEBUG_LEVEL_ERROR, "Failed to parse authenticaton response");
                    return -1;
                }
                // TODO state to finish?
                debug_printf(DEBUG_LEVEL_VERBOSE, "FIDO authentication success!");
                break;
            default:
                debug_printf(DEBUG_LEVEL_ERROR, "Invalid state");
                return -1;
        }
    } else {
        // debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Unhandeled context event in %s: %s", __func__, get_ssl_ext_context_code(context));
        return 0;
    }
    return 1;
}

void fidossl_server_free_cb(SSL *ssl, unsigned int ext_type, unsigned int context,
                            const unsigned char *out, void *add_arg) {
    // Clean up the debug system
    // debug_cleanup();
}

// TOOD: delete
int no_verify_cb(int preverify_ok, X509_STORE_CTX *x509_ctx) {
    // Don't validae the vertificate
    return 1;
}
