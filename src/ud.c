#include "ud.h"
#include "common.h"
#include "debug.h"
#include "encoding.h"
#include "fidossl.h"
#include "serialize.h"
#include "types.h"
#include <assert.h>
#include <fido.h>
#include <jansson.h>
#include <openssl/sha.h>
#include <openssl/x509v3.h>

// SSL objects can hold arbitray external data. This index points to the
// struct which holds the user devise data.
static int ctx_data_index = -1;

void ud_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp) {
    struct ud_data *data = (struct ud_data *)ptr;
    if (data == NULL) {
        return;
    }
    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Freeing all data allocated by FIDOSSL");
    free_ud_data(data);
    debug_cleanup();
}

struct ud_data *init_ud(SSL *ssl, void *add_arg) {
    // Get the client options
    if (add_arg == NULL) {
        return NULL;
    }
    // Validate client options
    struct fidossl_client_opts *opts = (struct fidossl_client_opts *)add_arg;

    // Initialize the debug system.
    debug_initialize();
    set_debug_level(opts->debug_level);

    if (opts->mode != FIDOSSL_REGISTER && opts->mode != FIDOSSL_AUTHENTICATE) {
        debug_printf(DEBUG_LEVEL_ERROR,
                     "FIDOSSL: Invalid mode in client options");
        return NULL;
    }
    if (opts->mode == FIDOSSL_REGISTER &&
        (opts->ticket_b64 == NULL || opts->user_name == NULL ||
         opts->pin == NULL)) {
        debug_printf(
            DEBUG_LEVEL_ERROR,
            "FIDOSSL: A user id, pin and ticket must be set for registration");
        return NULL;
    }
    // Create the user device data
    struct ud_data *data = OPENSSL_malloc(sizeof(struct ud_data));
    if (data == NULL) {
        debug_printf(DEBUG_LEVEL_ERROR, "Memory allocation failed");
        return NULL;
    }
    memset(data, 0, sizeof(struct ud_data));

    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Configuring Client:");

    // Fill the user device data with the client options
    if (opts->mode == FIDOSSL_REGISTER) {
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    Mode: Key enrollment");
        data->state = STATE_REG_INITIAL;
        if (decode_base64(opts->ticket_b64, &data->ticket, &data->ticket_len) !=
            0) {
            debug_printf(DEBUG_LEVEL_ERROR,
                         "Failed to base64 decode the ticket");
            return NULL;
        }
        data->user_name = OPENSSL_zalloc(strlen(opts->user_name) + 1);
        memcpy(data->user_name, opts->user_name, strlen(opts->user_name));
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    User name: %s",
                     data->user_name);
        if (opts->user_display_name) {
            data->user_display_name =
                OPENSSL_zalloc(strlen(opts->user_display_name) + 1);
            memcpy(data->user_display_name, opts->user_display_name,
                   strlen(opts->user_display_name));
            debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    User display name: %s",
                         data->user_display_name);
        } else {
            debug_printf(
                DEBUG_LEVEL_MORE_VERBOSE,
                "    User display name not set. Falling back to user name");
        }
    } else if (opts->mode == FIDOSSL_AUTHENTICATE) {
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    Mode: Authentication");
        data->state = STATE_AUTH_INITIAL;
    }

    // TODO: how to configure this from rp side?
    data->user_presence = PREFERRED;
    data->pin = strdup(opts->pin);

    // Save the user device data to the SSL_CTX object
    SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
    ctx_data_index = CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL_CTX, 0, NULL, NULL, NULL, ud_free);
    if (ctx_data_index == -1) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to get ex new index");
        return NULL;
    }
    if (!SSL_CTX_set_ex_data(ctx, ctx_data_index, data)) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to set ex data");
        free_ud_data(data);
        return NULL;
    }

    return data;
}

struct ud_data *get_ud_data(SSL *ssl, void *add_arg) {
    if (ctx_data_index == -1) {
        // User device is not initialized
        return init_ud(ssl, add_arg);
    }
    SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
    return SSL_CTX_get_ex_data(ctx, ctx_data_index);
}

char *get_origin(SSL *ssl) {
    if (!ssl) {
        return NULL;
    }
    char *origin = NULL;

    // The Server Name Indication (SNI) specifies the client's intended
    // destination. If not set, hostname verification relies on SSL_set1_host().
    // Absence of both SNI and a manually set hostname prevents server
    // certificate validation. Since server certificate validation is crucial
    // for FIDO, we enforce the use of SNI.

    // Start by probing the SNI
    const char *sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (sni) {
        // +1 for null terminator, +8 for 'https://'
        origin = OPENSSL_zalloc(strlen(sni) + 1 + 8);
        memcpy(origin, "https://", 8);
        memcpy(origin + 8, sni, strlen(sni));
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Origin derived from SNI: %s",
                     origin);
        return origin;
    }
    // If the client has not set the SNI, we fall back to the hostname set with
    // SSL_set1_host().
    const char *hostname = SSL_get0_peername(ssl);
    if (hostname) {
        debug_printf(
            DEBUG_LEVEL_VERBOSE,
            "No SNI set by the client. Falling back to the DNS hostname");
        origin = OPENSSL_zalloc(strlen(hostname) + 1 + 8);
        memcpy(origin, "https://", 8);
        memcpy(origin + 8, hostname, strlen(hostname));
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE,
                     "Origin derived from DNS hostname: %s", origin);
        return origin;
    }
    debug_printf(DEBUG_LEVEL_ERROR,
                 "Client has not set the SNI nor the DNS hostname");
    return NULL;
}

int is_equal_or_registrable_domain_suffix(const char *host,
                                          const char *host_suffix) {
    // For now, we only check for equality
    return strcmp(host, host_suffix);
}

int validate_rp_id(SSL *ssl, const char *origin, const char *rp_id) {
    if (!ssl || !origin) {
        return -1;
    }

    // By default, the RPID for a WebAuthn operation is set to the RP’s origin's
    // effective domain. This default MAY be overridden by the RP, as long as
    // the RP-specified RPID value is a registrable domain suffix of / or is
    // equal to the RP’s origin's effective domain.
    // See: https://www.w3.org/TR/webauthn-2/#relying-party-identifier

    // If the RP explilcitly provided a RPID and its equal to the origin, we
    // accept it. Again, no need to validate against the server certificate as
    // TLS is doing that.
    if (strcmp(rp_id, origin) == 0) {
        return 0;
    }

    // If the RP explilcitly provided a RPID and it does not match the origin,
    // we must check if it matches any registrable domain suffix of the DNS
    // names in the server certificate's Subject Alternative Name (SAN) field.

    // Get the X509 server certificate from the SSL object
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        debug_printf(DEBUG_LEVEL_ERROR, "No server certificate available");
        return -1;
    }
    // Get the SAN field from the certificate.
    STACK_OF(GENERAL_NAME) *san_names = NULL;
    san_names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (!san_names) {
        // When no SAN field is found, we could fall back to the Common Name
        // (CN) field, but it is deprecated so we don't.
        debug_printf(DEBUG_LEVEL_ERROR, "No SAN field in the certificate");
        X509_free(cert);
        return -1;
    }
    // Iterate over the DNS names in the SAN field and compare them to the
    // RPID
    int san_names_len = sk_GENERAL_NAME_num(san_names);
    for (int i = 0; i < san_names_len; ++i) {
        const GENERAL_NAME *current_name = sk_GENERAL_NAME_value(san_names, i);
        // Only look at DNS names. We ignore IP addresses and URIs.
        if (current_name->type != GEN_DNS)
            continue;

        // Convert the ASN1 string to a byte array
        u8 *dns_name_bytes = NULL;
        size_t dns_name_len =
            ASN1_STRING_to_UTF8(&dns_name_bytes, current_name->d.dNSName);

        // Create a c-string from the byte array without repeated heap
        // allocation
        char dns_name[dns_name_len + 1];
        memcpy(dns_name, dns_name_bytes, dns_name_len);
        dns_name[dns_name_len] = '\0';
        OPENSSL_free(dns_name_bytes);

        if (is_equal_or_registrable_domain_suffix(dns_name, rp_id) == 0) {
            // We accept the RPID
            X509_free(cert);
            sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
            return 0;
        }
    }
    // The RPID does not match the server certificate's DNS names
    debug_printf(DEBUG_LEVEL_ERROR, "The server provided RPID does not match "
                                    "the server certificate's DNS names");
    X509_free(cert);
    sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
    return -1;
}

char *generate_clientdata(struct ud_data *data, const char *type) {
    // It is possible to drop the libjansson dependency and use a simple
    // string builder to generate the client data. However, the client data
    // is a JSON object and libjansson provides a convenient way to build
    // JSON objects.
    // See: https://www.w3.org/TR/webauthn-2/#clientdatajson-serialization
    assert(data->challenge != NULL && data->challenge_len != 0 &&
           data->origin != NULL);

    // The challenge must be base64url encoded
    char *encoded_challenge = NULL;
    if (base64url_encode(data->challenge, data->challenge_len,
                         &encoded_challenge) < 0) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to encode challenge");
        return NULL;
    }

    json_t *root = json_object();
    json_object_set_new(root, "type", json_string(type));
    json_object_set_new(root, "challenge", json_string(encoded_challenge));
    json_object_set_new(root, "origin", json_string(data->origin));
    json_object_set_new(root, "crossOrigin", json_false());

    char *cd;
    // Serialize JSON object to a c string
    cd = json_dumps(root, JSON_COMPACT);

    json_decref(root);
    return cd;
}

fido_cred_t *create_fido_cred_t(struct ud_data *data) {
    fido_cred_t *cred = fido_cred_new();
    if (cred == NULL) {
        debug_printf(DEBUG_LEVEL_ERROR,
                     "Failed to allocate memory for fido_cred_t");
        return NULL;
    }
    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Preparing CTAP with:");
    // Set the relying party ID and name
    if (fido_cred_set_rp(cred, data->rp_id, data->rp_name) != FIDO_OK) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to set RPID in fido_cred_t");
        fido_cred_free(&cred);
        return NULL;
    }
    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    Relying Party ID: %s",
                 data->rp_id);
    // Set the user information
    if (fido_cred_set_user(cred,
                           data->user_id,           // User ID
                           data->user_id_len,       // User ID length
                           data->user_name,         // User name
                           data->user_display_name, // User display name
                           NULL                     // User icon
                           ) != FIDO_OK) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to set user in fido_cred_t");
        fido_cred_free(&cred);
        return NULL;
    }
    debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE, "    User ID: ", data->user_id,
                    data->user_id_len);
    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    User name: %s",
                 data->user_name);
    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    User display name: %s",
                 data->user_display_name);

    // For now, we only support ES256 but other algorithms can be added
    // in the future
    int cose_alg = data->cred_params[0];
    if (fido_cred_set_type(cred, cose_alg) != FIDO_OK) {
        debug_printf(DEBUG_LEVEL_ERROR,
                     "Failed to set cred param in fido_cred_t");
        fido_cred_free(&cred);
        return NULL;
    }
    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    Credential algorithm: %s",
                 get_cose_algorithm_name(cose_alg));

    // Set the clientdata hash
    u8 hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)data->clientdata_json,
           strlen(data->clientdata_json), hash);
    if (fido_cred_set_clientdata_hash(cred, hash, SHA256_DIGEST_LENGTH) !=
        FIDO_OK) {
        debug_printf(DEBUG_LEVEL_ERROR,
                     "Failed to set client data hash in fido_cred_t");
        fido_cred_free(&cred);
        return NULL;
    }
    debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE, "    Client data hash: ", hash,
                    SHA256_DIGEST_LENGTH);

    // Set discoverable credentials
    if (data->resident_key == REQUIRED || data->resident_key == PREFERRED) {
        if (fido_cred_set_rk(cred, FIDO_OPT_TRUE) != FIDO_OK) {
            debug_printf(DEBUG_LEVEL_ERROR, "Failed to request resident key");
            fido_cred_free(&cred);
            return NULL;
        }
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE,
                     "    Discoverable credentials: TRUE");
    } else {
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE,
                     "    Discoverable credentials: FALSE");
    }
    // Set user verification
    int uv = FIDO_OPT_OMIT;
    if (data->user_verification == REQUIRED ||
        data->user_verification == PREFERRED) {
        uv = FIDO_OPT_TRUE;
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    User verification: TRUE");
    } else {
        uv = FIDO_OPT_FALSE;
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    User verification: FALSE");
    }
    if (fido_cred_set_uv(cred, uv) != FIDO_OK) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to set user verification");
        fido_cred_free(&cred);
        return NULL;
    }

    // Platform authenticator are not supported for now
    debug_printf(DEBUG_LEVEL_MORE_VERBOSE,
                 "    Authenticator attachment: CROSS_PLATFORM");

    // Set excluded credentials
    for (size_t i = 0; i < data->exclude_creds_len; i++) {
        struct credential *excl_cred = &data->exclude_creds[i];
        if (fido_cred_exclude(cred, excl_cred->id, excl_cred->id_len) != FIDO_OK) {
            debug_printf(DEBUG_LEVEL_ERROR, "Failed to exclude credential ID");
            fido_cred_free(&cred);
            return NULL;
        }
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Credential ID excluded: ");
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE, "    Excluded Credential ID: ", excl_cred->id, excl_cred->id_len);
    }

    return cred;
}

fido_assert_t *create_fido_assert_t(struct ud_data *data) {
    fido_opt_t uv, up;
    fido_assert_t *assert_t = fido_assert_new();
    if (assert_t == NULL) {
        debug_printf(DEBUG_LEVEL_ERROR,
                     "Failed to allocate memory for fido_assert_t");
        return NULL;
    }
    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Preparing CTAP with:");

    if (fido_assert_set_rp(assert_t, data->rp_id) != FIDO_OK) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to set RPID in fido_assert_t");
        fido_assert_free(&assert_t);
        return NULL;
    }
    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    Relying Party ID: %s",
                 data->rp_id);
    u8 hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)data->clientdata_json,
           strlen(data->clientdata_json), hash);
    if (fido_assert_set_clientdata_hash(assert_t, hash, SHA256_DIGEST_LENGTH) !=
        FIDO_OK) {
        debug_printf(DEBUG_LEVEL_ERROR,
                     "Failed to set client data hash in fido_assert_t");
        fido_assert_free(&assert_t);
        return NULL;
    }
    debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE, "    Client data hash: ", hash,
                    SHA256_DIGEST_LENGTH);
    // If the server wishes to require user verification, set the user
    // verification
    if (data->user_verification) {
        if (data->user_verification == PREFERRED ||
            data->user_verification == REQUIRED) {
            uv = FIDO_OPT_TRUE;
        } else {
            uv = FIDO_OPT_FALSE;
        }
        if (fido_assert_set_uv(assert_t, uv) != FIDO_OK) {
            debug_printf(DEBUG_LEVEL_ERROR,
                         "Failed to set user verification in fido_assert_t");
            fido_assert_free(&assert_t);
            return NULL;
        }
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    User verification: %s",
                     uv == FIDO_OPT_TRUE ? "TRUE" : "FALSE");
    }
    if (data->user_presence) {
        if (data->user_presence == PREFERRED ||
            data->user_presence == REQUIRED) {
            up = FIDO_OPT_TRUE;
        } else {
            up = FIDO_OPT_FALSE;
        }
        if (fido_assert_set_up(assert_t, up) != FIDO_OK) {
            debug_printf(DEBUG_LEVEL_ERROR,
                         "Failed to set user presence in fido_assert_t");
            fido_assert_free(&assert_t);
            return NULL;
        }
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    User presence: %s",
                     up == FIDO_OPT_TRUE ? "TRUE" : "FALSE");
    }

    return assert_t;
}

int run_ctap(struct ud_data *data, enum fido_mode mode) {
    fido_assert_t *assert_t = NULL;
    fido_cred_t *cred_t = NULL;

    if (mode == AUTHENTICATE) {
        assert_t = create_fido_assert_t(data);
        if (assert_t == NULL) {
            debug_printf(DEBUG_LEVEL_ERROR, "Failed to create fido_assert_t");
            return -1;
        }
    } else if (mode == REGISTER) {
        cred_t = create_fido_cred_t(data);
        if (cred_t == NULL) {
            debug_printf(DEBUG_LEVEL_ERROR, "Failed to create fido_cred_t");
            return -1;
        }
    } else {
        debug_printf(DEBUG_LEVEL_ERROR, "Invalid CTAP mode");
        return -1;
    }

    fido_dev_info_t *devlist;
    size_t ndevs;
    fido_dev_t *fido_dev;
    const fido_dev_info_t *fido_dev_info;
    const char *fido_path;
    bool success = false;

    // Allocate a list for storing information about up to 64 FIDO devices
    devlist = fido_dev_info_new(64);
    if (devlist == NULL) {
        debug_printf(DEBUG_LEVEL_ERROR,
                     "Failed to allocate memory for fido_dev_info_t");
        return -1;
    }

    // Discovers FIDO devices available to the system and populates the devlist
    // with their information
    if (fido_dev_info_manifest(devlist, 64, &ndevs) != FIDO_OK) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to discover FIDO devices");
        return -1;
    }

    if (ndevs == 0) {
        debug_printf(DEBUG_LEVEL_ERROR, "No FIDO token discovered");
        return -1;
    }
    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Discovered FIDO tokens: %d", ndevs);

    // Print device information
    for (int i = 0; i < ndevs; i++) {
        const fido_dev_info_t *info = fido_dev_info_ptr(devlist, i);
        const char *path = fido_dev_info_path(info);
        const char *manufacturer = fido_dev_info_manufacturer_string(info);
        const char *product = fido_dev_info_product_string(info);
        int vendor_id = fido_dev_info_vendor(info);
        int product_id = fido_dev_info_product(info);

        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Device path: %s", path);
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    Manufacturer: %s",
                     manufacturer);
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    Product: %s", product);
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    Product ID: %d",
                     product_id);
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    Vendor ID: %d", vendor_id);
    }

    // Iterate over the discovered devices and try to run the CTAP
    // until we find a device that works
    for (int i = 0; i < ndevs; i++) {
        fido_dev = fido_dev_new();
        if (fido_dev == NULL) {
            debug_printf(DEBUG_LEVEL_ERROR,
                         "Failed to allocate memory for fido_dev_t");
            return -1;
        }
        fido_dev_info = fido_dev_info_ptr(devlist, i);
        fido_path = fido_dev_info_path(fido_dev_info);
        if (fido_dev_open(fido_dev, fido_path) != FIDO_OK) {
            debug_printf(DEBUG_LEVEL_ERROR, "Failed to open FIDO device");
            fido_dev_free(&fido_dev);
            continue;
        }
        // Set timeout
        if (data->timeout) {
            if (fido_dev_set_timeout(fido_dev, data->timeout) != FIDO_OK) {
                debug_printf(DEBUG_LEVEL_ERROR, "Failed to set timeout");
                fido_dev_close(fido_dev);
                fido_dev_free(&fido_dev);
                continue;
            }
        }
        debug_printf(DEBUG_LEVEL_VERBOSE, "Running CTAP with device: %s",
                     fido_path);

        if (data->user_presence == REQUIRED ||
            data->user_presence == PREFERRED) {
            printf("Please touch the FIDO token\n");
        }

        int ret = -1;
        if (mode == REGISTER) {
            ret = fido_dev_make_cred(fido_dev, cred_t, data->pin);
        } else if (mode == AUTHENTICATE) {
            ret = fido_dev_get_assert(fido_dev, assert_t, data->pin);
        }
        if (ret == FIDO_OK) {
            debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "CTAP was successful");
            success = true;
        } else if (ret == FIDO_ERR_ACTION_TIMEOUT) {
            debug_printf(DEBUG_LEVEL_ERROR, "Proof of user presence timed out");
        } else if (ret == FIDO_ERR_NO_CREDENTIALS) {
            debug_printf(
                DEBUG_LEVEL_ERROR,
                "This token has no credentials for the given relying party");
        } else if (ret == FIDO_ERR_PIN_INVALID) {
            debug_printf(DEBUG_LEVEL_ERROR, "The PIN was invalid");
        } else if (ret == FIDO_ERR_PIN_NOT_SET) {
            debug_printf(DEBUG_LEVEL_ERROR,
                         "A PIN is required to use this token. Please set a "
                         "PIN and try again.");
        } else if (ret == FIDO_ERR_CREDENTIAL_EXCLUDED) {
            debug_printf(DEBUG_LEVEL_ERROR, "There is already a credential "
                         "for this user on this token. Excluded credentials "
                         "prevent the creation of duplicate credentials.");
        } else {
            debug_printf(DEBUG_LEVEL_ERROR, "CTAP failed with error code: %d",
                         ret);
        }

        fido_dev_close(fido_dev);
        fido_dev_free(&fido_dev);
        if (success) {
            break;
        }
    }
    // Read the output from ctap and store it in the ud_data struct
    if (success && mode == REGISTER) {
        data->authdata_len = fido_cred_authdata_raw_len(cred_t);
        data->authdata = OPENSSL_malloc(data->authdata_len);
        memcpy(data->authdata, fido_cred_authdata_raw_ptr(cred_t),
               data->authdata_len);

        // attStmt and fmt is omitted here because attestation is not supported

    } else if (success && mode == AUTHENTICATE) {
        data->authdata_len = fido_assert_authdata_raw_len(assert_t, 0);
        data->authdata = OPENSSL_malloc(data->authdata_len);
        memcpy(data->authdata, fido_assert_authdata_raw_ptr(assert_t, 0),
               data->authdata_len);

        data->signature_len = fido_assert_sig_len(assert_t, 0);
        data->signature = OPENSSL_malloc(data->signature_len);
        memcpy(data->signature, fido_assert_sig_ptr(assert_t, 0),
               data->signature_len);

        data->user_id_len = fido_assert_user_id_len(assert_t, 0);
        data->user_id = OPENSSL_malloc(data->user_id_len);
        memcpy(data->user_id, fido_assert_user_id_ptr(assert_t, 0),
               data->user_id_len);

        data->cred_id_len = fido_assert_id_len(assert_t, 0);
        data->cred_id = OPENSSL_malloc(data->cred_id_len);
        memcpy(data->cred_id, fido_assert_id_ptr(assert_t, 0),
               data->cred_id_len);

        if (!data->authdata || !data->authdata_len || !data->signature ||
            !data->signature_len || !data->user_id || !data->user_id_len ||
            !data->cred_id || !data->cred_id_len) {
            debug_printf(
                DEBUG_LEVEL_ERROR,
                "CTAP failed to return all necessary data, this is unusual");
            success = -1;
        }
    }
    fido_cred_free(&cred_t);
    fido_assert_free(&assert_t);

    return success ? 0 : -1;
}

int create_pre_indication(struct ud_data *data, const u8 **out,
                              size_t *out_len) {
    // The pre indication has no data. It is simply a signal to the
    // server that the user device is ready to start a registration
    // or authentication with non-discoverable credentials process.
    if (cbor_build(NULL, PKT_PRE_INDICATION, out, out_len) != 0) {
        debug_printf(DEBUG_LEVEL_ERROR,
                     "Failed to build pre indication");
        return -1;
    }
    return 0;
}

int create_reg_indication(struct ud_data *data, const u8 **out,
                          size_t *out_len) {
    assert(data->eph_user_id != NULL && data->eph_user_id_len != 0);
    struct reg_indication packet;
    memset(&packet, 0, sizeof(packet));
    packet.eph_user_id = data->eph_user_id;
    packet.eph_user_id_len = data->eph_user_id_len;
    packet.user_name = data->user_name;
    packet.user_display_name = data->user_display_name;
    packet.ticket = data->ticket;
    packet.ticket_len = data->ticket_len;
    return cbor_build(&packet, PKT_REG_INDICATION, out, out_len);
}

int create_reg_response(struct ud_data *data, SSL *ssl, const u8 **out,
                        size_t *out_len) {
    // Update ud_data with the origin
    data->origin = get_origin(ssl);

    // If the RP did not explicitly override the RPID, we default to the origin.
    // It is not necessary to validate the RPID against the server certificate
    // since we already enforce the use of SNI or hostname validation. The TLS
    // handshake would fail if the server certificate does not match.
    if (!data->rp_id) {
        data->rp_id = data->origin;
    } else {
        // If the RP explilcitly provided a RPID, we must validate it against
        // the origin.
        if (validate_rp_id(ssl, data->origin, data->rp_id) != 0) {
            debug_printf(DEBUG_LEVEL_ERROR,
                         "Server provided RPID is no registrable domain suffix "
                         "of the server certificate SNI or hostname");
            return -1;
        }
    }
    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Validated RPID: %s", data->rp_id);

    data->clientdata_json = generate_clientdata(data, "webauthn.create");
    if (data->clientdata_json == NULL) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to generate client data");
        return -1;
    }
    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Generated client data: %s",
                 data->clientdata_json);

    // Run the CTAP
    if (run_ctap(data, REGISTER) != 0) {
        debug_printf(DEBUG_LEVEL_VERBOSE, "Failed to run CTAP");
        return -1;
    }

    struct reg_response packet;
    memset(&packet, 0, sizeof(packet));
    packet.authdata = data->authdata;
    packet.authdata_len = data->authdata_len;
    packet.clientdata_json = data->clientdata_json;

    return cbor_build(&packet, PKT_REG_RESPONSE, out, out_len);
}

int create_auth_indication(struct ud_data *data, const u8 **out,
                           size_t *out_len) {
    // The FIDO standard speficifies that the authentication process is started
    // by the REST api call: 'webauthn/authenticate-begin'. In TLS context, we
    // indicate the start of the authentication by the packet type.
    return cbor_build(NULL, PKT_AUTH_INDICATION, out, out_len);
}

int create_auth_response(struct ud_data *data, SSL *ssl, const u8 **out,
                         size_t *out_len) {
    // Update ud_data with the origin
    data->origin = get_origin(ssl);

    // If the RP did not explicitly override the RPID, we default to the origin.
    // It is not necessary to validate the RPID against the server certificate
    // since we already enforce the use of SNI or hostname validation. The TLS
    // handshake would fail if the server certificate does not match.
    if (!data->rp_id) {
        data->rp_id = data->origin;
    } else {
        // If the RP explilcitly provided a RPID, we must validate it against
        // the origin.
        if (validate_rp_id(ssl, data->origin, data->rp_id) != 0) {
            debug_printf(DEBUG_LEVEL_ERROR,
                         "Server provided RPID is no registrable domain suffix "
                         "of the server certificate SNI or hostname");
            return -1;
        }
    }
    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Validated RPID: %s", data->rp_id);

    // Generate the client data
    data->clientdata_json = generate_clientdata(data, "webauthn.get");
    if (data->clientdata_json == NULL) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to generate client data");
        return -1;
    }
    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Generated client data: %s",
                 data->clientdata_json);

    // Run the CTAP
    if (run_ctap(data, AUTHENTICATE) != 0) {
        debug_printf(DEBUG_LEVEL_VERBOSE, "Failed to run CTAP");
        return -1;
    }

    struct auth_response packet;
    memset(&packet, 0, sizeof(packet));
    packet.authdata = data->authdata;
    packet.authdata_len = data->authdata_len;
    packet.signature = data->signature;
    packet.signature_len = data->signature_len;
    packet.clientdata_json = data->clientdata_json;

    //Optional Fields
    if (data->user_id_len != 0 && data->user_id) {
        packet.user_id = data->user_id;
        packet.user_id_len = data->user_id_len;
    }
    if (data->cred_id_len != 0 && data->cred_id) {
        packet.cred_id = data->cred_id;
        packet.cred_id_len = data->cred_id_len;
    }

    return cbor_build(&packet, PKT_AUTH_RESPONSE, out, out_len);
}

int process_pre_request(const u8 *in, size_t in_len,
                            struct ud_data *data) {
    if (in == NULL || in_len == 0 || data == NULL) {
        return -1;
    }
    struct pre_request packet;
    memset(&packet, 0, sizeof(packet));
    enum packet_type type = PKT_PRE_REQUEST;
    if (cbor_parse(in, in_len, &type, &packet) != 0) {
        debug_printf(DEBUG_LEVEL_ERROR,
                     "Failed to parse pre-registration request");
        return -1;
    }
    // Copy pointers. We can reuse the allocated memory.
    data->eph_user_id = packet.eph_user_id;
    data->eph_user_id_len = packet.eph_user_id_len;
    data->gcm_key = packet.gcm_key;
    data->gcm_key_len = packet.gcm_key_len;

    // No Need to free the packet since we reused the allocated memory
    return 0;
}

int process_reg_request(const u8 *in, size_t in_len, struct ud_data *data) {
    if (in == NULL || in_len == 0 || data == NULL) {
        return -1;
    }
    struct reg_request packet;
    memset(&packet, 0, sizeof(packet));
    enum packet_type type = PKT_REG_REQUEST;
    if (cbor_parse(in, in_len, &type, &packet) != 0) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to parse registration request");
        return -1;
    }
    assert(data->gcm_key != NULL);
    assert(data->gcm_key_len != 0);
    // Decrypt the user name
    u8 *user_name;
    size_t user_name_len;
    if (aes_gcm_decrypt(packet.gcm_user_name, packet.gcm_user_name_len,
                        &user_name, &user_name_len, data->gcm_key,
                        data->gcm_key_len) != 0) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to decrypt user name");
        return -1;
    }
    // Check if the user name is the name of the user who initiated the
    // registration process
    if (user_name_len != strlen(data->user_name) ||
        memcmp(user_name, data->user_name, strlen(data->user_name)) != 0) {
        debug_printf(DEBUG_LEVEL_ERROR,
                     "User name does not match the user who initiated the "
                     "registration process");
        return -1;
    }
    debug_printf(DEBUG_LEVEL_MORE_VERBOSE,
                 "User name matches the user who "
                 "initiated the registration process");
    // Decrypt the user id and store it
    if (aes_gcm_decrypt(packet.gcm_user_id, packet.gcm_user_id_len,
                        &data->user_id, &data->user_id_len, data->gcm_key,
                        data->gcm_key_len) != 0) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to decrypt user id");
        return -1;
    }
    debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE,
                    "Decrypted user id: ", data->user_id, data->user_id_len);

    // Store the remaining data
    data->challenge = packet.challenge;
    data->challenge_len = packet.challenge_len;
    data->rp_id = packet.rp_id;
    data->rp_name = packet.rp_name;
    data->cred_params = packet.pubkey_cred_params;
    data->cred_params_len = packet.pubkey_cred_params_len;

    // Optional fields
    if (packet.timeout) {
        data->timeout = packet.timeout;
    }
    if (packet.auth_sel.attachment != 0 && packet.auth_sel.resident_key != 0 &&
        packet.auth_sel.user_verification != 0) {
        data->auth_attach = packet.auth_sel.attachment;
        data->resident_key = packet.auth_sel.resident_key;
        data->user_verification = packet.auth_sel.user_verification;
    }
    if (packet.exclude_creds_len != 0 && packet.exclude_creds) {
        data->exclude_creds = packet.exclude_creds;
        data->exclude_creds_len = packet.exclude_creds_len;
    }
    // Free unneeded memory
    OPENSSL_free(user_name);
    OPENSSL_free(packet.gcm_user_name);
    OPENSSL_free(packet.gcm_user_display_name);
    OPENSSL_free(packet.gcm_user_id);

    return 0;
}

int process_auth_request(const u8 *in, size_t in_len, struct ud_data *data) {
    if (in == NULL || in_len == 0 || data == NULL) {
        return -1;
    }
    struct auth_request packet;
    memset(&packet, 0, sizeof(packet));
    enum packet_type type = PKT_AUTH_REQUEST;
    if (cbor_parse(in, in_len, &type, &packet) != 0) {
        debug_printf(DEBUG_LEVEL_ERROR,
                     "Failed to parse authentication request");
        return -1;
    }
    // Copy pointers. We can reuse the allocated memory.
    data->challenge = packet.challenge;
    data->challenge_len = packet.challenge_len;

    if (packet.rp_id) {
        data->rp_id = packet.rp_id;
    }
    if (packet.user_verification != 0) {
        data->user_verification = packet.user_verification;
    }
    if (packet.timeout) {
        data->timeout = packet.timeout;
    }
    // No need to free the packet since we reused the allocated memory
    return 0;
}
