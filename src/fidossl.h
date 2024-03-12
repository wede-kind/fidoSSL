#ifndef FIDOSSL_H
#define FIDOSSL_H

#include "types.h"
#include "debug.h"
#include <openssl/ssl.h>

#define FIDOSSL_EXT_TYPE 0x1234
// Logical or of:
// - SSL_EXT_CLIENT_HELLO
// - SSL_EXT_TLS1_3_CERTIFICATE
// - SSL_EXT_TLS1_3_CERTIFICATE_REQUEST
#define FIDOSSL_CONTEXT 0x5080

typedef struct fidossl_client_opts {
    enum client_mode {
        FIDOSSL_REGISTER,
        FIDOSSL_AUTHENTICATE,
    } mode;
    char *user_name;
    char *user_display_name;
    char *ticket_b64;
    char *pin;
    int debug_level;
} FIDOSSL_CLIENT_OPTS;

typedef struct fidossl_server_opts {
    char *rp_id;
    char *rp_name;
    char *ticket_b64;
    POLICY user_verification;
    POLICY resident_key;
    AUTH_ATTACH auth_attach;
    TRANSPORT transport;
    size_t timeout;
    int debug_level;
} FIDOSSL_SERVER_OPTS;

int fidossl_client_add_cb(SSL *ssl, unsigned int ext_type, unsigned int context,
                          const unsigned char **out, size_t *outlen, X509 *x,
                          size_t chainidx, int *al, void *add_arg);

int fidossl_client_parse_cb(SSL *ssl, unsigned int ext_type, unsigned int context,
                            const unsigned char *in, size_t inlen, X509 *x,
                            size_t chainidx, int *al, void *parse_arg);

void fidossl_client_free_cb(SSL *ssl, unsigned int ext_type, unsigned int context,
                            const unsigned char *out, void *add_arg);

int fidossl_server_add_cb(SSL *ssl, unsigned int ext_type, unsigned int context,
                          const unsigned char **out, size_t *outlen, X509 *x,
                          size_t chainidx, int *al, void *add_arg);

int fidossl_server_parse_cb(SSL *ssl, unsigned int ext_type, unsigned int context,
                            const unsigned char *in, size_t inlen, X509 *x,
                            size_t chainidx, int *al, void *parse_arg);

void fidossl_server_free_cb(SSL *ssl, unsigned int ext_type, unsigned int context,
                            const unsigned char *out, void *add_arg);

int no_verify_cb(int preverify_ok, X509_STORE_CTX *x509_ctx);

#endif /* FIDOSSL_H */
