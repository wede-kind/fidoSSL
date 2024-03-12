#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fidossl.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 12345

int main() {
    SSL_CTX *ctx;
    SSL *ssl;
    int sockfd;
    struct sockaddr_in server_addr;

    // Initialize OpenSSL
    SSL_library_init();
    ctx = SSL_CTX_new(TLS_client_method());

    // Tell the client which CA should be trusted for server certificate verification
    if (!SSL_CTX_load_verify_locations(ctx, "/opt/homebrew/etc/pki/ca.crt", NULL)) {
        printf("Failed to load CA certificate\n");
        exit(EXIT_FAILURE);
    }

    // Configure the client to abort the handshake if certificate
    // verification fails.
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    //-------------------------------------------------------------------------
    // FIDOSSL START

    // Enforce TLS 1.3
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)) {
        printf("Failed to set the minimum TLS protocol version\n");
    }

    // Since the extension enforces client certificates, we need to provide a
    // client certificate and a private key
    if (SSL_CTX_use_certificate_file(ctx, "/opt/homebrew/etc/pki/issued/Alice.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "/opt/homebrew/etc/pki/private/Alice.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // TODO: Write in the README that the user is responsible to free all
    // allocated himself. However this is only possible after the callbacks are
    // called, so after SSL_connect
    FIDOSSL_CLIENT_OPTS *opts = malloc(sizeof(FIDOSSL_CLIENT_OPTS));
    opts->mode = FIDOSSL_AUTHENTICATE;
    opts->user_name = "alice";
    opts->user_display_name = "Alice";
    opts->ticket_b64 = "y1v2BsTzi6baajWpU5WSDw6AYorx2MSDO1iVFSQC8VQ=";
    opts->pin = "1234";
    opts->debug_level = DEBUG_LEVEL_MORE_VERBOSE;

    // Add extension
    SSL_CTX_add_custom_ext(
        ctx,
        FIDOSSL_EXT_TYPE,
        FIDOSSL_CONTEXT,
        fidossl_client_add_cb,
        fidossl_client_free_cb,
        // void * add_arg is a pointer to arbitrary data that you can use within
        // your add_cb function.
        opts,
        fidossl_client_parse_cb,
        // void * parse_args is like add_arg but it passes arbitrary data into
        // the parse_cb
        NULL
    );

    //-------------------------------------------------------------------------
    // FIDOSSL END

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Initialize server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    // Connect to server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    // Create SSL connection
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    // Set the SNI hostname
    if (!SSL_set_tlsext_host_name(ssl, "demo.fido2.tls.edu")) {
        printf("Failed to set the SNI hostname\n");
    }

    // Additionally set hostname validation
    if (!SSL_set1_host(ssl, "demo.fido2.tls.edu")) {
        printf("Failed to set the certificate verification hostname");
    }

    // Do the TLS handshake
    if (SSL_connect(ssl) != 1) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    printf("=== First TLS connection established.\n");

    while (SSL_shutdown(ssl) != 1) {}

    // Only do a second handshake if we want to register a new credential
    if (opts->mode == FIDOSSL_REGISTER) {
        // Create new SSL connection. Unfortunately, we cant reuse the SSL object
        SSL_free(ssl);
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sockfd);

        // Set the SNI hostname
        if (!SSL_set_tlsext_host_name(ssl, "demo.fido2.tls.edu")) {
            printf("Failed to set the SNI hostname\n");
        }

        // Additionally set hostname validation
        if (!SSL_set1_host(ssl, "demo.fido2.tls.edu")) {
            printf("Failed to set the certificate verification hostname");
        }

        // Connect to server again
        if (SSL_connect(ssl) != 1) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        printf("=== Second TLS connection established.\n");

        // Shutdown SSL connection
        while (SSL_shutdown(ssl) != 1) {}
    }

    // Clean up
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sockfd);

    return 0;
}





// #include <openssl/bio.h>
// #include <openssl/err.h>
// #include <openssl/ssl.h>
// #include <string.h>
// #include <sys/socket.h>
//
// #include <stdio.h>
// #include <unistd.h>
//
// #include <fidossl.h>
//
// /* Helper function to create a BIO connected to the server */
// static BIO *create_socket_bio(const char *hostname, const char *port,
//                               int family) {
//     int sock = -1;
//     BIO_ADDRINFO *res;
//     const BIO_ADDRINFO *ai = NULL;
//     BIO *bio;
//
//     /*
//      * Lookup IP address info for the server.
//      */
//     if (!BIO_lookup_ex(hostname, port, BIO_LOOKUP_CLIENT, family, SOCK_STREAM,
//                        0, &res))
//         return NULL;
//
//     /*
//      * Loop through all the possible addresses for the server and find one
//      * we can connect to.
//      */
//     for (ai = res; ai != NULL; ai = BIO_ADDRINFO_next(ai)) {
//         /*
//          * Create a TCP socket. We could equally use non-OpenSSL calls such
//          * as "socket" here for this and the subsequent connect and close
//          * functions. But for portability reasons and also so that we get
//          * errors on the OpenSSL stack in the event of a failure we use
//          * OpenSSL's versions of these functions.
//          */
//         sock = BIO_socket(BIO_ADDRINFO_family(ai), SOCK_STREAM, 0, 0);
//         if (sock == -1)
//             continue;
//
//         /* Connect the socket to the server's address */
//         if (!BIO_connect(sock, BIO_ADDRINFO_address(ai), BIO_SOCK_NODELAY)) {
//             BIO_closesocket(sock);
//             sock = -1;
//             continue;
//         }
//
//         /* We have a connected socket so break out of the loop */
//         break;
//     }
//
//     /* Free the address information resources we allocated earlier */
//     BIO_ADDRINFO_free(res);
//
//     /* If sock is -1 then we've been unable to connect to the server */
//     if (sock == -1)
//         return NULL;
//
//     /* Create a BIO to wrap the socket */
//     bio = BIO_new(BIO_s_socket());
//     if (bio == NULL) {
//         BIO_closesocket(sock);
//         return NULL;
//     }
//
//     /*
//      * Associate the newly created BIO with the underlying socket. By
//      * passing BIO_CLOSE here the socket will be automatically closed when
//      * the BIO is freed. Alternatively you can use BIO_NOCLOSE, in which
//      * case you must close the socket explicitly when it is no longer
//      * needed.
//      */
//     BIO_set_fd(bio, sock, BIO_CLOSE);
//
//     return bio;
// }
//
// /*
//  * Simple application to send a basic HTTP/1.0 request to a server and
//  * print the response on the screen.
//  */
// int main(int argc, char *argv[]) {
//     SSL_CTX *ctx = NULL;
//     SSL *ssl = NULL;
//     BIO *bio = NULL;
//     int res = EXIT_FAILURE;
//     int ret;
//     const char *message = "TLS tunnel established: hello from client\n";
//     size_t written, readbytes;
//     char buf[160];
//     char *hostname, *port;
//     int argnext = 1;
//     int ipv6 = 0;
//
//     if (argc < 3) {
//         printf("Usage: tls-client-block [-6]  hostname port\n");
//         goto end;
//     }
//
//     if (!strcmp(argv[argnext], "-6")) {
//         if (argc < 4) {
//             printf("Usage: tls-client-block [-6]  hostname port\n");
//             goto end;
//         }
//         ipv6 = 1;
//         argnext++;
//     }
//     hostname = argv[argnext++];
//     port = argv[argnext];
//
//     /*
//      * Create an SSL_CTX which we can use to create SSL objects from. We
//      * want an SSL_CTX for creating clients so we use TLS_client_method()
//      * here.
//      */
//     ctx = SSL_CTX_new(TLS_client_method());
//     if (ctx == NULL) {
//         printf("Failed to create the SSL_CTX\n");
//         goto end;
//     }
//
//     if (SSL_CTX_use_certificate_file(ctx, "test/keys/localhost.crt", SSL_FILETYPE_PEM) <= 0) {
//         ERR_print_errors_fp(stderr);
//         exit(EXIT_FAILURE);
//     }
//
//     if (SSL_CTX_use_PrivateKey_file(ctx, "test/keys/localhost.key", SSL_FILETYPE_PEM) <= 0) {
//         ERR_print_errors_fp(stderr);
//         exit(EXIT_FAILURE);
//     }
//
//     // TODO: Write in the README that the user is responsible to free all
//     // allocated himself. However this is only possible after the callbacks are
//     // called, so after SSL_connect
//     FIDOSSL_CLIENT_OPTS *opts = malloc(sizeof(FIDOSSL_CLIENT_OPTS));
//     opts->mode = FIDOSSL_REGISTER;
//     opts->user_id_b64 = "y1v2BsTzi6baajWpU5WSDw6AYorx2MSDO1iVFSQC8VQ=";
//     opts->user_name = "Alice";
//
//     // Add extension
//     // SSL_CTX_add_custom_ext(
//     //     ctx,
//     //     FIDOSSL_EXT_TYPE,
//     //     FIDOSSL_CONTEXT,
//     //     fidossl_client_add_cb,
//     //     fidossl_client_free_cb,
//     //     // void * add_arg is a pointer to arbitrary data that you can use within
//     //     // your add_cb function.
//     //     opts,
//     //     fidossl_client_parse_cb,
//     //     // void * parse_args is like add_arg but it passes arbitrary data into
//     //     // the parse_cb
//     //     NULL
//     // );
//
//     /*
//      * Configure the client to abort the handshake if certificate
//      * verification fails. Virtually all clients should do this unless you
//      * really know what you are doing. The verify_callback in this example
//      * determines if the certificate is valid.
//      */
//     SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, no_verify_cb);
//
//     /* Use the default trusted certificate store */
//     if (!SSL_CTX_set_default_verify_paths(ctx)) {
//         printf("Failed to set the default trusted certificate store\n");
//         goto end;
//     }
//
//     /*
//      * TLSv1.1 or earlier are deprecated by IETF and are generally to be
//      * avoided if possible. We require a minimum TLS version of TLSv1.2.
//      * TODO: change to TLS1.3
//      */
//     if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
//         printf("Failed to set the minimum TLS protocol version\n");
//         goto end;
//     }
//
//     /* Create an SSL object to represent the TLS connection */
//     ssl = SSL_new(ctx);
//     if (ssl == NULL) {
//         printf("Failed to create the SSL object\n");
//         goto end;
//     }
//
//     /*
//      * Create the underlying transport socket/BIO and associate it with the
//      * connection.
//      */
//     bio = create_socket_bio(hostname, port, ipv6 ? AF_INET6 : AF_INET);
//     if (bio == NULL) {
//         printf("Failed to crete the BIO\n");
//         goto end;
//     }
//     SSL_set_bio(ssl, bio, bio);
//
//     /*
//      * Tell the server during the handshake which hostname we are attempting
//      * to connect to in case the server supports multiple hosts.
//      */
//     if (!SSL_set_tlsext_host_name(ssl, hostname)) {
//         printf("Failed to set the SNI hostname\n");
//         goto end;
//     }
//
//     /*
//      * Ensure we check during certificate verification that the server has
//      * supplied a certificate for the hostname that we were expecting.
//      * Virtually all clients should do this unless you really know what you
//      * are doing.
//      */
//     if (!SSL_set1_host(ssl, hostname)) {
//         printf("Failed to set the certificate verification hostname");
//         goto end;
//     }
//
//     /* Do the handshake with the server */
//     ret = SSL_connect(ssl);
//     if (ret < 0) {
//         printf("Handshake failed due to an error\n");
//         // Consider using the following function to get more information about the
//         // error:
//         // SSL_get_error(ssl, ret);
//         goto end;
//     } else if (ret == 0) {
//         // The connection was closed cleanly during the handshake, indicating
//         // that the handshake was not successful but was shut down in a
//         // controlled manner without a sudden failure. 
//         printf("Connection closed by the server\n");
//     } else {
//         printf("Handshake successful\n");
//     }
//
//     // Do the double handshake
//     // _________________________________________________________
//
//     if (SSL_shutdown(ssl) == 0) {
//         SSL_shutdown(ssl);
//     }
//     SSL_free(ssl);
//
//     ssl = SSL_new(ctx);
//     if (ssl == NULL) {
//         printf("Failed to create the SSL object\n");
//         goto end;
//     }
//     SSL_set_bio(ssl, bio, bio);
//     if (!SSL_set_tlsext_host_name(ssl, hostname)) {
//         printf("Failed to set the SNI hostname\n");
//         goto end;
//     }
//     if (!SSL_set1_host(ssl, hostname)) {
//         printf("Failed to set the certificate verification hostname");
//         goto end;
//     }
//     // // TODO: test if we could avoid clearing the SSL object and reusing session
//     // // parameters
//     // if (!SSL_clear(ssl)) {
//     //     printf("Failed to clear the SSL object\n");
//     // }
//     // free the socket bio
//     // BIO_free(bio);
//
//     printf("----->Start sleeping\n");
//     sleep(5);
//     if (SSL_connect(ssl) < 1) {
//         printf("Failed to connect to the server\n");
//         /*
//          * If the failure is due to a verification error we can get more
//          * information about it from SSL_get_verify_result().
//          */
//         if (SSL_get_verify_result(ssl) != X509_V_OK)
//             printf("Verify error: %s\n",
//                    X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
//         goto end;
//     }
//
//     // _________________________________________________________
//
//     /* Write an simple message through the TLS tunnel */
//     if (!SSL_write_ex(ssl, message, strlen(message), &written)) {
//         printf("Failed to write message\n");
//         goto end;
//     }
//
//     /*
//      * Get up to sizeof(buf) bytes of the response. We keep reading until the
//      * server closes the connection.
//      */
//     while (SSL_read_ex(ssl, buf, sizeof(buf), &readbytes)) {
//         /*
//          * OpenSSL does not guarantee that the returned data is a string or
//          * that it is NUL terminated so we use fwrite() to write the exact
//          * number of bytes that we read. The data could be non-printable or
//          * have NUL characters in the middle of it. For this simple example
//          * we're going to print it to stdout anyway.
//          */
//         fwrite(buf, 1, readbytes, stdout);
//     }
//     /* In case the response didn't finish with a newline we add one now */
//     printf("\n");
//
//     /*
//      * Check whether we finished the while loop above normally or as the
//      * result of an error. The 0 argument to SSL_get_error() is the return
//      * code we received from the SSL_read_ex() call. It must be 0 in order
//      * to get here. Normal completion is indicated by SSL_ERROR_ZERO_RETURN.
//      */
//     if (SSL_get_error(ssl, 0) != SSL_ERROR_ZERO_RETURN) {
//         /*
//          * Some error occurred other than a graceful close down by the
//          * peer.
//          */
//         printf("Failed reading remaining data\n");
//         goto end;
//     }
//
//     /*
//      * The peer already shutdown gracefully (we know this because of the
//      * SSL_ERROR_ZERO_RETURN above). We should do the same back.
//      */
//     ret = SSL_shutdown(ssl);
//     if (ret < 1) {
//         /*
//          * ret < 0 indicates an error. ret == 0 would be unexpected here
//          * because that means "we've sent a close_notify and we're waiting
//          * for one back". But we already know we got one from the peer
//          * because of the SSL_ERROR_ZERO_RETURN above.
//          */
//         printf("Error shutting down\n");
//         goto end;
//     }
//     // int version = SSL_version(ssl);
//     // if (version == TLS1_3_VERSION) {
//     //     // TLS 1.3 is used
//     //     printf("TLS 1.3 is used\n");
//     // } else {
//     //     // Another TLS version is used
//     //     printf("TLS 1.3 is not used\n");
//     // }
//
//     /* Success! */
//     res = EXIT_SUCCESS;
// end:
//     /*
//      * If something bad happened then we will dump the contents of the
//      * OpenSSL error stack to stderr. There might be some useful diagnostic
//      * information there.
//      */
//     if (res == EXIT_FAILURE)
//         ERR_print_errors_fp(stderr);
//
//     /*
//      * Free the resources we allocated. We do not free the BIO object here
//      * because ownership of it was immediately transferred to the SSL object
//      * via SSL_set_bio(). The BIO will be freed when we free the SSL object.
//      */
//     SSL_free(ssl);
//     SSL_CTX_free(ctx);
//     return res;
// }
