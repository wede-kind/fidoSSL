#include "types.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fidossl.h>

// #include <arpa/inet.h>
// #include <openssl/err.h>
// #include <openssl/ssl.h>
// #include <signal.h>
// #include <stdio.h>
// #include <string.h>
// #include <sys/socket.h>
// #include <unistd.h>

#define SERVER_PORT 12345

int main() {
    SSL_CTX *ctx;
    SSL *ssl;
    int sockfd, clientfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len;

    // Initialize OpenSSL
    SSL_library_init();
    ctx = SSL_CTX_new(TLS_server_method());

    // Load certificate and private key
    SSL_CTX_use_certificate_file(ctx, "/opt/homebrew/etc/pki/issued/demo.fido2.tls.edu.crt", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "/opt/homebrew/etc/pki/private/demo.fido2.tls.edu.key", SSL_FILETYPE_PEM);
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate.\n");
        exit(EXIT_FAILURE);
    }

    //-------------------------------------------------------------------------
    // FIDOSSL START

    FIDOSSL_SERVER_OPTS *opts = malloc(sizeof(FIDOSSL_SERVER_OPTS));
    opts->rp_id = "demo.fido2.tls.edu";
    opts->rp_name = "Demo Fido2 TLS";
    opts->ticket_b64 = "y1v2BsTzi6baajWpU5WSDw6AYorx2MSDO1iVFSQC8VQ=";
    // TODO: When user verification is changed while createing the asster_t, it
    // does not work anymore. why?
    opts->user_verification = PREFERRED;
    opts->resident_key = REQUIRED;
    opts->auth_attach = CROSS_PLATFORM;
    opts->transport = USB;
    opts->timeout = 60000; // 1 Minute
    opts->debug_level = DEBUG_LEVEL_MORE_VERBOSE;

    // TODO: Write the manpage

    SSL_CTX_add_custom_ext(
        ctx,
        FIDOSSL_EXT_TYPE,
        FIDOSSL_CONTEXT,
        fidossl_server_add_cb,
        fidossl_server_free_cb,
        NULL, // No add_args on the server side
        fidossl_server_parse_cb,
        opts // Server options are passed as the parse_arg
    );
    // Ask for a client certificate in order to trigger the SSL_EXT_TLS1_3_CERTIFICATE event
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, no_verify_cb);

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
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SERVER_PORT);

    // Bind socket
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Binding failed");
        exit(EXIT_FAILURE);
    }

    // Listen for connections
    if (listen(sockfd, 5) == -1) {
        perror("Listening failed");
        exit(EXIT_FAILURE);
    }

    // Accept incoming connections
    addr_len = sizeof(client_addr);
    clientfd = accept(sockfd, (struct sockaddr *)&client_addr, &addr_len);
    if (clientfd == -1) {
        perror("Accepting connection failed");
        exit(EXIT_FAILURE);
    }

    // Create SSL connection
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, clientfd);
    if (SSL_accept(ssl) != 1) {
        printf("SSL_accept failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    printf("=== First TLS connection established.\n");

    // Shutdown SSL connection
    while (SSL_shutdown(ssl) != 1) {}

    // Create new SSL connection. Unfortunately, we cant reuse the SSL object.
    SSL_free(ssl);
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, clientfd);

    if (SSL_accept(ssl) != 1) {
        // ERR_print_errors_fp(stderr);
        close(clientfd);
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("=== Second TLS connection established.\n");

    // Shutdown SSL connection
    while (SSL_shutdown(ssl) != 1) {}

    SSL_free(ssl);
    SSL_CTX_free(ctx);

    // Close sockets
    close(clientfd);
    close(sockfd);

    return 0;
}




// #include <arpa/inet.h>
// #include <openssl/err.h>
// #include <openssl/ssl.h>
// #include <signal.h>
// #include <stdio.h>
// #include <string.h>
// #include <sys/socket.h>
// #include <unistd.h>
//
// #include <fidossl.h>
//
// int create_socket(int port) {
//     int s;
//     struct sockaddr_in addr;
//
//     addr.sin_family = AF_INET;
//     addr.sin_port = htons(port);
//     addr.sin_addr.s_addr = htonl(INADDR_ANY);
//
//     s = socket(AF_INET, SOCK_STREAM, 0);
//     if (s < 0) {
//         perror("Unable to create socket");
//         exit(EXIT_FAILURE);
//     }
//
//     if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
//         perror("Unable to bind");
//         exit(EXIT_FAILURE);
//     }
//
//     if (listen(s, 1) < 0) {
//         perror("Unable to listen");
//         exit(EXIT_FAILURE);
//     }
//
//     return s;
// }
//
// SSL_CTX *create_context() {
//     const SSL_METHOD *method;
//     SSL_CTX *ctx;
//
//     method = TLS_server_method();
//
//     ctx = SSL_CTX_new(method);
//     if (!ctx) {
//         perror("Unable to create SSL context");
//         ERR_print_errors_fp(stderr);
//         exit(EXIT_FAILURE);
//     }
//
//     return ctx;
// }
//
// void configure_context(SSL_CTX *ctx) {
//     /* Set the key and cert */
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
//     FIDOSSL_SERVER_OPTS *opts = malloc(sizeof(FIDOSSL_SERVER_OPTS));
//     opts->rp_id = "localhost";
//     opts->rp_name = "Eduroam RP";
//     opts->challenge_len = 32; // create a challenge of 256 bits
//     opts->user_id_b64 = "y1v2BsTzi6baajWpU5WSDw6AYorx2MSDO1iVFSQC8VQ=";
//     opts->user_name = "Alice";
//     // TODO: manpage. One of "required", "preferred", "discouraged"
//     // opts->user_verification = "discouraged";
//
//     // SSL_CTX_add_custom_ext(
//     //     ctx,
//     //     FIDOSSL_EXT_TYPE,
//     //     FIDOSSL_CONTEXT,
//     //     fidossl_server_add_cb,
//     //     fidossl_server_free_cb,
//     //     NULL, // No add_args on the server side
//     //     fidossl_server_parse_cb,
//     //     opts // Server options are passed as the parse_arg
//     // );
//     // Ask for a client certificate in order to trigger the SSL_EXT_TLS1_3_CERTIFICATE event
//     // SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, no_verify_cb);
// }
//
// int main(int argc, char **argv) {
//     int sock;
//     SSL_CTX *ctx;
//
//     /* Ignore broken pipe signals */
//     signal(SIGPIPE, SIG_IGN);
//
//     ctx = create_context();
//
//     configure_context(ctx);
//
//     sock = create_socket(4433);
//
//     struct sockaddr_in addr;
//     unsigned int len = sizeof(addr);
//     SSL *ssl;
//     const char reply[] = "TLS tunnel established. hello from server\n";
//     char buf[160];
//     size_t readbytes;
//
//     int client = accept(sock, (struct sockaddr *)&addr, &len);
//     if (client < 0) {
//         perror("Unable to accept");
//         exit(EXIT_FAILURE);
//     }
//
//     ssl = SSL_new(ctx);
//     SSL_set_fd(ssl, client);
//
//     int ret = SSL_accept(ssl);
//     printf("SSL_accept returned %d\n", ret);
//     if (ret < 0) {
//         printf("Connection failed\n");
//         ERR_print_errors_fp(stderr);
//     } else if (ret == 0) {
//         printf("Connection closed by the client\n");
//     } else {
//         printf("Connection established\n");
//         // int ret = SSL_read_ex(ssl, buf, sizeof(buf), &readbytes);
//         // if (ret <= 0) {
//         //     ERR_print_errors_fp(stderr);
//         // } else if (ret == 0) {
//         //     printf("Connection closed by the client\n");
//         // } else {
//         //     // Write an answer to the client
//         //     fwrite(buf, 1, readbytes, stdout);
//         //     SSL_write(ssl, reply, strlen(reply));
//         // }
//     }
//     if (SSL_shutdown(ssl) == 0) {
//         SSL_shutdown(ssl);
//     }
//     // close(client);
//     // if (!SSL_clear(ssl)) {
//     //     printf("Failed to clear the SSL object\n");
//     // }
//     SSL_free(ssl);
//     // make new ssl object with same context
//     ssl = SSL_new(ctx);
//     SSL_set_fd(ssl, client);
//
//
//     printf("------\n");
//     // sleep(2);
//     // client = accept(sock, (struct sockaddr *)&addr, &len);
//
//     printf("waiting for SSL_accept %d\n", SSL_accept(ssl));
//     ret = SSL_accept(ssl);
//     if (ret < 0){
//         int ssl_err = SSL_get_error(ssl, ret);
//         ERR_print_errors_fp(stderr);
//         printf("SSL_accept returned error %d\n", ssl_err);
//     } else {
//         printf("SSL_accept returned %d\n", ret);
//     }
//
//
//
//
//     SSL_shutdown(ssl);
//     SSL_free(ssl);
//     close(client);
//
//     close(sock);
//     SSL_CTX_free(ctx);
// }
