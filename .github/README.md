# FIDO2 TLS1.3 Extension



**fidoSSL** is a proof of concept implementation of a TLS1.3 extension that incorporates [FIDO](https://fidoalliance.org/what-is-fido/) authentication into [openSSL](https://www.openssl.org/), aiming to enhance security and user authentication processes. This project serves as a foundational draft for further studies and development in the realm of secure communications.

### Features

- Implements FIDO authentication within the TLS protocol
- Uses the TLS1.3 extension mechanism ([RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446#section-4.2))
- The extension is compiled as shared library and can be added as openSSL callbacks to the applciation layer code

### Prerequisites

- C programming environment (GCC, Clang, etc.)
- Dependencies: 
  - **libssl**, **libcrypto** (openSSL)
  - **libfido2** (high level API for WebAuthn & CTAP)
  - **tinycbor** (CBOR encoder & parser)
  - **sqlite3** (SQLite database)
  - **libjansson** (JSON encoder & parser)
- Basic TLS concepts and how it is used in openSSL [[link1](https://www.openssl.org/docs/man3.2/man7/ossl-guide-introduction.html), [link2](https://www.openssl.org/docs/man3.2/man7/ossl-guide-tls-introduction.html), [link3](https://www.openssl.org/docs/man3.2/man7/ossl-guide-tls-client-non-block.html), [link4](https://www.openssl.org/docs/man3.2/man7/ossl-guide-tls-client-block.html)]

### Installation

##### macOS

On macOS, the dependencies can be installed with [homebrew](https://brew.sh/)

```bash
# Update homebrew in order to get the newest formulas
brew update

# Install dependencies
brew install openssl libfido2 sqlite jansson
```

##### ubuntu

On Ubuntu, dependencies can be installed with [aptitude](https://wiki.ubuntuusers.de/aptitude/)

```sh
# Update apt in order to get the newest packages sources
sudo apt update

# Install dependencies
sudo apt install build-essential libssl-dev libfido2-dev libtinycbor-dev  libjansson-dev
```

### Usage

This section outlines the steps required to seamlessly incorporate `libfidossl` into your project. Ensure you've met all [Prerequisites](#Prerequisites), including a basic understanding of OpenSSL in C, before proceeding.



First, link the `libfidossl` shared library with your application. Update your Makefile to include the library's path in the linker flags:

```makefile
LDFLAGS = -L/path/to/libfidossl
LDLIBS = -lfidossl
```



The following comprehensive example demonstrates how to integrate the  FIDO authentication extension within a client and server application, utilizing  OpenSSL for the setup. **Please note**: This example specifically focuses on illustrating how to add `libfidossl` to your application. It intentionally skips intermediate steps related to general OpenSSL setup and usage, which should be implemented as per OpenSSL's documentation and best practices.

##### Client

```c
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fidossl.h>

// Assume you have already created a SSL context object according to you applications needs
SSL_CTX *ctx;

// Enforce TLS 1.3
if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)) {
    printf("Failed to set TLS version 1.3\n");
    exit(EXIT_FAILURE);
}

// Since the extension uses the client certificates extension context, we must provide a
// client certificate and a private key
if (SSL_CTX_use_certificate_file(ctx, "/path/to/client.crt", SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}
if (SSL_CTX_use_PrivateKey_file(ctx, "/path/to/client.key", SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

// Create the client options for the FIDO authenticaiton
FIDOSSL_CLIENT_OPTS *opts = malloc(sizeof(FIDOSSL_CLIENT_OPTS));

// Modes are: FIDOSSL_REGISTER or FIDOSSL_AUTHENTICATE
opts->mode = FIDOSSL_REGISTER;

// Define a user and user display name.
// When in FIDOSSL_AUTHENTICATE mode, this setting is ignored.
opts->user_name = "alice";
opts->user_display_name = "Alice";

// In FIDOSSL_REGISTER mode, new fido keys are only enrolled if the client provides a valid ticket.
// Client and Server must be configured with the same ticket. The ticket is base64 encoded.
// When in FIDOSSL_AUTHENTICATE mode, this option is ignored.
opts->ticket_b64 = "y1v2BsTzi6baajWpU5WSDw6AYorx2MSDO1iVFSQC8VQ=";

// The PIN of the FIDO token.
opts->pin = "1234";

// Optional: Debug levels are: DEBUG_LEVEL_ERROR, DEBUG_LEVEL_VERBOSE, DEBUG_LEVEL_MORE_VERBOSE.
opts->debug_level = DEBUG_LEVEL_MORE_VERBOSE;

// Register the extension with the specified options
SSL_CTX_add_custom_ext(
    ctx,
    FIDOSSL_EXT_TYPE,
    FIDOSSL_CONTEXT,
    fidossl_client_add_cb,
    fidossl_client_free_cb,
    opts,
    fidossl_client_parse_cb,
    NULL
);

// Create a SSL object out of the SSL context object as usual
SSL *ssl = SSL_new(ctx);

// Create a socket, connect to the socket and associate the socket with the
// SSL object as usual ...

// Important: Set a Server Name Indication (SNI). The extension requires a SNI.
if (!SSL_set_tlsext_host_name(ssl, "https://my-server-name.com")) {
    printf("Failed to set the SNI\n");
}

// Connect to the Server as usual (do the handshake)
if (SSL_connect(ssl) != 1) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

// In we want to register new fido keys, a second handshake is necessary
// Only do a second handshake if we want to register a new credential
if (opts->mode == FIDOSSL_REGISTER) {
  
    // Shutdown the first connection
    while (SSL_shutdown(ssl) != 1) {}
  
    // Create new SSL object out of the context object
    SSL_free(ssl);
    ssl = SSL_new(ctx);
  
  	// Connect the SSL object to the socket as usual... The socket can be kept open,
  	// the new TLS handshake reuses the TCP connection

    // Set the SNI hostname as before ..

    // Connect to server again
    if (SSL_connect(ssl) != 1) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Shutdown SSL connection
    while (SSL_shutdown(ssl) != 1) {}
}

// The caller is responsible for freeing the client options,
// the extension keeps no references, all data is copied.
free(opts);

// Free the SSL and SSL_CTX, close the socket, free the socket as usual ...
```

n

