#include "debug.h"
#include <openssl/bio.h>
#include "types.h"

// Default debug level
int debug_level = DEBUG_LEVEL_ERROR;

static BIO *bio_out = NULL;
static BIO *bio_err = NULL;

// Initialize debug system
void debug_initialize(void) {
    if (!bio_out) {
        bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
    }
    if (!bio_err) {
        bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    }
}

// Set debug level
void set_debug_level(int level) {
    debug_level = level;
}

// Print debug message based on level
void debug_printf(int level, const char *format, ...) {
    // Choose the appropriate BIO based on the debug level
    BIO *bio = (level == DEBUG_LEVEL_ERROR) ? bio_err : bio_out;
    if (level > debug_level || !bio) {
        return;
    }

    va_list args;
    va_start(args, format);
    // Use BIO_printf to print the formatted message directly, using variadic
    // arguments similar to vprintf
    BIO_vprintf(bio, format, args);
    va_end(args);

    // Print a newline at the end of the message
    BIO_puts(bio, "\n");
}

void debug_print_hex(int level, const char *title, const void *buf, size_t len) {
    // Choose the appropriate BIO based on the debug level
    BIO *bio = (level <= DEBUG_LEVEL_ERROR) ? bio_err : bio_out;
    if (level > debug_level || !bio) {
        return;
    }

    // Print the title directly to the BIO
    BIO_puts(bio, title);

    // The function can accept a pointer to any type of data without requiring
    // the caller to cast their data to a specific type. This makes the function
    // more flexible and easier to use in different contexts, as it can handle
    // data arrays of any type. In order to do the hexdump, the type must be
    // casted to an u8 pointer.
    const unsigned char *data = (const u8 *)buf;

    for (size_t i = 0; i < len; ++i) {
        // Print each byte in hex format directly to the BIO
        BIO_printf(bio, "%02x", data[i]);
    }

    // Print a newline at the end of the hexdump
    BIO_puts(bio, "\n");
}

// Cleanup debug system
void debug_cleanup(void) {
    if (bio_out) {
        BIO_free(bio_out);
        bio_out = NULL;
    }
    if (bio_err) {
        BIO_free(bio_err);
        bio_err = NULL;
    }
}
