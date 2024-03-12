#ifndef DEBUG_H
#define DEBUG_H

#include <stddef.h>

// Debug levels
#define DEBUG_LEVEL_ERROR   0
#define DEBUG_LEVEL_VERBOSE 1
#define DEBUG_LEVEL_MORE_VERBOSE 2

// Global debug level variable
extern int debug_level;

// Function prototypes
void set_debug_level(int level);
void debug_printf(int level, const char *format, ...);
void debug_print_hex(int level, const char *title, const void *buf, size_t len);
void debug_initialize(void);
void debug_cleanup(void);

#endif // DEBUG_H
