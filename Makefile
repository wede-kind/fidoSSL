CC = cc

# Detect operating system
UNAME_S := $(shell uname -s)

# Using pkg-config to set flags for dependencies
PKG_CONFIG_DEPS = libssl libfido2 tinycbor jansson sqlite3

# Define required versions for dependencies
LIBFIDO2_REQUIRED_VERSION := 1.14.0
OPENSSL_REQUIRED_VERSION := 3.2.1
JANSSON_REQUIRED_VERSION := 2.14
SQLITE_REQUIRED_VERSION := 3.39.5
TINYCBOR_REQUIRED_VERSION := 0.6.0

# Define PKG_CONFIG_PATH
CUSTOM_PKG_CONFIG_PATH := $(shell pwd)/libs/pkgconfig

PKG_CONFIG := PKG_CONFIG_PATH=$(CUSTOM_PKG_CONFIG_PATH) pkg-config

# Retrieve flags for compiling and linking
CFLAGS = $(shell $(PKG_CONFIG) --cflags $(PKG_CONFIG_DEPS)) -I./src -g -Wall

# Use pkg-config to get linker flags
LIBS = $(shell $(PKG_CONFIG) --libs $(PKG_CONFIG_DEPS))

# Generate -rpath flags based on library paths from pkg-config and remove
# duplicates
RPATH_FLAGS = $(shell $(PKG_CONFIG) --libs-only-L $(PKG_CONFIG_DEPS) \
			  | sed 's/-L/-Wl,-rpath,/g' | tr ' ' '\n' | sort -u | tr '\n' ' ')

LDFLAGS = $(LIBS) $(RPATH_FLAGS)

PROJECT_SRC = $(wildcard src/*.c)
PROJECT_OBJ = $(patsubst src/%.c, build/obj/%.o, $(PROJECT_SRC))
PROJECT_TARGET = build/libfidossl.a

TEST_CLIENT_SRC = test/client.c
TEST_SERVER_SRC = test/server.c
TEST_UNIT_SRC = test/unit_tests.c
TEST_CLIENT_OBJ = $(patsubst test/%.c, build/obj/%.o, $(TEST_CLIENT_SRC))
TEST_SERVER_OBJ = $(patsubst test/%.c, build/obj/%.o, $(TEST_SERVER_SRC))
TEST_UNIT_OBJ = $(patsubst test/%.c, build/obj/%.o, $(TEST_UNIT_SRC))
TEST_CLIENT_TARGET = build/client
TEST_SERVER_TARGET = build/server
TEST_UNIT_TARGET = build/unit_tests

# Add installation paths
PREFIX = /usr/local
LIBDIR = $(PREFIX)/lib
INCLUDEDIR = $(PREFIX)/include

# Define the header files to install
HEADERS = $(wildcard src/*.h)

all: check-versions $(PROJECT_TARGET) $(TEST_CLIENT_TARGET) $(TEST_SERVER_TARGET) $(TEST_UNIT_TARGET)

$(PROJECT_OBJ): build/obj/%.o : src/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(TEST_CLIENT_OBJ): build/obj/%.o : test/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(TEST_SERVER_OBJ): build/obj/%.o : test/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(TEST_UNIT_OBJ): build/obj/%.o : test/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(PROJECT_TARGET): $(PROJECT_OBJ)
	mkdir -p $(dir $@)
	ar rcs $@ $(PROJECT_OBJ)

$(TEST_CLIENT_TARGET): $(TEST_CLIENT_OBJ) $(PROJECT_TARGET)
	mkdir -p $(dir $@)
	$(CC) -o $@ $(TEST_CLIENT_OBJ) $(PROJECT_TARGET) $(LDFLAGS)

$(TEST_SERVER_TARGET): $(TEST_SERVER_OBJ) $(PROJECT_TARGET)
	mkdir -p $(dir $@)
	$(CC) -o $@ $(TEST_SERVER_OBJ) $(PROJECT_TARGET) $(LDFLAGS)

$(TEST_UNIT_TARGET): $(TEST_UNIT_OBJ) $(PROJECT_TARGET)
	mkdir -p $(dir $@)
	$(CC) -o $@ $(TEST_UNIT_OBJ) $(PROJECT_TARGET) $(LDFLAGS)

clean:
	rm -rf build

# Add an install target
install: $(PROJECT_TARGET)
	mkdir -p $(LIBDIR)
	mkdir -p $(INCLUDEDIR)/fidossl
	cp $(PROJECT_TARGET) $(LIBDIR)
	cp $(HEADERS) $(INCLUDEDIR)/fidossl

# Add an uninstall target for cleanup
uninstall:
	rm -f $(LIBDIR)/$(notdir $(PROJECT_TARGET))
	rm -rf $(INCLUDEDIR)/fidossl

check-versions:
	@$(PKG_CONFIG) --atleast-version=$(LIBFIDO2_REQUIRED_VERSION) libfido2 || \
		(echo "libfido2 $(LIBFIDO2_REQUIRED_VERSION) or higher is required" && false)
	@$(PKG_CONFIG) --atleast-version=$(OPENSSL_REQUIRED_VERSION) libssl || \
		(echo "OpenSSL $(OPENSSL_REQUIRED_VERSION) or higher is required" && false)
	@$(PKG_CONFIG) --atleast-version=$(JANSSON_REQUIRED_VERSION) jansson || \
		(echo "Jansson $(JANSSON_REQUIRED_VERSION) or higher is required" && false)
	@$(PKG_CONFIG) --atleast-version=$(SQLITE_REQUIRED_VERSION) sqlite3 || \
		(echo "SQLite $(SQLITE_REQUIRED_VERSION) or higher is required" && false)
	@$(PKG_CONFIG) --atleast-version=$(TINYCBOR_REQUIRED_VERSION) tinycbor || \
		(echo "TinyCBOR $(TINYCBOR_REQUIRED_VERSION) or higher is required" && false)

.PHONY: all clean
