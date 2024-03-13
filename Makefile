CC = cc
# Specify compile flags, library paths and libraries to link against for the
# fido extension (which will be a static library on its own).
PROJECT_CFLAGS = -I./libs/tinycbor/src -I/usr/include -I/opt/homebrew/include -g -Wall

PROJECT_SRC = $(wildcard src/*.c)
PROJECT_OBJ = $(patsubst src/%.c, build/obj/%.o, $(PROJECT_SRC))
PROJECT_TARGET = build/libfidossl.a

# Specify compile flags, library paths and libraries to link against for the
# test prorgams (client and server).
TEST_CFLAGS = -I/usr/include -I/opt/homebrew/include -I./libs/tinycbor/src -I./src -g -Wall
TEST_LDFLAGS =  -L./build -L/usr/lib/aarch64-linux-gnu -L./libs/tinycbor/lib -L/opt/homebrew/lib
TEST_LDLIBS = -lfidossl -lcrypto -lssl -lfido2 -ltinycbor -ljansson -lsqlite3

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

all: tinycbor $(PROJECT_TARGET) $(TEST_CLIENT_TARGET) $(TEST_SERVER_TARGET) $(TEST_UNIT_TARGET)

tinycbor:
	@$(MAKE) -s -C libs/tinycbor

libfido2:
	cd ./libs/libfido2/ && \
	cmake -B build && \
	make -C build

$(PROJECT_OBJ): build/obj/%.o : src/%.c
	mkdir -p $(dir $@)
	$(CC) $(PROJECT_CFLAGS) -c $< -o $@

$(TEST_CLIENT_OBJ): build/obj/%.o : test/%.c
	mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -c $< -o $@

$(TEST_SERVER_OBJ): build/obj/%.o : test/%.c
	mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -c $< -o $@

$(TEST_UNIT_OBJ): build/obj/%.o : test/%.c
	mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -c $< -o $@

$(PROJECT_TARGET): $(PROJECT_OBJ)
	mkdir -p $(dir $@)
	ar rcs $@ $(PROJECT_OBJ)

$(TEST_CLIENT_TARGET): $(TEST_CLIENT_OBJ) $(PROJECT_TARGET)
	mkdir -p $(dir $@)
	$(CC) $(TEST_LDFLAGS) -o $@ $(TEST_CLIENT_OBJ) $(TEST_LDLIBS)

$(TEST_SERVER_TARGET): $(TEST_SERVER_OBJ) $(PROJECT_TARGET)
	mkdir -p $(dir $@)
	$(CC) $(TEST_LDFLAGS) -o $@ $(TEST_SERVER_OBJ) $(TEST_LDLIBS)

$(TEST_UNIT_TARGET): $(TEST_UNIT_OBJ) $(PROJECT_TARGET)
	mkdir -p $(dir $@)
	$(CC) $(TEST_LDFLAGS) -o $@ $(TEST_UNIT_OBJ) $(TEST_LDLIBS)

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

.PHONY: all tinycbor libfido2 clean
