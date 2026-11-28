# Secure Password Manager
#
#   make            build ./pm
#   make run        build and start the program
#   make test       unit tests + end-to-end tests (takes about a minute)
#   make asan       build ./build/pm_asan with AddressSanitizer + UBSan
#   make test-asan  run the end-to-end tests against the sanitizer build
#   make clean      remove build output
#
# Needs: gcc (or cc), make, libssl-dev, libcrypt-dev
#   Debian/Ubuntu: sudo apt install build-essential libssl-dev libcrypt-dev

CC      ?= cc
CFLAGS  ?= -std=gnu11 -O2 -Wall -Wextra -Wformat=2 \
           -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE
LDFLAGS ?= -pie -Wl,-z,relro,-z,now
LDLIBS  := -lcrypt -lcrypto

SRCS  := $(wildcard src/*.c)
HDRS  := $(wildcard src/*.h)
BUILD := build

# Test builds shorten two waits: a password reveal lasts 1 second (not 10)
# and an idle session expires after 3 seconds (not 15 minutes).
TEST_DEFS := -DREVEAL_SECONDS=1 -DSESSION_TIMEOUT_SECONDS=3

.PHONY: all run test test-unit test-app asan test-asan clean help

all: pm

pm: $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) $(SRCS) $(LDFLAGS) $(LDLIBS) -o $@

run: pm
	./pm

$(BUILD):
	mkdir -p $(BUILD)

# Unit tests for the crypto module and for secret handling in memory.
$(BUILD)/test_crypto: src/crypto.c src/crypto.h tests/test_crypto.c | $(BUILD)
	$(CC) $(CFLAGS) -Isrc src/crypto.c tests/test_crypto.c $(LDFLAGS) $(LDLIBS) -o $@

$(BUILD)/test_memory: src/crypto.c src/crypto.h src/utils.c src/utils.h tests/test_memory.c | $(BUILD)
	$(CC) $(CFLAGS) -Isrc src/crypto.c src/utils.c tests/test_memory.c $(LDFLAGS) $(LDLIBS) -o $@

$(BUILD)/pm_test: $(SRCS) $(HDRS) | $(BUILD)
	$(CC) $(CFLAGS) $(TEST_DEFS) $(SRCS) $(LDFLAGS) $(LDLIBS) -o $@

test: test-unit test-app

test-unit: $(BUILD)/test_crypto $(BUILD)/test_memory
	./$(BUILD)/test_crypto
	./$(BUILD)/test_memory

test-app: $(BUILD)/pm_test
	bash tests/test_app.sh ./$(BUILD)/pm_test

# PM_KEEP_DUMPABLE: the leak checker needs to attach to the process itself.
asan: $(SRCS) $(HDRS) | $(BUILD)
	$(CC) -std=gnu11 -O1 -g -Wall -Wextra -fsanitize=address,undefined \
	    -fno-omit-frame-pointer -DPM_KEEP_DUMPABLE $(TEST_DEFS) \
	    $(SRCS) $(LDLIBS) -o $(BUILD)/pm_asan $(LDLIBS) -o $(BUILD)/pm_asan

test-asan: asan
	bash tests/test_app.sh ./$(BUILD)/pm_asan

clean:
	rm -rf $(BUILD) pm

help:
	@sed -n '3,9p' Makefile