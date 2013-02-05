CFLAGS := -std=c99 -Wall -O2

TARGET ?= $(shell uname -s 2>/dev/null || echo unknown)
override TARGET := $(shell echo $(TARGET) | tr A-Z a-z)

JAVA_HOME ?= $(realpath $(dir $(realpath $(shell which java)))../)

ifeq ($(TARGET), darwin)
	DYLIB     := dylib
	LDFLAGS	  := -dynamiclib -Wl,-undefined -Wl,dynamic_lookup -Wl,-single_module
	CFLAGS    += -I $(JAVA_HOME)/Headers/
else
	DYLIB     := so
	LDFLAGS   := -shared
	CFLAGS    += -fPIC
endif

ifeq ($(TARGET), linux)
	CFLAGS += -D_POSIX_C_SOURCE=200809L -D_BSD_SOURCE
endif

CFLAGS += -I $(JAVA_HOME)/include -I $(JAVA_HOME)/include/$(TARGET)
CFLAGS += -I src/main/include

OBJ  = $(patsubst src/main/c/%.c,$(OBJ_DIR)/%.o,$(wildcard src/main/c/*.c))
OBJ += $(patsubst src/main/asm/%.S,$(OBJ_DIR)/%.o,$(wildcard src/main/asm/*.S))

OBJ_DIR := target/obj
LIB     := target/libcrypto.$(DYLIB)

all: $(LIB)

clean:
	$(RM) $(LIB) $(OBJ)

$(LIB): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^

$(OBJ): | $(OBJ_DIR)

$(OBJ_DIR):
	@mkdir -p $@

test: test_aes test_base64 test_compare test_rdrand test_zero
	./test_aes
	./test_base64
	./test_compare
	./test_rdrand
	./test_zero

test_aes: target/obj/test_aes.o target/obj/aes_kat.o target/obj/gcm_kat.o \
	target/obj/cbc_mct.o target/obj/aesavs.o $(OBJ)
	$(CC) -o $@ $^

test_base64: target/obj/test_base64.o target/obj/tinymt64.o $(OBJ)
	$(CC) -o $@ $^

test_compare: target/obj/test_compare.o target/obj/tinymt64.o $(OBJ)
	$(CC) -o $@ $^

test_rdrand: target/obj/test_rdrand.o target/obj/tinymt64.o $(OBJ)
	$(CC) -o $@ $^

test_zero: target/obj/test_zero.o target/obj/tinymt64.o $(OBJ)
	$(CC) -o $@ $^

$(OBJ_DIR)/%.o : src/main/c/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ_DIR)/%.o : src/main/asm/%.S
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ_DIR)/%.o : src/test/c/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: all clean test
