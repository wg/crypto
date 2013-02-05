// Copyright (C) 2012 - Will Glozer. All rights reserved.

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>

#include "base64.h"
#include "test.h"

#define DECODE(DECODED, ENCODED, PAD) {                         \
    size_t len = strlen(ENCODED);                               \
    uint8_t *out = decode64((uint8_t *) ENCODED, &len, PAD);    \
    assert(strlen(DECODED) == len);                             \
    assert(memcmp(DECODED, out, len) == 0);                     \
}

#define DECODE_URL(DECODED, ENCODED, PAD) {                     \
    size_t len = strlen(ENCODED);                               \
    uint8_t *out = decode64url((uint8_t *) ENCODED, &len, PAD); \
    assert(strlen(DECODED) == len);                             \
    assert(memcmp(DECODED, out, len) == 0);                     \
}

#define ENCODE(ENCODED, DECODED, PAD) {                         \
    size_t len = strlen((const char *)DECODED);                 \
    uint8_t *out = encode64((uint8_t *) DECODED, &len, PAD);    \
    assert(strlen(ENCODED) == len);                             \
    assert(memcmp(ENCODED, out, len) == 0);                     \
}

#define ENCODE_URL(ENCODED, DECODED, PAD) {                     \
    size_t len = strlen((const char *)DECODED);                 \
    uint8_t *out = encode64url((uint8_t *) DECODED, &len, PAD); \
    assert(strlen(ENCODED) == len);                             \
    assert(memcmp(ENCODED, out, len) == 0);                     \
}

int main(int argc, char **argv) {
    DECODE("",       "",         true);
    DECODE("f",      "Zg==",     true);
    DECODE("fo",     "Zm8=",     true);
    DECODE("foo",    "Zm9v",     true);
    DECODE("foob",   "Zm9vYg==", true);
    DECODE("fooba",  "Zm9vYmE=", true);
    DECODE("foobar", "Zm9vYmFy", true);

    ENCODE("",         "",        true);
    ENCODE("Zg==",     "f",       true);
    ENCODE("Zm8=",     "fo",      true);
    ENCODE("Zm9v",     "foo",     true);
    ENCODE("Zm9vYg==", "foob",    true);
    ENCODE("Zm9vYmE=", "fooba",   true);
    ENCODE("Zm9vYmFy", "foobar",  true);

    DECODE("",       "",         false);
    DECODE("f",      "Zg",       false);
    DECODE("fo",     "Zm8",      false);
    DECODE("foo",    "Zm9v",     false);
    DECODE("foob",   "Zm9vYg",   false);
    DECODE("fooba",  "Zm9vYmE",  false);
    DECODE("foobar", "Zm9vYmFy", false);

    ENCODE("",         "",        false);
    ENCODE("Zg",       "f",       false);
    ENCODE("Zm8",      "fo",      false);
    ENCODE("Zm9v",     "foo",     false);
    ENCODE("Zm9vYg",   "foob",    false);
    ENCODE("Zm9vYmE",  "fooba",   false);
    ENCODE("Zm9vYmFy", "foobar",  false);

    uint8_t bytes[] = { 0x2a, 0xfe, 0xff, 0xfa, 0 };
    ENCODE    ("Kv7/+g==", bytes, true);
    ENCODE_URL("Kv7_-g..", bytes, true);
    ENCODE_URL("Kv7_-g",   bytes, false);

    const size_t MAX = 1024;
    tinymt64_t rand;
    tinymt64_init(&rand, time_us());

    int fd = open("/dev/urandom", O_RDONLY);
    assert(fd > 0);

    // test encoding random bytes
    for (int i = 0; i < 10000; i++) {
        size_t bytes = rand64(&rand, MAX);
        bool pad = (bool) rand64(&rand, 2);
        uint8_t *src = malloc(bytes);
        size_t len;

        assert(read(fd, src, bytes) == bytes);

        len = bytes;
        uint8_t *encoded = encode64(src, &len, pad);
        assert(bytes == 0 || len > bytes);

        uint8_t *decoded = decode64(encoded, &len, pad);
        assert(len == bytes);
        assert(memcmp(decoded, src, bytes) == 0);

        free(decoded);
        free(encoded);
        free(src);
    }

    // test decoding random invalid base64
    for (int i = 0; i < 100000; i++) {
        uint64_t bytes = rand64(&rand, MAX);
        bool pad = (bool) rand64(&rand, 2);
        uint8_t *src = malloc(bytes);

        assert(read(fd, src, bytes) == bytes);

        size_t len = bytes;
        uint8_t *decoded = decode64(src, &len, pad);
        assert(len <= bytes);

        free(decoded);
        free(src);
    }

    return 0;
}
