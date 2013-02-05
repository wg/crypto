// Copyright (C) 2012 - Will Glozer. All rights reserved.

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libgen.h>

#include "aesavs.h"
#include "aesni.h"

int cbc_mct(char *filename, FILE *file) {
    char line[1024], name[64], value[1024];

    uint8_t KEY[256], IV[AES_BLOCK_LEN];
    uint8_t CT[AES_BLOCK_LEN], PT[AES_BLOCK_LEN];
    uint8_t block[AES_BLOCK_LEN], prev[AES_BLOCK_LEN];

    enum { head, params } section = head;
    enum { encrypt, decrypt } mode;
    uint32_t lineno = 0, start = 0, tests = 0, count = 0;
    bool done = true;

    struct { param key, iv, ct, pt; } expected;
    void (*op)(aes_key *, uint8_t *, uint8_t *, size_t, uint8_t*);
    aes_key aes_key;

    while (fgets(line, sizeof(line), file)) {
        lineno++;
        switch (line[0]) {
            case '#':
                break;
            case '\n':
            case '\r':
                if (!done && section == params) {
                    tests++;
                    if (count == 0) {
                        memcpy(KEY, expected.key.value, expected.key.len);
                        memcpy(IV, expected.iv.value, expected.iv.len);
                        memcpy(PT, expected.pt.value, expected.pt.len);
                        memcpy(CT, expected.ct.value, expected.pt.len);
                    }

                    aesni_set_key(&aes_key, KEY, expected.key.len);
                    memcpy(block, IV, expected.iv.len);

                    uint8_t *SRC, *DST;

                    if (mode == encrypt) {
                        op  = &aesni_cbc_enc;
                        SRC = PT;
                        DST = CT;
                    } else {
                        op  = &aesni_cbc_dec;
                        SRC = CT;
                        DST = PT;
                    }

                    for (int j = 0; j < 1000; j++) {
                        memcpy(prev, DST, AES_BLOCK_LEN);
                        op(&aes_key, DST, SRC, AES_BLOCK_LEN, block);
                        memcpy(SRC, j == 0 ? IV : prev, AES_BLOCK_LEN);
                    }

                    if (count != 0) {
                        if (memcmp(KEY, expected.key.value, expected.key.len)) {
                            fail("FAILURE (KEY) %s @ %d\n", filename, start);
                        }
                        if (memcmp(IV, expected.iv.value, expected.iv.len)) {
                            fail("FAILURE (IV) %s @ %d\n", filename, start);
                        }
                        param *expected_p = (mode == encrypt ? &expected.ct : &expected.pt);
                        if (memcmp(DST, expected_p->value, expected_p->len)) {
                            fail("FAILURE (CIPHERTEXT) %s @ %d\n", filename, start);
                        }
                    }

                    uint8_t *K = KEY;
                    int y = abs(expected.key.len - 32);
                    for (int x = y; x < 16; x++) *K++ ^= prev[x];
                    for (int x = 0; x < 16; x++) *K++ ^=  DST[x];

                    memcpy(IV, DST, AES_BLOCK_LEN);

                    start = lineno + 1;
                    count++;
                    done = true;
                }
                break;
            case '[':
                if (section != head) {
                    section = head;
                    expected.key.len = expected.iv.len = 0;
                    expected.pt.len  = expected.ct.len = 0;
                    count   = 0;
                }
                parse_kv(line, name, value);
                if (!strcmp(name, "ENCRYPT")) mode = encrypt;
                if (!strcmp(name, "DECRYPT")) mode = decrypt;
                break;
            default:
                if (section != params) {
                    section = params;
                    start   = lineno;
                }
                parse_kv(line, name, value);
                if (!strcmp(name, "KEY"))        decode(name, value, &expected.key);
                if (!strcmp(name, "IV"))         decode(name, value, &expected.iv);
                if (!strcmp(name, "PLAINTEXT"))  decode(name, value, &expected.pt);
                if (!strcmp(name, "CIPHERTEXT")) decode(name, value, &expected.ct);
                if (!strcmp(name, "COUNT")) {
                    uint32_t n = atol(value);
                    if (count != n) {
                        fail("INVALID MCT: expected COUNT = %d\n", count);
                    }
                }
                done = false;
        }
    }

    return tests;
}
