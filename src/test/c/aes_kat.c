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

int aes_kat(char *filename, FILE *file) {
    enum { CBC, ECB } mode;
    enum { encrypt, decrypt, invalid } op = invalid;

    char line[1024], name[64], value[1024];
    uint8_t work[1024];

    if (strstr(filename, "CBC")) mode = CBC;
    if (strstr(filename, "ECB")) mode = ECB;

    enum { head, params } section = head;
    uint32_t lineno = 0, start = 0, tests = 0, count = 0;

    param key, iv, ct, pt;
    aes_key aes_key;

    while (fgets(line, sizeof(line), file)) {
        lineno++;
        switch (line[0]) {
            case '#':
                break;
            case '\n':
            case '\r':
                if (section == params) {
                    tests++;

                    if (!key.len || (mode == CBC && !iv.len) ) {
                        fail("INVALID KAT: bad Key or IV %s @ %d\n", filename, start);
                    }

                    aesni_set_key(&aes_key, key.value, key.len);

                    if (op == decrypt) {
                        memcpy(work, ct.value, ct.len);
                        if (mode == CBC) aesni_cbc_dec(&aes_key, work, ct.value, ct.len, iv.value);
                        if (mode == ECB) aesni_ecb_dec(&aes_key, work, ct.value, ct.len);
                        if (memcmp(work, pt.value, pt.len)) {
                            fail("FAILURE (PLAINTEXT) %s @ %d\n", filename, start);
                        }
                    } else if (op == encrypt) {
                        memcpy(work, pt.value, pt.len);
                        if (mode == CBC) aesni_cbc_enc(&aes_key, work, pt.value, pt.len, iv.value);
                        if (mode == ECB) aesni_ecb_enc(&aes_key, work, pt.value, pt.len);
                        if (memcmp(work, ct.value, ct.len)) {
                            fail("FAILURE (CIPHERTEXT) %s @ %d\n", filename, start);
                        }
                    } else {
                        fail("FAILURE (INVALID MDOE) %s @ %d\n", filename, start);
                    }

                    start = lineno + 1;
                    count++;
                }
                break;
            case '[':
                if (section != head) {
                    section = head;
                    key.len = iv.len = pt.len = ct.len = 0;
                    count   = 0;
                }
                parse_kv(line, name, value);
                if (!strcmp(name, "ENCRYPT")) op = encrypt;
                if (!strcmp(name, "DECRYPT")) op = decrypt;
                break;
            default:
                if (section != params) {
                    section = params;
                    start   = lineno;
                }
                parse_kv(line, name, value);
                if (!strcmp(name, "KEY"))        decode(name, value, &key);
                if (!strcmp(name, "IV"))         decode(name, value, &iv);
                if (!strcmp(name, "PLAINTEXT"))  decode(name, value, &pt);
                if (!strcmp(name, "CIPHERTEXT")) decode(name, value, &ct);
                if (!strcmp(name, "COUNT")) {
                    uint32_t n = atol(value);
                    if (count != n) {
                        fail("INVALID KAT: expected COUNT = %d\n", count);
                    }
                }
        }
    }

    return tests;
}
