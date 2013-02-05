// Copyright (C) 2012 - Will Glozer. All rights reserved.

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libgen.h>

#include "aesavs.h"
#include "gcm.h"

int gcm_kat(char *filename, FILE *file) {
    enum { encrypt, decrypt } mode;

    char line[1024], name[64], value[1024];
    uint8_t work[1024], calculated_tag[1024];
    mode = strcasestr(filename, "decrypt") ? decrypt : encrypt;

    enum { head, params } section = head;
    uint32_t lineno = 0, start = 0, tests = 0, count = 0;

    param key, iv, aad, ct, pt, tag;

    bool should_fail;
    aes_key aes_key;
    gcm_ctx ctx;

    while (fgets(line, sizeof(line), file)) {
        lineno++;
        switch (line[0]) {
            case '#':
                break;
            case '\n':
            case '\r':
                if (section == params) {
                    tests++;

                    if (!key.len || !iv.len || !tag.len) {
                        fail("INVALID KAT: bad Key, IV, or Tag %s @ %d\n", filename, start);
                    }

                    aesni_set_key(&aes_key, key.value, key.len);
                    aesni_gcm_init(&ctx, &aes_key, iv.value, iv.len);
                    if (aad.len) aesni_gcm_update_aad(&ctx, aad.value, aad.len);

                    if (mode == decrypt) {
                        aesni_gcm_decrypt(&ctx, work, ct.value, ct.len);
                        aesni_gcm_final(&ctx, calculated_tag);

                        if (should_fail) {
                            if (!memcmp(calculated_tag, tag.value, tag.len)) {
                                fail("FAILURE (TAG) %s @ %d\n", filename, start);
                            }
                        } else {
                            if (memcmp(calculated_tag, tag.value, tag.len)) {
                                fail("FAILURE (TAG) %s @ %d\n", filename, start);
                            }
                            if (memcmp(work, pt.value, pt.len)) {
                                fail("FAILURE (PLAINTEXT) %s @ %d\n", filename, start);
                            }
                        }
                    } else if (mode == encrypt) {
                        aesni_gcm_encrypt(&ctx, work, pt.value, pt.len);
                        aesni_gcm_final(&ctx, calculated_tag);

                        if (memcmp(calculated_tag, tag.value, tag.len)) {
                            fail("FAILURE (TAG) %s @ %d\n", filename, start);
                        }

                        if (memcmp(work, ct.value, ct.len)) {
                            fail("FAILURE (CIPHERTEXT) %s @ %d\n", filename, start);
                        }
                    }

                    start = lineno + 1;
                    should_fail = false;
                    count++;
                }
                break;
            case '[':
                if (section != head) {
                    section = head;
                    key.len = iv.len = aad.len = 0;
                    pt.len  = ct.len = tag.len = 0;
                    count   = 0;
                }
                parse_kv(line, name, value);
                if (!strcmp(name, "Keylen")) key.len = atol(value) / 8;
                if (!strcmp(name, "IVlen"))   iv.len = atol(value) / 8;
                if (!strcmp(name, "AADlen")) aad.len = atol(value) / 8;
                if (!strcmp(name, "PTlen"))   pt.len = atol(value) / 8;
                if (!strcmp(name, "PTlen"))   ct.len = atol(value) / 8;
                if (!strcmp(name, "Taglen")) tag.len = atol(value) / 8;
                break;
            default:
                if (section != params) {
                    section = params;
                    start   = lineno;
                }
                parse_kv(line, name, value);
                if (!strcmp(name, "Key"))  decode(name, value, &key);
                if (!strcmp(name, "IV"))   decode(name, value, &iv);
                if (!strcmp(name, "AAD"))  decode(name, value, &aad);
                if (!strcmp(name, "PT"))   decode(name, value, &pt);
                if (!strcmp(name, "CT"))   decode(name, value, &ct);
                if (!strcmp(name, "Tag"))  decode(name, value, &tag);
                if (!strcmp(name, "FAIL")) should_fail = true;

                if (!strcmp(name, "Count")) {
                    uint32_t n = atol(value);
                    if (count != n) {
                        fail("INVALID KAT: expected Count = %d\n", count);
                    }
                }
        }
    }

    return tests;
}
