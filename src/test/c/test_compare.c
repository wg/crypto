// Copyright (C) 2012 - Will Glozer. All rights reserved.

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "compare.h"
#include "test.h"

int main(int argc, char **argv) {
    uint8_t a[1024];
    uint8_t b[1024];

    tinymt64_t rand;
    tinymt64_init(&rand, time_us());
    
    for (int i = 0; i < 1024; i++) {
        memset(a, 0, sizeof(a));
        memset(b, 0, sizeof(b));

        uint64_t bit   = rand64(&rand, 8);
        uint64_t len   = rand64(&rand, sizeof(a)) + 1;
        uint64_t index = rand64(&rand, len);

        assert(compare(a, b, len) == 0);

        uint8_t *array = i % 2 ? a : b;
        array[index] |= 1 << bit;

        assert(compare(a, b, len) == 1);
    }

    return 0;
}
