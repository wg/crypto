// Copyright (C) 2012 - Will Glozer. All rights reserved.

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

#include "rdrand.h"
#include "test.h"

#define RDRAND_FLAG (1 << 30)

int main(int argc, char **argv) {
    uint8_t bytes[4096];
    int loops = 1024;
    uint64_t counts[256] = { 0 };

    uint32_t eax, ebx, ecx, edx;
    __asm__("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(1));
    if (!(ecx & RDRAND_FLAG)) {
        printf("CPU does not support RDRAND, skipping test\n");
        exit(0);
    }

    for (int i = 0; i < loops; i++) {
        memset(bytes, 0, sizeof(bytes));
        assert(rdrand_bytes(bytes, sizeof(bytes), i) == 1);
        for (int j = 0; j < i; j++) {
            counts[bytes[j]]++;
        }
    }

    uint64_t avg = 0;
    for (int j = 0; j < 256; j++) {
        assert(counts[j] > 0);
        avg += counts[j];
    }
    avg /= 256;

    for (int j = 0; j < 256; j++) {
        assert(counts[j] >= avg - (avg * 0.15));
        assert(counts[j] <= avg + (avg * 0.15));
    }

    return 0;
}
