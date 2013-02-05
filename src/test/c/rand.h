#ifndef TEST_H
#define TEST_H

#include "tinymt64.h"

uint64_t rand64(tinymt64_t *state, uint64_t n) {
    uint64_t x, max = ~UINT64_C(0);
    max -= max % n;
    do {
        x = tinymt64_generate_uint64(state);
    } while (x >= max);
    return x % n;
}

uint64_t time_us() {
    struct timeval t;
    gettimeofday(&t, NULL);
    return (t.tv_sec * 1000000) + t.tv_usec;
}    


#endif /* TEST_H */
