/**
 * Copyright (C) 2012 - Will Glozer. All rights reserved.
 *
 * Common interface to standard MAC constructs including
 * SHA2-256, SHA2-512, and SHA-3.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <jni.h>

#include "native.h"
#include "mac.h"

void sha2_256_init(JNIEnv *env, void *ctx, size_t bits, uint8_t *key, size_t len) {
    hmac_sha256_init((hmac_sha256_ctx *) ctx, key, len);
}

void sha2_256_final(JNIEnv *env, void *ctx, uint8_t *mac, size_t len) {
    hmac_sha256_final((hmac_sha256_ctx *) ctx, mac, len);
}

void sha2_512_init(JNIEnv *env, void *ctx, size_t bits, uint8_t *key, size_t len) {
    hmac_sha512_init((hmac_sha512_ctx *) ctx, key, len);
}

void sha2_512_final(JNIEnv *env, void *ctx, uint8_t *mac, size_t len) {
    hmac_sha512_final((hmac_sha512_ctx *) ctx, mac, len);
}

void sha3_init(JNIEnv *env, spongeState *ctx, size_t bits, uint8_t *key, size_t len) {
    switch (bits) {
        case 256:
            InitSponge(ctx, 1088, 512);
            break;
        case 512:
            InitSponge(ctx, 576, 1024);
            break;
        default:
            throw(env, "java/lang/IllegalArgumentException", "Invalid MAC length");
            return;
    }
    ctx->fixedOutputLength = bits;
    Absorb(ctx, key, len * 8);
}

void sha3_update(spongeState *ctx, uint8_t *data, size_t len) {
    Absorb(ctx, data, len * 8);
}

void sha3_final(JNIEnv *env, spongeState *ctx, uint8_t *mac, size_t len) {
    Squeeze(ctx, mac, ctx->fixedOutputLength);
}

void null_init(JNIEnv *env, void *ctx, size_t bits, uint8_t *key, size_t len) {}
void null_update(void *ctx, uint8_t *data, size_t len)                        {}
void null_final(JNIEnv *env, void *ctx, uint8_t *mac, size_t len) {
    throw(env, "java/lang/IllegalStateException", "Cipher is not authenticated");
}
