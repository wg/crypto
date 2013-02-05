/**
 * Copyright (C) 2012 - Will Glozer. All rights reserved.
 *
 * AES Galois/Counter Mode (GCM) implementation using AES-NI
 * and PCLMULQDQ instructions for 64-bit x86-64 systems.
 */

#include <stdint.h>
#include <string.h>
#include "gcm.h"

void aesni_gcm_init(gcm_ctx *ctx, aes_key *key, uint8_t *iv, size_t len) {
    memset(ctx, 0, sizeof(gcm_ctx));
    ctx->key = key;
    aesni_enc(ctx->key, ctx->subkey, ctx->subkey);
    if (len == 96 / 8) {
        memcpy(ctx->block, iv, len);
        ctx->block[AES_BLOCK_LEN - 1] = 1;
        memcpy(ctx->icb, ctx->block, AES_BLOCK_LEN);
    } else {
        uint8_t block[AES_BLOCK_LEN] = { 0 };

        size_t whole = (len / AES_BLOCK_LEN) * AES_BLOCK_LEN;
        size_t partial = len % AES_BLOCK_LEN;
        aesni_gmac_update(ctx, iv, whole);

        if (partial) {
            memcpy(block, &iv[whole], partial);
            aesni_gmac_update(ctx, block, AES_BLOCK_LEN);
            memset(block, 0, AES_BLOCK_LEN);
        }

        uint64_t *ptr = (uint64_t *) &block[AES_BLOCK_LEN - 8];
        *ptr = bswap64(len * 8);
        aesni_gmac_update(ctx, block, AES_BLOCK_LEN);
        memcpy(&ctx->block, &ctx->state, AES_BLOCK_LEN);
        memcpy(&ctx->icb,   &ctx->state, AES_BLOCK_LEN);
        memset(&ctx->state, 0, AES_BLOCK_LEN * 2);
    }
}

void aesni_gcm_update_aad(gcm_ctx *ctx, uint8_t *src, size_t len) {
    size_t whole = (len / AES_BLOCK_LEN) * AES_BLOCK_LEN;
    size_t partial = len % AES_BLOCK_LEN;
    aesni_gmac_update(ctx, src, whole);
    if (partial) {
        uint8_t block[AES_BLOCK_LEN] = { 0 };
        memcpy(block, &src[whole], partial);
        aesni_gmac_update(ctx, block, AES_BLOCK_LEN);
    }
    ctx->alen += len;
}

void aesni_gcm_encrypt(gcm_ctx *ctx, uint8_t *dst, uint8_t *src, size_t len) {
    size_t whole = (len / AES_BLOCK_LEN) * AES_BLOCK_LEN;
    size_t partial = len % AES_BLOCK_LEN;
    aesni_ctr_enc(ctx->key, dst, src, whole, ctx->block);
    aesni_gmac_update(ctx, dst, whole);
    if (partial) {
        uint8_t block[AES_BLOCK_LEN] = { 0 };
        memcpy(block, &src[whole], partial);
        aesni_ctr_enc(ctx->key, block, block, AES_BLOCK_LEN, ctx->block);
        memset(&block[partial], 0, AES_BLOCK_LEN - partial);
        aesni_gmac_update(ctx, block, AES_BLOCK_LEN);
        memcpy(&dst[whole], block, partial);
    }
    ctx->clen += len;
}

void aesni_gcm_decrypt(gcm_ctx *ctx, uint8_t *dst, uint8_t *src, size_t len) {
    size_t whole = (len / AES_BLOCK_LEN) * AES_BLOCK_LEN;
    size_t partial = len % AES_BLOCK_LEN;
    aesni_gmac_update(ctx, src, whole);
    aesni_ctr_enc(ctx->key, dst, src, whole, ctx->block);
    if (partial) {
        uint8_t block[AES_BLOCK_LEN] = { 0 };
        memcpy(block, &src[whole], partial);
        aesni_gmac_update(ctx, block, AES_BLOCK_LEN);
        aesni_ctr_enc(ctx->key, block, block, AES_BLOCK_LEN, ctx->block);
        memcpy(&dst[whole], block, partial);
    }
    ctx->clen += len;
}

void aesni_gcm_final(gcm_ctx *ctx, uint8_t tag[AES_BLOCK_LEN]) {
    uint64_t *ptr = (uint64_t *) tag;
    *ptr++ = bswap64(ctx->alen * 8);
    *ptr   = bswap64(ctx->clen * 8);
    aesni_gmac_update(ctx, tag, AES_BLOCK_LEN);
    aesni_gmac_final(ctx->key, tag, ctx->icb, ctx->state);
}

uint64_t bswap64(uint64_t n) {
    __asm__("bswapq %0" : "=r"(n) : "r"(n));
    return n;
}
