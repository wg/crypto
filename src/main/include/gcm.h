#ifndef GCM_H
#define GCM_H

#include "aesni.h"

typedef struct {
    uint8_t  subkey[AES_BLOCK_LEN];
    uint8_t   state[AES_BLOCK_LEN];
    uint8_t initial[AES_BLOCK_LEN];
    uint8_t   block[AES_BLOCK_LEN];
    uint8_t     icb[AES_BLOCK_LEN];
    aes_key    *key;
    uint64_t   alen;
    uint64_t   clen;
} gcm_ctx;

void aesni_gcm_init(gcm_ctx *ctx, aes_key *key, uint8_t *iv, size_t len);
void aesni_gcm_update_aad(gcm_ctx *ctx, uint8_t *src, size_t len);
void aesni_gcm_encrypt(gcm_ctx *ctx, uint8_t *dst, uint8_t *src, size_t len);
void aesni_gcm_decrypt(gcm_ctx *ctx, uint8_t *dst, uint8_t *src, size_t len);
void aesni_gcm_final(gcm_ctx *ctx, uint8_t tag[AES_BLOCK_LEN]);

void aesni_gmac_update(gcm_ctx *ctx, uint8_t *src, size_t len);
void aesni_gmac_final(aes_key *ctx, uint8_t *tag, uint8_t *icb, uint8_t *state);

uint64_t bswap64(uint64_t n);

#endif /* GCM_H */
