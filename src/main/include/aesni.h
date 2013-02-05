#ifndef AESNI_H
#define AESNI_H

#define AES_BLOCK_LEN   16
#define AES128_ROUNDS   10
#define AES192_ROUNDS   12
#define AES256_ROUNDS   14
#define AES_MAXROUNDS   AES256_ROUNDS

typedef struct __attribute__((aligned)) {
    uint32_t ekey[4 * (AES_MAXROUNDS + 1)];
    uint32_t dkey[4 * (AES_MAXROUNDS + 1)];
    uint32_t klen;
} aes_key;

void aesni_set_key(aes_key *key, uint8_t *ukey, size_t len);
void aesni_enc(aes_key *key, uint8_t *dst, uint8_t *src);

void aesni_ecb_enc(aes_key *key, uint8_t *dst, uint8_t *src, size_t len);
void aesni_ecb_dec(aes_key *key, uint8_t *dst, uint8_t *src, size_t len);

void aesni_cbc_enc(aes_key *key, uint8_t *dst, uint8_t *src, size_t len, uint8_t *iv);
void aesni_cbc_dec(aes_key *key, uint8_t *dst, uint8_t *src, size_t len, uint8_t *iv);

void aesni_ctr_enc(aes_key *key, uint8_t *dst, uint8_t *src, size_t len, uint8_t *ctb);

#endif /* AESNI_H */
