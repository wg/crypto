#ifndef CIPHER_H
#define CIPHER_H

typedef enum { sha2, sha3 } mac_type;

typedef struct {
    aes_key *key;
    uint8_t block[AES_BLOCK_LEN];
    union {
        gcm_ctx         gcm_ctx;
        hmac_sha256_ctx sha256;
        hmac_sha512_ctx sha512;
        spongeState     sha3_ctx;
    } mac_ctx;
    size_t     mac_len;
    mac_init   mac_init;
    mac_update mac_update;
    mac_final  mac_final;
} cipher_ctx;

#define GCM_CTX(ctx) (ctx->mac_ctx.gcm_ctx)

jlong JNICALL aes_init(JNIEnv *, jobject, jbyteArray, jbyteArray);
jlong JNICALL gcm_init(JNIEnv *, jobject, jbyteArray, jbyteArray);

void JNICALL authenticate(JNIEnv *, jobject, jlong, jint, jint, jbyteArray);

void JNICALL aes_update_aad(JNIEnv *, jobject, jlong, jbyteArray, jint);
jbyteArray JNICALL aes_mac(JNIEnv *, jobject, jlong);

void JNICALL cbc_encrypt(JNIEnv *, jobject, jlong, jbyteArray, jint);
void JNICALL cbc_decrypt(JNIEnv *, jobject, jlong, jbyteArray, jint);

void JNICALL ctr_encrypt(JNIEnv *, jobject, jlong, jbyteArray, jint);
void JNICALL ctr_decrypt(JNIEnv *, jobject, jlong, jbyteArray, jint);

void JNICALL gcm_update_aad(JNIEnv *, jobject, jlong, jbyteArray, jint);
void JNICALL gcm_encrypt(JNIEnv *, jobject, jlong, jbyteArray, jint);
void JNICALL gcm_decrypt(JNIEnv *, jobject, jlong, jbyteArray, jint);
jbyteArray JNICALL gcm_mac(JNIEnv *, jobject, jlong);

void JNICALL aes_reset(JNIEnv *, jobject, jlong, jbyteArray);
void JNICALL gcm_reset(JNIEnv *, jobject, jlong, jbyteArray);

void JNICALL close(JNIEnv *, jobject, jlong);

#endif /* CIPHER_H */
