/**
 * Copyright (C) 2012 - Will Glozer. All rights reserved.
 *
 * High performance native implementation of AES supporting
 * all keys sizes and the CBC, CTR, and GCM modes.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <jni.h>

#include "aesni.h"
#include "gcm.h"
#include "mac.h"
#include "zero.h"
#include "cipher.h"
#include "native.h"

jlong JNICALL aes_init(JNIEnv *env, jobject o, jbyteArray KEY, jbyteArray IV) {
    cipher_ctx *ctx;
    uint8_t *key = get_array(env, KEY, -1);
    uint8_t *iv  = get_array(env, IV,  -1);

    if (!key || !iv) goto cleanup;

    if (posix_memalign((void **) &ctx, 16, sizeof(cipher_ctx))) {
        throw(env, "java/lang/OutOfMemoryError", strerror(errno));
        goto cleanup;
    }

    if (posix_memalign((void **) &ctx->key, 16, sizeof(aes_key))) {
        throw(env, "java/lang/OutOfMemoryError", strerror(errno));
        goto cleanup;
    }

    aesni_set_key(ctx->key, key, (*env)->GetArrayLength(env, KEY));
    memcpy(ctx->block, iv, (*env)->GetArrayLength(env, KEY));

    ctx->mac_init   = null_init;
    ctx->mac_update = null_update;
    ctx->mac_final  = null_final;

  cleanup:

    release_array(env, KEY, key, JNI_ABORT);
    release_array(env, IV,  iv,  JNI_ABORT);
    return (jlong) ctx;
}


jlong JNICALL gcm_init(JNIEnv *env, jobject o, jbyteArray KEY, jbyteArray IV) {
    cipher_ctx *ctx;
    uint8_t *key = get_array(env, KEY, -1);
    uint8_t *iv  = get_array(env, IV,  -1);

    if (!key || !iv) goto cleanup;

    if (posix_memalign((void **) &ctx, 16, sizeof(cipher_ctx))) {
        throw(env, "java/lang/OutOfMemoryError", strerror(errno));
        return 0;
    }

    if (posix_memalign((void **) &ctx->key, 16, sizeof(aes_key))) {
        throw(env, "java/lang/OutOfMemoryError", strerror(errno));
        goto cleanup;
    }

    aesni_set_key(ctx->key, key, (*env)->GetArrayLength(env, KEY));
    aesni_gcm_init(&GCM_CTX(ctx), ctx->key, iv, (*env)->GetArrayLength(env, IV));

  cleanup:

    release_array(env, KEY, key, JNI_ABORT);
    release_array(env, IV,  iv,  JNI_ABORT);

    return (jlong) ctx;
}

void JNICALL authenticate(JNIEnv *env, jobject o, jlong state, jint type, jint bits, jbyteArray KEY) {
    cipher_ctx *ctx = (cipher_ctx *) state;
    uint8_t *key = get_array(env, KEY, -1);
    if (key) {
        memset(&ctx->mac_ctx, 0, sizeof(ctx->mac_ctx));
        ctx->mac_len = bits / 8;
        switch (type) {
            case sha2:
                switch (bits) {
                    case 256:
                        ctx->mac_init   = (mac_init)   &sha2_256_init;
                        ctx->mac_update = (mac_update) &hmac_sha256_update;
                        ctx->mac_final  = (mac_final)  &sha2_256_final;
                        break;
                    case 512:
                        ctx->mac_init   = (mac_init)   &sha2_512_init;
                        ctx->mac_update = (mac_update) &hmac_sha512_update;
                        ctx->mac_final  = (mac_final)  &sha2_512_final;
                        break;
                    default:
                        throw(env, "java/lang/IllegalArgumentException", "Invalid MAC length");
                        break;
                }
                break;
            case sha3:
                ctx->mac_init   = (mac_init)   &sha3_init;
                ctx->mac_update = (mac_update) &sha3_update;
                ctx->mac_final  = (mac_final)  &sha3_final;
                break;
        }
        ctx->mac_init(env, &ctx->mac_ctx, bits, key, (*env)->GetArrayLength(env, KEY));
    }
    release_array(env, KEY, key, JNI_ABORT);
}

void JNICALL aes_reset(JNIEnv *env, jobject o, jlong state, jbyteArray IV) {
    cipher_ctx *ctx = (cipher_ctx *) state;

    ctx->mac_init   = null_init;
    ctx->mac_update = null_update;
    ctx->mac_final  = null_final;

    uint8_t *iv = get_array(env, IV, -1);
    if (iv) {
        memcpy(ctx->block, iv, (*env)->GetArrayLength(env, IV));
    }
    release_array(env, IV, iv, JNI_ABORT);
}

void JNICALL gcm_reset(JNIEnv *env, jobject o, jlong state, jbyteArray IV) {
    cipher_ctx *ctx = (cipher_ctx *) state;

    uint8_t *iv = get_array(env, IV, -1);
    if (iv) {
        aesni_gcm_init(&GCM_CTX(ctx), ctx->key, iv, (*env)->GetArrayLength(env, IV));
    }
    release_array(env, IV, iv, JNI_ABORT);
}

void JNICALL aes_update_aad(JNIEnv *env, jobject o, jlong state, jbyteArray A, jint len) {
    cipher_ctx *ctx = (cipher_ctx *) state;
    uint8_t *bytes = get_array(env, A, len);
    if (bytes) {
        ctx->mac_update(&ctx->mac_ctx, bytes, len);
    }
    release_array(env, A, bytes, 0);
}

void JNICALL cbc_encrypt(JNIEnv *env, jobject o, jlong state, jbyteArray A, jint len) {
    cipher_ctx *ctx = (cipher_ctx *) state;
    uint8_t *bytes = get_array(env, A, len);
    if (bytes) {
        aesni_cbc_enc(ctx->key, bytes, bytes, len, ctx->block);
        ctx->mac_update(&ctx->mac_ctx, bytes, len);
        memcpy(ctx->block, &bytes[len - AES_BLOCK_LEN], AES_BLOCK_LEN);
    }
    release_array(env, A, bytes, 0);
}

void JNICALL cbc_decrypt(JNIEnv *env, jobject o, jlong state, jbyteArray A, jint len) {
    cipher_ctx *ctx = (cipher_ctx *) state;
    uint8_t *bytes = get_array(env, A, len);
    if (bytes) {
        uint8_t tmp[AES_BLOCK_LEN];
        memcpy(tmp, &bytes[len - AES_BLOCK_LEN], AES_BLOCK_LEN);
        ctx->mac_update(&ctx->mac_ctx, bytes, len);
        aesni_cbc_dec(ctx->key, bytes, bytes, len, ctx->block);
        memcpy(ctx->block, tmp, AES_BLOCK_LEN);
    }
    release_array(env, A, bytes, 0);
}

void ctr_encrypt_core(cipher_ctx *ctx, uint8_t *bytes, size_t len) {
    size_t whole   = (len / AES_BLOCK_LEN) * AES_BLOCK_LEN;
    size_t partial = len % AES_BLOCK_LEN;
    aesni_ctr_enc(ctx->key, bytes, bytes, whole, ctx->block);
    if (partial) {
        uint8_t block[AES_BLOCK_LEN];
        memcpy(block, &bytes[whole], partial);
        aesni_ctr_enc(ctx->key, block, block, AES_BLOCK_LEN, ctx->block);
        memcpy(&bytes[whole], block, partial);
    }
}

void JNICALL ctr_encrypt(JNIEnv *env, jobject o, jlong state, jbyteArray A, jint len) {
    cipher_ctx *ctx = (cipher_ctx *) state;
    uint8_t *bytes = get_array(env, A, len);
    if (bytes) {
        ctr_encrypt_core(ctx, bytes, len);
        ctx->mac_update(&ctx->mac_ctx, bytes, len);
    }
    release_array(env, A, bytes, 0);
}

void JNICALL ctr_decrypt(JNIEnv *env, jobject o, jlong state, jbyteArray A, jint len) {
    cipher_ctx *ctx = (cipher_ctx *) state;
    uint8_t *bytes = get_array(env, A, len);
    if (bytes) {
        ctx->mac_update(&ctx->mac_ctx, bytes, len);
        ctr_encrypt_core(ctx, bytes, len);
    }
    release_array(env, A, bytes, 0);
}

jbyteArray JNICALL aes_mac(JNIEnv *env, jobject o, jlong state) {
    cipher_ctx *ctx = (cipher_ctx *) state;
    jbyteArray array = new_array(env, ctx->mac_len);
    if (array) {
        uint8_t tag[ctx->mac_len];
        ctx->mac_final(env, &ctx->mac_ctx, tag, ctx->mac_len);
        (*env)->SetByteArrayRegion(env, array, 0, ctx->mac_len, (jbyte *) tag);
    }
    return array;
}

void JNICALL gcm_update_aad(JNIEnv *env, jobject o, jlong state, jbyteArray A, jint len) {
    cipher_ctx *ctx = (cipher_ctx *) state;
    uint8_t *bytes = get_array(env, A, len);
    if (bytes) {
        aesni_gcm_update_aad(&GCM_CTX(ctx), bytes, len);
    }
    release_array(env, A, bytes, 0);
}

void JNICALL gcm_encrypt(JNIEnv *env, jobject o, jlong state, jbyteArray A, jint len) {
    cipher_ctx *ctx = (cipher_ctx *) state;
    uint8_t *bytes = get_array(env, A, len);
    if (bytes) {
        aesni_gcm_encrypt(&GCM_CTX(ctx), bytes, bytes, len);
    }
    release_array(env, A, bytes, 0);
}

void JNICALL gcm_decrypt(JNIEnv *env, jobject o, jlong state, jbyteArray A, jint len) {
    cipher_ctx *ctx = (cipher_ctx *) state;
    uint8_t *bytes = get_array(env, A, len);
    if (bytes) {
        aesni_gcm_decrypt(&GCM_CTX(ctx), bytes, bytes, len);
    }
    release_array(env, A, bytes, 0);
}

jbyteArray JNICALL gcm_mac(JNIEnv *env, jobject o, jlong state) {
    cipher_ctx *ctx = (cipher_ctx *) state;
    jbyteArray array = new_array(env, AES_BLOCK_LEN);
    if (array) {
        uint8_t tag[AES_BLOCK_LEN];
        aesni_gcm_final(&GCM_CTX(ctx), tag);
        (*env)->SetByteArrayRegion(env, array, 0, AES_BLOCK_LEN, (jbyte *) tag);
    }
    return array;
}

void JNICALL close(JNIEnv *env, jobject o, jlong state) {
    cipher_ctx *ctx = (cipher_ctx *) state;
    zero(ctx->key, sizeof(aes_key));
    free(ctx->key);
    zero(ctx, sizeof(cipher_ctx));
    free(ctx);
}
