/**
 * Copyright (C) 2012 - Will Glozer. All rights reserved.
 *
 * High performance native cryptography and related utilities
 * for the JVM. This code uses the AES-NI, PCLMULQDQ, and
 * RDRAND instructions available on certain x86-64 CPUs.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <jni.h>

#include "aesni.h"
#include "gcm.h"
#include "mac.h"
#include "cipher.h"
#include "rdrand.h"
#include "compare.h"
#include "native.h"

#define PCLMUL_FLAG (1 <<  1)
#define  AESNI_FLAG (1 << 25)
#define RDRAND_FLAG (1 << 30)

void JNICALL bytes(JNIEnv *env, jclass cls, jbyteArray A, jint len) {
    uint8_t *bytes = get_array(env, A, len);
    if (bytes) {
        if (!rdrand_bytes(bytes, len, 10)) {
            throw(env, "java/lang/IllegalStateException", "RDRAND retries exhausted");
        }
    }
    release_array(env, A, bytes, 0);
}

jlong JNICALL uniform(JNIEnv *env, jclass cls, jlong n) {
    uint64_t x, max = ~UINT64_C(0);
    max -= max % n;

    do {
        if (!rdrand_bytes((uint8_t *) &x, sizeof(x), 10)) {
            throw(env, "java/lang/IllegalStateException", "RDRAND retries exhausted");
            return 0;
        }
    } while (x >= max);

    return (jlong) (x % n);
}

jboolean JNICALL acompare(JNIEnv *env, jclass cls, jbyteArray A, jbyteArray B, jint len) {
    uint8_t *a = get_array(env, A, len);
    uint8_t *b = get_array(env, B, len);

    jboolean result = (a && b) && compare(a, b, len) == 0;

    release_array(env, A, a, JNI_ABORT);
    release_array(env, B, b, JNI_ABORT);

    return result;
}

void JNICALL unsupported(JNIEnv *env, ...) {
    throw(env, "java/lang/UnsupportedOperationException", "");
}

static JNINativeMethod cipher_methods[] = {
    { "authenticate", "(JII[B)V", (void *) authenticate },
    { "close",        "(J)V",     (void *) close        },
};

static JNINativeMethod cbc_methods[] = {
    { "init",    "([B[B)J",  (void *) aes_init       },
    { "aad",     "(J[BI)V",  (void *) aes_update_aad },
    { "encrypt", "(J[BI)V",  (void *) cbc_encrypt    },
    { "decrypt", "(J[BI)V",  (void *) cbc_decrypt    },
    { "mac",     "(J)[B",    (void *) aes_mac        },
    { "reset",   "(J[B)V",   (void *) aes_reset      },
};

static JNINativeMethod ctr_methods[] = {
    { "init",    "([B[B)J",  (void *) aes_init       },
    { "aad",     "(J[BI)V",  (void *) aes_update_aad },
    { "encrypt", "(J[BI)V",  (void *) ctr_encrypt    },
    { "decrypt", "(J[BI)V",  (void *) ctr_decrypt    },
    { "mac"   ,  "(J)[B",    (void *) aes_mac        },
    { "reset",   "(J[B)V",   (void *) aes_reset      },
};

static JNINativeMethod gcm_methods[] = {
    { "init",    "([B[B)J",  (void *) gcm_init       },
    { "aad",     "(J[BI)V",  (void *) gcm_update_aad },
    { "encrypt", "(J[BI)V",  (void *) gcm_encrypt    },
    { "decrypt", "(J[BI)V",  (void *) gcm_decrypt    },
    { "mac",     "(J)[B",    (void *) gcm_mac        },
    { "reset",   "(J[B)V",   (void *) gcm_reset      },
};

static JNINativeMethod random_methods[] = {
    { "bytes",   "([BI)V",   (void *) bytes    },
    { "uniform", "(J)J",     (void *) uniform  },
};

static JNINativeMethod crypto_methods[] = {
    { "compare", "([B[BI)Z", (void *) acompare },
};

jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env;

    if ((*vm)->GetEnv(vm, (void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return -1;
    }

    uint32_t eax, ebx, ecx, edx;
    __asm__("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(1));

    bool have_aesni  = ecx & AESNI_FLAG;
    bool have_pclmul = ecx & PCLMUL_FLAG;
    bool have_rdrand = ecx & RDRAND_FLAG;

    jclass crypto = (*env)->FindClass(env, "com/lambdaworks/crypto/Crypto");
    jfieldID field;

    field = (*env)->GetStaticFieldID(env, crypto, "AESNI",  "Z");
    (*env)->SetStaticBooleanField(env, crypto, field, have_aesni);
    field = (*env)->GetStaticFieldID(env, crypto, "PCLMUL", "Z");
    (*env)->SetStaticBooleanField(env, crypto, field, have_pclmul);
    field = (*env)->GetStaticFieldID(env, crypto, "RDRAND", "Z");
    (*env)->SetStaticBooleanField(env, crypto, field, have_rdrand);

    native_methods natives[] = {
        METHODS("Cipher",     cipher_methods, have_aesni),
        METHODS("Cipher$CBC",    cbc_methods, have_aesni),
        METHODS("Cipher$CTR",    ctr_methods, have_aesni),
        METHODS("Cipher$GCM",    gcm_methods, have_pclmul),
        METHODS("Crypto",     random_methods, have_rdrand),
        METHODS("Crypto",     crypto_methods, have_aesni),
    };

    for (size_t i = 0; i < sizeof(natives) / sizeof(native_methods); i++) {
        native_methods n = natives[i];

        if (!n.supported) {
            for (size_t m = 0; m < n.count; m++) {
                n.methods[m].fnPtr = &unsupported;
            }
        }

        jclass cls = (*env)->FindClass(env, n.class);
        if ((*env)->RegisterNatives(env, cls, n.methods, n.count) != JNI_OK) {
            return -1;
        }
    }

    return JNI_VERSION_1_6;
}

uint8_t *get_array(JNIEnv *env, jbyteArray ref, jsize len) {
    if (ref == NULL && !(*env)->ExceptionCheck(env)) {
        throw(env, "java/lang/NullPointerException", "");
        return NULL;
    }

    uint8_t *bytes = (uint8_t *) (*env)->GetPrimitiveArrayCritical(env, ref, NULL);

    if (bytes == NULL && !(*env)->ExceptionCheck(env)) {
        throw(env, "java/lang/OutOfMemoryError", "");
        return NULL;
    }

    if (len >= 0 && (*env)->GetArrayLength(env, ref) < len) {
        (*env)->ReleasePrimitiveArrayCritical(env, ref, (jbyte *) bytes, JNI_ABORT);
        throw(env, "java/lang/ArrayIndexOutOfBoundsException", "");
        bytes = NULL;
    }

    return bytes;
}

void release_array(JNIEnv *env, jbyteArray array, uint8_t *bytes, jint mode) {
    if (bytes) {
        (*env)->ReleasePrimitiveArrayCritical(env, array, (jbyte *) bytes, mode);
    }
}

jbyteArray new_array(JNIEnv *env, jsize len) {
    jbyteArray ref = (*env)->NewByteArray(env, len);
    if (ref == NULL && !(*env)->ExceptionCheck(env)) {
        throw(env, "java/lang/OutOfMemoryError", "");
    }
    return ref;
}

void throw(JNIEnv *env, char *cls, char *msg) {
    jclass e = (*env)->FindClass(env, cls);
    if (e) {
        (*env)->ThrowNew(env, e, msg);
    }
}
