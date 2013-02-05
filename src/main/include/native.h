#ifndef NATIVE_H
#define NATIVE_H

#include <jni.h>

typedef struct {
    char *class;
    JNINativeMethod *methods;
    jint count;
    bool supported;
} native_methods;

#define METHODS(CLASS, METHODS, SUPPORTED) {                \
    .class     = "com/lambdaworks/crypto/" CLASS,           \
    .methods   = METHODS,                                   \
    .count     = sizeof(METHODS) / sizeof(JNINativeMethod), \
    .supported = SUPPORTED,                                 \
}

void throw(JNIEnv *, char *, char *);

uint8_t *get_array(JNIEnv *, jbyteArray, jsize);
void release_array(JNIEnv *, jbyteArray, uint8_t *, jint);
jbyteArray new_array(JNIEnv *, jsize);

#endif /* NATIVE_H */
