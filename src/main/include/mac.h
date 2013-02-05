#ifndef MAC_H
#define MAC_H

#include "KeccakSponge.h"
#include "hmac_sha2.h"

typedef void(*mac_init)(JNIEnv *, void *, size_t, uint8_t *, size_t);
typedef void(*mac_update)(void *, uint8_t *, size_t);
typedef void(*mac_final)(JNIEnv *, void *, uint8_t *, size_t);

void sha2_256_init(JNIEnv *, void *, size_t, uint8_t *, size_t);
void sha2_256_final(JNIEnv *, void *, uint8_t *, size_t);

void sha2_512_init(JNIEnv *, void *, size_t, uint8_t *, size_t);
void sha2_512_final(JNIEnv *, void *, uint8_t *, size_t);

void sha3_init(JNIEnv *, spongeState *, size_t, uint8_t *, size_t);
void sha3_update(spongeState *, uint8_t *, size_t);
void sha3_final(JNIEnv *, spongeState *, uint8_t *, size_t);

void null_init(JNIEnv *, void *, size_t, uint8_t *, size_t);
void null_update(void *, uint8_t *, size_t);
void null_final(JNIEnv *, void *, uint8_t *, size_t);

#endif /* MAC_H */
