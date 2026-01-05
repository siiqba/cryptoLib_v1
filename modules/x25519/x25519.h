/*
 * x25519.h
 *
 *  Created on: 5 sty 2026
 *      Author: sii
 */

#ifndef X25519_X25519_H_
#define X25519_X25519_H_
#include <stdint.h>
#include <memory.h> //ToDo: Remove memcpy by custom one

#define F25519_SIZE  32
#define X25519_KEY_SIZE (32)
#define X25519_SHARED_SIZE (32)

void swX25519Keygen(
    uint8_t private_key[X25519_KEY_SIZE],
    uint8_t public_key[X25519_KEY_SIZE],
    uint8_t random_seed[X25519_KEY_SIZE]
);

void swX25519Shared(
    uint8_t shared_secret[X25519_SHARED_SIZE],
    const uint8_t my_private_key[X25519_KEY_SIZE],
    const uint8_t their_public_key[X25519_KEY_SIZE]
);

#endif /* X25519_X25519_H_ */
