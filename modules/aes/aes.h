/*
 * aes.h
 *
 *  Created on: 22 gru 2025
 *      Author: sii
 */

#ifndef AES_AES_H_
#define AES_AES_H_

#define AES128 0
#define AES192 0
#define AES256 1

#define AES_BLOCKLEN 16 // Block length in bytes - AES is 128b 16B block for all key sizes AES128 | AES192 | AES256

#if defined(AES256) && (AES256 == 1)
    #define AES_KEYLEN 32
    #define AES_keyExpSize 240
#elif defined(AES192) && (AES192 == 1)
    #define AES_KEYLEN 24
    #define AES_keyExpSize 208
#else
    #define AES_KEYLEN 16   // Key length in bytes
    #define AES_keyExpSize 176
#endif

#endif /* AES_AES_H_ */
