/*
 * aes.h
 *
 *  Created on: 22 gru 2025
 *      Author: sii
 */

#ifndef AES_AES_H_
#define AES_AES_H_
#include <stdint.h>

#define AES_BLOCKLEN 16 // Block length in bytes - AES is 128b block only

#define AES256_KEYLEN 32
#define AES256_EXPKEYLEN 240
#define AES192_KEYLEN 24
#define AES192_EXPKEYLEN 208
#define AES128_KEYLEN 16   // Key length in bytes
#define AES128_EXPKEYLEN 176

//#define AES_MODE_128 1
//#define AES_MODE_192 2
//#define AES_MODE_256 3
typedef enum __attribute__((__packed__)) {SWAES128 = 1, SWAES192 = 2, SWAES256 = 3} swAesSize_t;
typedef enum __attribute__((__packed__)) {SWAESKEY_NORST = 0, SWAESKEY_RST = 1} swAesKeyRst_t;
typedef uint8_t swAesRoundState_t[4][4];

typedef struct {
	swAesRoundState_t roundState; //16B 4W
	uint8_t RoundKey[AES256_EXPKEYLEN]; //240B 60W
	uint8_t Iv[AES_BLOCKLEN]; //16B 4W
	uint32_t couter; //4B 1W
	swAesSize_t aesSize; //1B
	uint8_t Nb; //1B
	uint8_t Nk; //1B
	uint8_t Nr; //1B
	uint8_t keyReady; // 1B for removing needs of key calculation in case its already calculated
}swAesCtx_t;

int swAesIinit(swAesCtx_t* ctx, const uint8_t* key, swAesSize_t aesSize, swAesKeyRst_t keyRst);

#endif /* AES_AES_H_ */
