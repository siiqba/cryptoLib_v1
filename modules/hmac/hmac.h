/*
 * hmac.h
 *
 *  Created on: 6 sty 2026
 *      Author: sii
 */
/*
 * HMAC algorithms base on previously defined sha2 function.
 *
 */
#ifndef HMAC_HMAC_H_
#define HMAC_HMAC_H_
#include <stdint.h>

#define HMAC_SHA256_BLOCK_SIZE 64U
#define HMAC_SHA256_SIZE 32U
#define HMAC_SHA512_BLOCK_SIZE 128U
#define HMAC_SHA512_SIZE 64U

//typedef enum __attribute__((__packed__)) {HAMAC_SHA256 = 64, HMAC_SHA512 = 128} hmacBlockSize_t;

//typedef struct {
//	uint8_t block[HMAC_SHA256_BLOCK_SIZE];
//	hmacBlockSize_t blockSize;
//	uint8_t* keyPtr;
//	uint32_t keySize;
//	uint8_t* messagePtr;
//	uint32_t messageSize;
//}hmacCtx_t;

int hamacSha256Calc(const uint8_t  key[], const uint32_t keyLen, const uint8_t message[], const uint32_t messageLen);
int hamacSha512Calc(const uint8_t  key[], const uint32_t keyLen, const uint8_t message[], const uint32_t messageLen);
//int hmacGet(hmacCtx_t* ctx, uint8_t* hmac, uint32_t* hmacLen);
#endif /* HMAC_HMAC_H_ */
