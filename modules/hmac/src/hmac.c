/*
 * hmac.c
 *
 *  Created on: 6 sty 2026
 *      Author: sii
 */

#include "hmac.h"
#include "sha2.h"

#define HMAC_IPAD 0x36
#define HMAC_OPAD 0x5C

void xpadAppend(uint8_t* block, const uint8_t blockSize, const uint8_t* K, const uint8_t Klen, const uint8_t pad){
	int i;
	for(i = 0; i < Klen; i++){
		block[i] = K[i] ^ pad;
	}
	for(; i < blockSize; i++){
		block[i] = pad;
	}
}

int hamacSha256Calc(const uint8_t  key[], const uint32_t keyLen, const uint8_t message[], const uint32_t messageLen){

	swSha256Ctx_t shaCtx;
	uint8_t block[HMAC_SHA256_BLOCK_SIZE];
	uint8_t hash[HMAC_SHA256_SIZE];
//	uint8_t* keyInUse;
//	if(keyLen > HMAC_SHA256_BLOCK_SIZE){
//		swSha256Init(&shaCtx);
//		swSha256Append(&shaCtx, key, keyLen);
//		swSha256Final(&shaCtx, hash);
//		keyInUse = hash;
//	}
	xpadAppend(block, HMAC_SHA256_BLOCK_SIZE, key, keyLen, HMAC_IPAD);
	swSha256Init(&shaCtx);
	swSha256Append(&shaCtx, block, HMAC_SHA256_BLOCK_SIZE);
	swSha256Append(&shaCtx, message, messageLen);
	swSha256Final(&shaCtx, hash);
	xpadAppend(block, HMAC_SHA256_BLOCK_SIZE, key, keyLen, HMAC_OPAD);
	swSha256Init(&shaCtx);
	swSha256Append(&shaCtx, block, HMAC_SHA256_BLOCK_SIZE);
	swSha256Append(&shaCtx, hash, HMAC_SHA256_SIZE);
	swSha256Final(&shaCtx, hash);
	//K xor ipad
	return 0;
}

int hamacSha512Calc(const uint8_t  key[], const uint32_t keyLen, const uint8_t message[], const uint32_t messageLen){

	swSha512Ctx_t shaCtx;
	uint8_t block[HMAC_SHA512_BLOCK_SIZE];
	uint8_t hash[HMAC_SHA512_SIZE];
	xpadAppend(block, HMAC_SHA512_BLOCK_SIZE, key, keyLen, HMAC_IPAD);
	swSha512Init(&shaCtx);
	swSha512Append(&shaCtx, block, HMAC_SHA512_BLOCK_SIZE);
	swSha512Append(&shaCtx, message, messageLen);
	swSha512Final(&shaCtx, hash);
	xpadAppend(block, HMAC_SHA512_BLOCK_SIZE, key, keyLen, HMAC_OPAD);
	swSha512Init(&shaCtx);
	swSha512Append(&shaCtx, block, HMAC_SHA512_BLOCK_SIZE);
	swSha512Append(&shaCtx, hash, HMAC_SHA512_SIZE);
	swSha512Final(&shaCtx, hash);
	//K xor ipad
	return 0;
}
