/*
 * sha2.c
 *
 *  Created on: 22 gru 2025
 *      Author: sii
 */

#include "sha2.h"
#include <stdio.h>
#include <memory.h>
//#include <stdbool.h>

#define rotate_right(value, places) (((value) >> (places)) | ((value) << (32U - (places))))
#define rotate_right_64bit(value, places) (((value) >> (places)) | ((value) << (64U - (places))))

//for little endian machine
#define UINT32_HOST_TO_LE(x)  (x)
#define UINT64_HOST_TO_LE(x)  (x)

//for big endian machine and gcc compiler
//ToDo Add conversion for bigendian
//#define UINT32_HOST_TO_LE(x)  __builtin_bswap32(x)

#define IS_ADD_SAFE_UINT16_T(a,b)       (((UINT16_MAX - (a)) >= (b)) ? true : false)
#define IS_ADD_SAFE_UINT32_T(a,b)       (((UINT32_MAX - (a)) >= (b)) ? true : false)
#define IS_ADD_SAFE_UINT64_T(a,b)       (((UINT64_MAX - (a)) >= (b)) ? true : false)
#define IS_ADD_SAFE_SIZE_T(a,b)         (((SIZE_MAX   - (a)) >= (b)) ? true : false)

#define IS_MUL_SAFE_UINT16_T(a,b)       ((((a)  <= UINT16_MAX / (b))) ? true : false)
#define IS_MUL_SAFE_UINT32_T(a,b)       ((((a)  <= UINT32_MAX / (b))) ? true : false)
#define IS_MUL_SAFE_UINT64_T(a,b)       ((((a)  <= UINT64_MAX / (b))) ? true : false)
#define IS_MUL_SAFE_SIZE_T(a,b)         ((((a)  <= SIZE_MAX   / (b))) ? true : false)

//NEW implementation

int swSha256Init(swSha256Ctx_t* ctx)
{
	int i;

	if(NULL == ctx)
	{
		return -1;
	}

	(void)memset(ctx, 0, sizeof(*ctx));
	for (i = 0; i < 8; i++)
	{
		ctx->hash[i] = sha2_256_HashInit[i];
	}

	return 0;
}

int swSha512Init(swSha512Ctx_t* ctx)
{
	int i;

	if(NULL == ctx)
	{
		return -1;
	}

	(void)memset(ctx, 0, sizeof(*ctx));
	for (i = 0; i < 8; i++)
	{
		ctx->hash[i] = sha2_512_HashInit[i];
	}

	return 0;
}

/**
 * \brief Processes whole blocks (64 bytes) of data.
 *
 * \param[in] ctx          SHA256 hash context
 * \param[in] blocks       Raw blocks to be processed
 *
 * \return 0 on success, otherwise an error code.
 */
static void swSha256BlockProcess(swSha256Ctx_t* ctx, const uint8_t* block)
{
    uint16_t i = 0u;
	uint32_t w_index = 0U;
	uint32_t word_value = 0U;
	uint32_t s0, s1 = 0U;
	uint32_t t1, t2 = 0U;
	uint32_t maj, ch = 0U;
	uint32_t rotate_register[8] = {0};

//    if((NULL == ctx) || (NULL == block))
//    {
//        return -1;
//    }

    union
    {
        uint32_t w_word[SHA256_BLOCK_SIZE];
        uint8_t  w_byte[SHA256_BLOCK_SIZE * sizeof(uint32_t)];
    } w_union;


    (void)memset(&w_union, 0, sizeof(w_union));

	// Swap word bytes
	for (i = 0U; i < SHA256_BLOCK_SIZE; i += 4U)
	{
		w_union.w_byte[i + 3U] = block[i + 0U];
		w_union.w_byte[i + 2U] = block[i + 1U];
		w_union.w_byte[i + 1U] = block[i + 2U];
		w_union.w_byte[i + 0U] = block[i + 3U];
		w_union.w_word[i / 4U] = UINT32_HOST_TO_LE(w_union.w_word[i / 4U]);
	}

	w_index = 16u;
	while (w_index < SHA256_BLOCK_SIZE)
	{
		// right rotate for 32-bit variable in C: (value >> places) | (value << 32 - places)
		word_value = w_union.w_word[w_index - 15U];
		s0 = rotate_right(word_value, 7U) ^ rotate_right(word_value, 18U) ^ (word_value >> 3U);

		word_value = w_union.w_word[w_index - 2U];
		s1 = rotate_right(word_value, 17U) ^ rotate_right(word_value, 19U) ^ (word_value >> 10U);

		w_union.w_word[w_index] = w_union.w_word[w_index - 16U] + s0 + w_union.w_word[w_index - 7U] + s1;

		w_index++;
	}

	// Initialize hash value for this chunk.
	for (i = 0U; i < 8U; i++)
	{
		rotate_register[i] = ctx->hash[i];
	}

	// hash calculation loop
	for (i = 0U; i < SHA256_BLOCK_SIZE; i++)
	{
		s0 = rotate_right(rotate_register[0], 2U)
			 ^ rotate_right(rotate_register[0], 13U)
			 ^ rotate_right(rotate_register[0], 22U);
		maj = (rotate_register[0] & rotate_register[1])
			  ^ (rotate_register[0] & rotate_register[2])
			  ^ (rotate_register[1] & rotate_register[2]);
		t2 = s0 + maj;
		s1 = rotate_right(rotate_register[4], 6U)
			 ^ rotate_right(rotate_register[4], 11U)
			 ^ rotate_right(rotate_register[4], 25U);
		ch = (rotate_register[4] & rotate_register[5])
			 ^ (~rotate_register[4] & rotate_register[6]);
		t1 = rotate_register[7] + s1 + ch + sha2_256_k[i] + w_union.w_word[i];

		rotate_register[7] = rotate_register[6];
		rotate_register[6] = rotate_register[5];
		rotate_register[5] = rotate_register[4];
		rotate_register[4] = rotate_register[3] + t1;
		rotate_register[3] = rotate_register[2];
		rotate_register[2] = rotate_register[1];
		rotate_register[1] = rotate_register[0];
		rotate_register[0] = t1 + t2;
	}

	// Add the hash of this block to current result.
	for (i = 0U; i < 8U; i++)
	{
		ctx->hash[i] += rotate_register[i];
	}
//    return 0;
}

/**
 * \brief Processes whole blocks (128 bytes) of data.
 *
 * \param[in] ctx          SHA512 hash context
 * \param[in] blocks       Raw blocks to be processed
 * \param[in] block_count  Number of 128-byte blocks to process
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
static void swSha512BlockProcess(swSha512Ctx_t* ctx, const uint8_t* block)
{
	uint16_t i = 0u;
	uint32_t w_index =0U;
	uint64_t word_value =0U;
	uint64_t s0, s1 = 0U;
	uint64_t t1, t2 = 0U;
	uint64_t maj, ch = 0U ;
	uint64_t rotate_register[8] = {0};

//	if((NULL == ctx) || (NULL == blocks))
//	{
//		return -1;
//	}

	union
	{
		uint64_t w_dword[SHA512_BLOCK_SIZE];
		uint8_t  w_byte[SHA512_BLOCK_SIZE * sizeof(uint64_t)];
	} w_union;

	(void)memset(&w_union, 0, sizeof(w_union));

	 // Swap word bytes
	for (i = 0U; i < SHA512_BLOCK_SIZE; i += 8U)
	{
		w_union.w_byte[i + 7U] = block[i + 0U];
		w_union.w_byte[i + 6U] = block[i + 1U];
		w_union.w_byte[i + 5U] = block[i + 2U];
		w_union.w_byte[i + 4U] = block[i + 3U];
		w_union.w_byte[i + 3U] = block[i + 4U];
		w_union.w_byte[i + 2U] = block[i + 5U];
		w_union.w_byte[i + 1U] = block[i + 6U];
		w_union.w_byte[i + 0U] = block[i + 7U];
		w_union.w_dword[i / 8U] = UINT64_HOST_TO_LE(w_union.w_dword[i / 8U]);
	}

	w_index = 16u;
	while (w_index < 80u)
	{
		// right rotate for 64-bit variable in C: (value >> places) | (value << 64 - places)
		word_value = w_union.w_dword[w_index - 15u];
		s0 = (rotate_right_64bit(word_value, 1U)) ^ (rotate_right_64bit(word_value, 8U)) ^ (word_value >> 7U);

		word_value = w_union.w_dword[w_index - 2u];
		s1 = (rotate_right_64bit(word_value, 19U)) ^ (rotate_right_64bit(word_value, 61U)) ^ (word_value >> 6U);

		w_union.w_dword[w_index] = w_union.w_dword[w_index - 16u] + s0 + w_union.w_dword[w_index - 7u] + s1;

		w_index++;
	}

	// Initialize hash value for this chunk.
	for (i = 0U; i < 8U; i++)
	{
		rotate_register[i] = ctx->hash[i];
	}

	// hash calculation loop
	for (i = 0U; i < 80U; i++)
	{
		s0 = (rotate_right_64bit(rotate_register[0], 28U))
			 ^ (rotate_right_64bit(rotate_register[0], 34U))
			 ^ (rotate_right_64bit(rotate_register[0], 39U));
		maj = (rotate_register[0] & rotate_register[1])
			  ^ (rotate_register[0] & rotate_register[2])
			  ^ (rotate_register[1] & rotate_register[2]);
		t2 = s0 + maj;
		s1 = (rotate_right_64bit(rotate_register[4], 14U))
			 ^ (rotate_right_64bit(rotate_register[4], 18U))
			 ^ (rotate_right_64bit(rotate_register[4], 41U));
		ch = (rotate_register[4] & rotate_register[5])
			 ^ (~rotate_register[4] & rotate_register[6]);
		t1 = rotate_register[7] + s1 + ch + sha2_512_k[i] + w_union.w_dword[i];

		rotate_register[7] = rotate_register[6];
		rotate_register[6] = rotate_register[5];
		rotate_register[5] = rotate_register[4];
		rotate_register[4] = rotate_register[3] + t1;
		rotate_register[3] = rotate_register[2];
		rotate_register[2] = rotate_register[1];
		rotate_register[1] = rotate_register[0];
		rotate_register[0] = t1 + t2;
	}

	// Add the hash of this block to current result.
	for (i = 0U; i < 8U; i++)
	{
		ctx->hash[i] += rotate_register[i];
	}

}

int swSha256Append(swSha256Ctx_t* ctx, const uint8_t messageChunk[], const uint32_t messageSize){
//	const uint8_t* opBuff;
	uint32_t messageLenght;
	if( (NULL == ctx) || (NULL == messageChunk) )return -1;
//	opBuff = &messageChunk[0];
	if(0 == messageSize){
		messageLenght = messageChunk[-1];
	}else{
		messageLenght = messageSize;
	}
	int i = 0;
	while(0 < messageLenght){
		ctx->tblock[ctx->tblock_size++] = messageChunk[i++];
		messageLenght--;
		if(SHA256_BLOCK_SIZE == ctx->tblock_size){
			ctx->msg_size += SHA256_BLOCK_SIZE;
			//Process block
			swSha256BlockProcess(ctx, ctx->tblock);
			ctx->tblock_size = 0;
		}
	}
	return 0;
}

int swSha512Append(swSha512Ctx_t* ctx, const uint8_t messageChunk[], const uint32_t messageSize){
//	const uint8_t* opBuff;
	uint32_t messageLenght;
	if( (NULL == ctx) || (NULL == messageChunk) )return -1;
//	opBuff = &messageChunk[0];
	if(0 == messageSize){
		messageLenght = messageChunk[-1];
	}else{
		messageLenght = messageSize;
	}
	int i = 0;
	while(0 < messageLenght){
		ctx->tblock[ctx->tblock_size++] = messageChunk[i++];
		messageLenght--;
		if(SHA512_BLOCK_SIZE == ctx->tblock_size){
			ctx->msg_size += SHA512_BLOCK_SIZE;
			//Process block
			swSha512BlockProcess(ctx, ctx->tblock);
			ctx->tblock_size = 0;
		}
	}
	return 0;
}

int swSha256Final(swSha256Ctx_t* ctx, uint8_t digest[SHA256_DIGEST_SIZE]){
	int i;
	uint32_t msg_size_bits;//message size cannot exceed 536MB - seems unlikely in embedded uPC system thats why I use uint32_t not uint64_t according to RFC 6234

	if((NULL == ctx) || (NULL == digest)) return -1;
	ctx->msg_size += ctx->tblock_size;
	msg_size_bits = ctx->msg_size * 8U; //message size cannot exceed 536MB - seems unlikely in embedded uPC system
	ctx->tblock[ctx->tblock_size++] = 0x80;//at this point always at least 1B is available in block
	for(i=ctx->tblock_size; i < SHA256_BLOCK_SIZE; i++){
		ctx->tblock[i] = 0x00;
	}
	if( ctx->tblock_size > (SHA256_BLOCK_SIZE - (SHA256_APPEND_SIZE)) ){
		//Process block
		swSha256BlockProcess(ctx, ctx->tblock);
		ctx->tblock_size = 0;
		for(i=ctx->tblock_size; i < SHA256_BLOCK_SIZE; i++){
			ctx->tblock[i] = 0x00;
		}
	}
	ctx->tblock_size = (SHA256_BLOCK_SIZE - (SHA256_APPEND_SIZE - (SHA256_APPEND_SIZE-4U)));//append size to last 4 B
	ctx->tblock[ctx->tblock_size++] = (uint8_t)((msg_size_bits >> 24U) & UINT8_MAX);
	ctx->tblock[ctx->tblock_size++] = (uint8_t)((msg_size_bits >> 16U) & UINT8_MAX);
	ctx->tblock[ctx->tblock_size++] = (uint8_t)((msg_size_bits >> 8U) & UINT8_MAX);
	ctx->tblock[ctx->tblock_size++] = (uint8_t)((msg_size_bits >> 0U) & UINT8_MAX);
	swSha256BlockProcess(ctx, ctx->tblock);

	uint8_t* tBuff = (uint8_t*)ctx->hash;
	for (i = 0; i < 8; i++){
		ctx->hash[i] = SHA_REV32(ctx->hash[i]);
	}
	for (i = 0; i < SHA256_DIGEST_SIZE; i++){
		digest[i] = tBuff[i];
	}
	return 0;
}

int swSha512Final(swSha512Ctx_t* ctx, uint8_t digest[SHA512_DIGEST_SIZE]){
	int i;
	uint32_t msg_size_bits;//message size cannot exceed 536MB - seems unlikely in embedded uPC system thats why I use uint32_t not uint64_t according to RFC 6234

	if((NULL == ctx) || (NULL == digest)) return -1;
	ctx->msg_size += ctx->tblock_size;
	msg_size_bits = ctx->msg_size * 8U; //message size cannot exceed 536MB - seems unlikely in embedded uPC system
	ctx->tblock[ctx->tblock_size++] = 0x80;//at this point always at least 1B is available in block
	for(i=ctx->tblock_size; i < SHA512_BLOCK_SIZE; i++){
		ctx->tblock[i] = 0x00;
	}
	if( ctx->tblock_size > (SHA512_BLOCK_SIZE - (SHA512_APPEND_SIZE)) ){
		//Process block
		swSha512BlockProcess(ctx, ctx->tblock);
		ctx->tblock_size = 0;
		for(i=ctx->tblock_size; i < SHA512_BLOCK_SIZE; i++){
			ctx->tblock[i] = 0x00;
		}
	}
	ctx->tblock_size = (SHA512_BLOCK_SIZE - (SHA512_APPEND_SIZE - (SHA512_APPEND_SIZE-4U)));//append size to last 4 B
	ctx->tblock[ctx->tblock_size++] = (uint8_t)((msg_size_bits >> 24U) & UINT8_MAX);
	ctx->tblock[ctx->tblock_size++] = (uint8_t)((msg_size_bits >> 16U) & UINT8_MAX);
	ctx->tblock[ctx->tblock_size++] = (uint8_t)((msg_size_bits >> 8U) & UINT8_MAX);
	ctx->tblock[ctx->tblock_size++] = (uint8_t)((msg_size_bits >> 0U) & UINT8_MAX);
	swSha512BlockProcess(ctx, ctx->tblock);

	uint8_t* tBuff = (uint8_t*)ctx->hash;
	for (i = 0; i < 8; i++){
		ctx->hash[i] = SHA_REV64(ctx->hash[i]);
	}
	for (i = 0; i < SHA512_DIGEST_SIZE; i++){
		digest[i] = tBuff[i];
	}
	return 0;
}

int swSha512(const uint8_t* message, unsigned int len, uint8_t digest[SHA512_DIGEST_SIZE]){
	swSha512Ctx_t ctx;
	if(0 != swSha512Init(&ctx)) return -1;
	if(0 != swSha512Append(&ctx, message, len)) return -1;
	if(0 != swSha512Final(&ctx, digest)) return -1;
	return 0;
}

int swSha256(const uint8_t* message, unsigned int len, uint8_t digest[SHA256_DIGEST_SIZE])
{
	swSha256Ctx_t ctx;
	if(0 != swSha256Init(&ctx)) return -1;
	if(0 != swSha256Append(&ctx, message, len)) return -1;
	if(0 != swSha256Final(&ctx, digest)) return -1;
	return 0;
}
