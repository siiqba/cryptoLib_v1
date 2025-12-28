/*
 * sha2.c
 *
 *  Created on: 22 gru 2025
 *      Author: sii
 */

#include "sha2.h"
#include <stdio.h>
#include <memory.h>
#include <stdbool.h>

#define rotate_right(value, places) (((value) >> (places)) | ((value) << (32U - (places))))
//#define rotate_right_64bit(value, places) (((value) >> (places)) | ((value) << (64U - (places))))

//for little endian machine
#define UINT32_HOST_TO_LE(x)  (x)

//for big endian machine and gcc compiler
//#define ATCA_UINT32_HOST_TO_LE(x)  __builtin_bswap32(x)

#define IS_ADD_SAFE_UINT16_T(a,b)       (((UINT16_MAX - (a)) >= (b)) ? true : false)
#define IS_ADD_SAFE_UINT32_T(a,b)       (((UINT32_MAX - (a)) >= (b)) ? true : false)
#define IS_ADD_SAFE_UINT64_T(a,b)       (((UINT64_MAX - (a)) >= (b)) ? true : false)
#define IS_ADD_SAFE_SIZE_T(a,b)         (((SIZE_MAX   - (a)) >= (b)) ? true : false)

#define IS_MUL_SAFE_UINT16_T(a,b)       ((((a)  <= UINT16_MAX / (b))) ? true : false)
#define IS_MUL_SAFE_UINT32_T(a,b)       ((((a)  <= UINT32_MAX / (b))) ? true : false)
#define IS_MUL_SAFE_UINT64_T(a,b)       ((((a)  <= UINT64_MAX / (b))) ? true : false)
#define IS_MUL_SAFE_SIZE_T(a,b)         ((((a)  <= SIZE_MAX   / (b))) ? true : false)

int sw_sha2_init(sw_sha2_ctx* ctx);
int sw_sha2_update(sw_sha2_ctx* ctx, const uint8_t* msg, uint32_t msg_size);

//void sha2(void){
//	printf("sha2\n");
//}

/**
 * \brief Intialize the software SHA256.
 *
 * \param[in] ctx          SHA256 hash context
 *
 * \return 0 on success, otherwise an error code.
 */
int sw_sha2_init(sw_sha2_ctx* ctx)
{
	static const uint32_t hash_init[] = {
		0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
		0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
	};
	int i;

	if(NULL == ctx)
	{
		return -1;
	}

	(void)memset(ctx, 0, sizeof(*ctx));
	for (i = 0; i < 8; i++)
	{
		ctx->hash[i] = hash_init[i];
	}

	return 0;
}



/**
 * \brief Processes whole blocks (64 bytes) of data.
 *
 * \param[in] ctx          SHA256 hash context
 * \param[in] blocks       Raw blocks to be processed
 * \param[in] block_count  Number of 64-byte blocks to process
 *
 * \return 0 on success, otherwise an error code.
 */
static int sw_sha2_process(sw_sha2_ctx* ctx, const uint8_t* blocks, uint32_t block_count)
{
    uint16_t i = 0u;
    uint32_t block = 0u;

    if((NULL == ctx) || (NULL == blocks))
    {
        return -1;
    }

    union
    {
        uint32_t w_word[SHA2_BLOCK_SIZE];
        uint8_t  w_byte[SHA2_BLOCK_SIZE * sizeof(uint32_t)];
    } w_union;

    static const uint32_t k[] = {
        0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
        0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
        0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
        0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
        0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
        0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
        0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
        0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
    };

    (void)memset(&w_union, 0, sizeof(w_union));

    // Loop through all the blocks to process
    for (block = 0; block < block_count; block++)
    {
        uint32_t w_index = 0U;
        uint32_t word_value = 0U;
        uint32_t s0, s1 = 0U;
        uint32_t t1, t2 = 0U;
        uint32_t maj, ch = 0U;
        uint32_t rotate_register[8] = {0};
        const uint8_t* cur_msg_block = &blocks[block * SHA2_BLOCK_SIZE];

        // Swap word bytes
        for (i = 0U; i < SHA2_BLOCK_SIZE; i += 4U)
        {
            w_union.w_byte[i + 3U] = cur_msg_block[i + 0U];
            w_union.w_byte[i + 2U] = cur_msg_block[i + 1U];
            w_union.w_byte[i + 1U] = cur_msg_block[i + 2U];
            w_union.w_byte[i + 0U] = cur_msg_block[i + 3U];
            w_union.w_word[i / 4U] = UINT32_HOST_TO_LE(w_union.w_word[i / 4U]);
        }

        w_index = 16u;
        while (w_index < SHA2_BLOCK_SIZE)
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
        for (i = 0U; i < SHA2_BLOCK_SIZE; i++)
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
            t1 = rotate_register[7] + s1 + ch + k[i] + w_union.w_word[i];

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

    return 0;
}


/**
 * \brief updates the running hash with the next block of data, called iteratively for the entire
 *  stream of data to be hashed using the SHA256 software
 *
 * \param[in] ctx          SHA256 hash context
 * \param[in] msg          Raw blocks to be processed
 * \param[in] msg_size     The size of the message passed
 *
 * \return 0 on success, otherwise an error code.
 */
int sw_sha2_update(sw_sha2_ctx* ctx, const uint8_t* msg, uint32_t msg_size)
{
    uint32_t block_count;


    if(NULL == ctx)
    {
        return -1;
    }

    uint32_t rem_size = SHA2_BLOCK_SIZE - ctx->block_size;
    uint32_t copy_size = msg_size > rem_size ? rem_size : msg_size;//MINIMUM

    if (0u == msg_size || NULL == msg)
    {
        return 0;
    }

    // Copy data into current block
    (void)memcpy(&ctx->block[ctx->block_size], msg, (size_t)copy_size);

    if (ctx->block_size + msg_size < SHA2_BLOCK_SIZE)
    {
        // Not enough data to finish off the current block
        // This data will be processed in sw_sha256_final
        ctx->block_size += msg_size;
        return 0;
    }

    // Process the current block
    if(0 != sw_sha2_process(ctx, ctx->block, 1))
    {
        return -1;
    }

    // Process any additional blocks
    msg_size -= copy_size; // Adjust to the remaining message bytes
    block_count = msg_size / SHA2_BLOCK_SIZE;
    if(0 != sw_sha2_process(ctx, &msg[copy_size], block_count))
    {
        return -1;
    }

    // Save any remaining data
    ctx->total_msg_size += (block_count + 1U) * SHA2_BLOCK_SIZE;
    ctx->block_size = msg_size % SHA2_BLOCK_SIZE;
    (void)memcpy(ctx->block, &msg[copy_size + block_count * SHA2_BLOCK_SIZE], (size_t)ctx->block_size);

    return 0;
}

int sw_sha2_final_test(sw_sha2_ctx* ctx, uint8_t digest[SHA2_DIGEST_SIZE]){
	uint8_t* tbuff;
	tbuff = (uint8_t*)ctx->hash;
	 for (int i = 0; i < 32; i++){
		 digest[i] = (uint8_t)(tbuff[i] & 0xFFu);
	 }
	 return 0;
}
/** \brief completes the final SHA256 calculation and returns the final digest/hash
 * \param[in]  ctx     ptr to context data structure
 * \param[out] digest  receives the computed digest of the SHA 256
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
int sw_sha2_final(sw_sha2_ctx* ctx, uint8_t digest[SHA2_DIGEST_SIZE])
{
    int32_t  i, j;
    uint32_t msg_size_bits = 0U;
    uint32_t pad_zero_count = 0u;
    int32_t byte_cnt = (int32_t)(sizeof(uint32_t));

    if(NULL == ctx)
    {
        return -1;
    }

    // Calculate the total message size in bits
    ctx->total_msg_size += ctx->block_size;

    if(true == IS_MUL_SAFE_UINT32_T(ctx->total_msg_size, 8U))
    {
          msg_size_bits = ctx->total_msg_size * 8U;
    }

    // Calculate the number of padding zero bytes required between the 1 bit byte and the 64 bit message size in bits.
    pad_zero_count = (SHA2_BLOCK_SIZE - ((ctx->block_size + 9U) % SHA2_BLOCK_SIZE)) % SHA2_BLOCK_SIZE;

    // Append a single 1 bit
    ctx->block[ctx->block_size++] = 0x80; //na koniec bloku dodwane jest 1b

    // Add padding zeros plus upper 4 bytes of total msg size in bits (only supporting 32bit message bit counts)
    (void)memset(&ctx->block[ctx->block_size], 0, (size_t)pad_zero_count + 4U);

    pad_zero_count +=4U;

    if(true == IS_ADD_SAFE_UINT32_T(ctx->block_size, pad_zero_count))
    {
        ctx->block_size += pad_zero_count;
    }

    // Add the total message size in bits to the end of the current block. Technically this is
    // supposed to be 8 bytes. This shortcut will reduce the max message size to 536,870,911 bytes.
    ctx->block[ctx->block_size++] = (uint8_t)((msg_size_bits >> 24U) & UINT8_MAX);
    ctx->block[ctx->block_size++] = (uint8_t)((msg_size_bits >> 16U) & UINT8_MAX);
    ctx->block[ctx->block_size++] = (uint8_t)((msg_size_bits >> 8U) & UINT8_MAX);
    ctx->block[ctx->block_size++] = (uint8_t)((msg_size_bits >> 0U) & UINT8_MAX);

    if(0 != sw_sha2_process(ctx, ctx->block, ctx->block_size / SHA2_BLOCK_SIZE))
    {
        return -1;
    }

    // All blocks have been processed.
    // Concatenate the hashes to produce digest, MSB of every hash first.
    for (i = 0; i < 8; i++)
    {
        for (j = byte_cnt - 1; j >= 0; j--)
        {
            if ((i <= (INT32_MAX / byte_cnt)) && ((i * byte_cnt) <= (INT32_MAX - j)))
            {
                digest[i * byte_cnt + j] = (uint8_t)(ctx->hash[i] & 0xFFu);
            }
            ctx->hash[i] >>= 8u;
        }
    }

    return 0;
}


/** \brief single call convenience function which computes Hash of given data using SHA256 software
 * \param[in]  message       pointer to stream of data to hash
 * \param[in]  len           size of data stream to hash
 * \param[out] digest        result
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

int sw_sha256(const uint8_t* message, unsigned int len, uint8_t digest[SHA2_DIGEST_SIZE])
{
    int status;
    sw_sha2_ctx ctx;

    if(0 == (status = sw_sha2_init(&ctx)))
    {
        if(0 == (status = sw_sha2_update(&ctx, message, len)))
        {
        	status = sw_sha2_final(&ctx, digest);
//            status = sw_sha2_final_test(&ctx, digest);
        }
    }

    return status;
}



int swSha2Init(swSha2Ctx_t* ctx)
{
	int i;
//	static const uint32_t hash_init[] = {
//		0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
//		0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
//	};

	//ToDo: check that, this value can be NULL at this point
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


/**
 * \brief Processes whole blocks (64 bytes) of data.
 *
 * \param[in] ctx          SHA256 hash context
 * \param[in] blocks       Raw blocks to be processed
 *
 * \return 0 on success, otherwise an error code.
 */
static int swSha2BlockProcess(swSha2Ctx_t* ctx, const uint8_t* block)
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
        uint32_t w_word[SHA2_BLOCK_SIZE];
        uint8_t  w_byte[SHA2_BLOCK_SIZE * sizeof(uint32_t)];
    } w_union;


    (void)memset(&w_union, 0, sizeof(w_union));

	// Swap word bytes
	for (i = 0U; i < SHA2_BLOCK_SIZE; i += 4U)
	{
		w_union.w_byte[i + 3U] = block[i + 0U];
		w_union.w_byte[i + 2U] = block[i + 1U];
		w_union.w_byte[i + 1U] = block[i + 2U];
		w_union.w_byte[i + 0U] = block[i + 3U];
		w_union.w_word[i / 4U] = UINT32_HOST_TO_LE(w_union.w_word[i / 4U]);
	}

	w_index = 16u;
	while (w_index < SHA2_BLOCK_SIZE)
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
	for (i = 0U; i < SHA2_BLOCK_SIZE; i++)
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
		t1 = rotate_register[7] + s1 + ch + sha2_255_k[i] + w_union.w_word[i];

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
    return 0;
}

int sha2Append(swSha2Ctx_t* ctx, const uint8_t messageChunk[], const uint32_t messageSize){
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
		if(SHA2_BLOCK_SIZE == ctx->tblock_size){
			ctx->msg_size += SHA2_BLOCK_SIZE;
			//Process block
			swSha2BlockProcess(ctx, ctx->tblock);
			ctx->tblock_size = 0;
		}
	}
//	if(SHA2_BLOCK_SIZE == ctx->tblock_size){
//		ctx->msg_size += i;
//		//Process block
//		swSha2BlockProcess(ctx, ctx->tblock);
//		ctx->tblock_size = 0;
//	}
	return 0;
}
int sha2Final_test(swSha2Ctx_t* ctx, uint8_t digest[SHA2_DIGEST_SIZE]){
	uint8_t* tbuff;
	tbuff = (uint8_t*)ctx->hash;
	 for (int i = 0; i < 32; i++){
			 digest[i] = (uint8_t)(tbuff[i] & 0xFFu);
		 }
	 return 0;
}

int sha2Final(swSha2Ctx_t* ctx, uint8_t digest[SHA2_DIGEST_SIZE]){
	int i, j;
	uint32_t msg_size_bits;//message size cannot exceed 536MB - seems unlikely in embedded uPC system thats why I use uint32_t not uint64_t according to RFC 6234
	uint32_t byte_cnt = 4u;
	if((NULL == ctx) || (NULL == digest)) return -1;
	ctx->msg_size += ctx->tblock_size;
	msg_size_bits = ctx->msg_size * 8U; //message size cannot exceed 536MB - seems unlikely in embedded uPC system
	ctx->tblock[ctx->tblock_size++] = 0x80;//at this point always at least 1B is available in block
	for(i=ctx->tblock_size; i < SHA2_BLOCK_SIZE; i++){
		ctx->tblock[i] = 0x00;
	}
	if( ctx->tblock_size > (SHA2_BLOCK_SIZE - (SHA2_APPEND_SIZE)) ){
		//Process block
		swSha2BlockProcess(ctx, ctx->tblock);
		ctx->tblock_size = 0;
		for(i=ctx->tblock_size; i < SHA2_BLOCK_SIZE; i++){
			ctx->tblock[i] = 0x00;
		}
	}
	ctx->tblock_size = (SHA2_BLOCK_SIZE - (SHA2_APPEND_SIZE-4U));//append size to last 4 B
	ctx->tblock[ctx->tblock_size++] = (uint8_t)((msg_size_bits >> 24U) & UINT8_MAX);
	ctx->tblock[ctx->tblock_size++] = (uint8_t)((msg_size_bits >> 16U) & UINT8_MAX);
	ctx->tblock[ctx->tblock_size++] = (uint8_t)((msg_size_bits >> 8U) & UINT8_MAX);
	ctx->tblock[ctx->tblock_size++] = (uint8_t)((msg_size_bits >> 0U) & UINT8_MAX);
	swSha2BlockProcess(ctx, ctx->tblock);
	// All blocks have been processed.
	// Concatenate the hashes to produce digest, MSB of every hash first.
	for (i = 0; i < 8; i++)
	{
		for (j = byte_cnt - 1; j >= 0; j--)
		{
			if ((i <= (INT32_MAX / byte_cnt)) && ((i * byte_cnt) <= (INT32_MAX - j)))
			{
				digest[i * byte_cnt + j] = (uint8_t)(ctx->hash[i] & 0xFFu);
			}
			ctx->hash[i] >>= 8u;
		}
	}
	return 0;
}

int sha2(const uint8_t* message, unsigned int len, uint8_t digest[SHA2_DIGEST_SIZE])
{
	swSha2Ctx_t ctx;
	swSha2Init(&ctx);
	sha2Append(&ctx, message, len);
//	sha2Final_test(&ctx, digest);
	sha2Final(&ctx, digest);
	return 0;
}

int sha2B(const uint8_t* message, unsigned int len, uint8_t digest[SHA2_DIGEST_SIZE])
{
	swSha2Ctx_t ctx;
	if((NULL == message) || (NULL == digest) || (0 >= len))
	{
		return -1;

	}
	swSha2Init(&ctx);
//	int i;
	uint32_t copy_size, rem_size;
//	int block_Count = len / SHA2_BLOCK_SIZE;
	while(len){
		rem_size = SHA2_BLOCK_SIZE - ctx.tblock_size;
		copy_size = len > rem_size ? rem_size : len;//MINIMUM
		(void)memcpy(&ctx.tblock[ctx.tblock_size], &message[ctx.msg_ind], copy_size);
		ctx.tblock_size += copy_size;
		ctx.msg_ind += copy_size;
		len -= copy_size;
		if (ctx.tblock_size < SHA2_BLOCK_SIZE) break;
		if (0 != swSha2BlockProcess(&ctx, ctx.tblock)){
			return -1;
		}
		ctx.tblock_size = 0;
	}
	if(ctx.tblock_size < SHA2_BLOCK_SIZE){
		ctx.tblock[ctx.tblock_size++] = 0x80;
		(void)memset(&ctx.tblock[ctx.tblock_size], 0, SHA2_BLOCK_SIZE - ctx.tblock_size);
		ctx.tblock_size += SHA2_BLOCK_SIZE - ctx.tblock_size;
//		ctx.tblock[ctx.tblock_size] = 0x80;
	}


	uint32_t* outBuff = ctx.hash;
	memcpy(digest, outBuff, 32);
	return 0;
}
