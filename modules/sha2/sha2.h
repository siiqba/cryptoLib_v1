/*
 * sha2.h
 *
 *  Created on: 22 gru 2025
 *      Author: sii
 */

#ifndef SHA2_SHA2_H_
#define SHA2_SHA2_H_

/*
 * possible options:
 *  - SHA256: 256
 *  - SHA384: 384
 *  - SHA512: 512
 */
#define SHA2_DEFINITION 256

#include <stdint.h>
#define bool	_Bool
#define true	1
#define false	0

#if defined(SHA2_DEFINITION) && (SHA2_DEFINITION == 256)
#pragma message "SHA256"
#define SHA2_DIGEST_SIZE (32U)
#define SHA2_BLOCK_SIZE  (64U)

#elif  defined(SHA2_DEFINITION) && (SHA2_DEFINITION == 384)
#pragma message "SHA384"
#define SHA2_DIGEST_SIZE (48U)
#define SHA2_BLOCK_SIZE  (128U)
#error "sha2.h: SHA2 384 not implemented"
#elif defined(SHA2_DEFINITION) && (SHA2_DEFINITION == 512)
#pragma message "SHA512"
#define SHA2_DIGEST_SIZE (64U)
#define SHA2_BLOCK_SIZE  (128U)
#error "sha2.h: SHA2 512 not implemented"
#else
	#error "sha2.h: size of SHA2 not defined or defined incorrectly"
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    uint32_t total_msg_size;				//!< Total number of message bytes processed
    uint32_t block_size;					//!< Number of bytes in current block
    uint8_t  block[SHA2_BLOCK_SIZE * 2];	//!< Unprocessed message storage
#if (SHA2_DEFINITION == 256)
    uint32_t hash[8];						//!< Hash state SHA384 | SHA512
#else
    uint64_t hash[8];						//!< Hash state SHA256
#endif
} sw_sha2_ctx;


int sw_sha256(const uint8_t* message, unsigned int len, uint8_t digest[SHA2_DIGEST_SIZE]);


//static int swSha2BlockProcess(sw_sha2_ctx* ctx, const uint8_t* block);
int swSha2Init(sw_sha2_ctx* ctx);
int sha2(const uint8_t* message, unsigned int len, uint8_t digest[SHA2_DIGEST_SIZE]);
#ifdef __cplusplus
}
#endif

#endif /* SHA2_SHA2_H_ */
