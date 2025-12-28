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

/*
 * const tablen in Flash
 */
static const uint32_t sha2_256_HashInit[] = {
		0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
		0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
	};
static const uint32_t sha2_255_k[] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};


#if defined(SHA2_DEFINITION) && (SHA2_DEFINITION == 256)
#pragma message "SHA256"
#define SHA2_DIGEST_SIZE (32U)
#define SHA2_BLOCK_SIZE  (64U)
#define SHA2_APPEND_SIZE  (8U)

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

typedef struct
{
	uint32_t msg_size;						//!< Accumulated size of message (sum of all chunks)
    uint32_t msg_ind;						//!< Total number of message bytes processed
    uint32_t tblock_size;					//!< Number of bytes in current block
    uint8_t  tblock[SHA2_BLOCK_SIZE * 2];	//!< Unprocessed message storage
#if (SHA2_DEFINITION == 256)
    uint32_t hash[8];						//!< Hash state SHA384 | SHA512
#else
    uint64_t hash[8];						//!< Hash state SHA256
#endif
} swSha2Ctx_t;

int sw_sha256(const uint8_t* message, unsigned int len, uint8_t digest[SHA2_DIGEST_SIZE]);


//static int swSha2BlockProcess(sw_sha2_ctx* ctx, const uint8_t* block);
int swSha2Init(swSha2Ctx_t* ctx);
int sha2(const uint8_t* message, unsigned int len, uint8_t digest[SHA2_DIGEST_SIZE]);
#ifdef __cplusplus
}
#endif

#endif /* SHA2_SHA2_H_ */
