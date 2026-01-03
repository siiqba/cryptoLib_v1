/*
 * base64.h
 *
 *  Created on: 1 sty 2026
 *      Author: sii
 */

#ifndef BASE64_BASE64_H_
#define BASE64_BASE64_H_
#include <stdint.h>

#define BASE64_ERROR -1

static const uint8_t base64TransTab[64]={
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
		'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
		'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
		'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
		'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
		'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
		'w', 'x', 'y', 'z', '0', '1', '2', '3',
		'4', '5', '6', '7', '8', '9', '+', '/',
};

#define BASE64_PADDING '='

uint32_t base64EncodedLenght(uint32_t messageLen);
uint32_t base64DecodedLenght(const uint8_t* b64message, uint32_t b64messageLen);
uint32_t base64Decode(const uint8_t* b64message, uint8_t* message, uint32_t b64messageLen);
uint32_t base64Encode(const uint8_t* message, uint8_t* b64message, uint32_t messageLen);

#endif /* BASE64_BASE64_H_ */
