/*
 * base64.c
 *
 *  Created on: 1 sty 2026
 *      Author: sii
 */

#include "../base64.h"

uint32_t base64EncodedLenght(uint32_t messageLen){
	uint32_t ut32;
	ut32 = messageLen % 3U;
	if (ut32 > 0){
		return ((messageLen / 3U) + 1U) * 4U;
	}else{
		return (messageLen / 3U) * 4U;
	}
}

uint32_t base64DecodedLenght(const uint8_t* b64message, const uint32_t b64messageLen){
	uint32_t ut32 = b64messageLen;
	uint32_t ut32_2;
	if ( BASE64_PADDING == b64message[ut32 - 1] ) ut32 --; //remove potential second paddings '='
	if ( BASE64_PADDING == b64message[ut32 - 1] ) ut32 --; //remove potential first paddings '='

	ut32_2 = (ut32 / 4U) * 3U; //number of bytes in full 4 chars in base64
	ut32 = ut32 % 4U;
	if (ut32 > 1) ut32_2 += ut32 - 1U; //add remaining bytes that not fit to full 4 chars in base64
	return ut32_2;
}

uint32_t base64Decode(const uint8_t* b64message, uint8_t* message, uint32_t b64messageLen){
	uint32_t decodeBuff, i, j, k;
	int32_t temp1;
	if((b64messageLen % 4) == 1) return 0; //one char in Base64 left - cannot reconstruct data
	decodeBuff = 0;
	for(i=0, j = 1, k = 0; i < b64messageLen; i++, j++){
		temp1 = -1;
		if ((b64message[i] >= '0') && (b64message[i] <= '9')) temp1 = 52U + (int32_t)(b64message[i] - '0');
		if ((b64message[i] >= 'A') && (b64message[i] <= 'Z')) temp1 = (int32_t)(b64message[i] - 'A');
		if ((b64message[i] >= 'a') && (b64message[i] <= 'z')) temp1 = 26U + (int32_t)(b64message[i] - 'a');
		if (b64message[i] == '+') temp1 = 62;
		if (b64message[i] == '/') temp1 = 63;
		if (b64message[i] == BASE64_PADDING) {break;}
		if (temp1 < 0) return 0; // bad character in base64 string
		decodeBuff |= temp1;
		if( 0 == (j%4)){
			message[k++] = (uint8_t)((decodeBuff >> 16) & 0x000000FF);
			message[k++] = (uint8_t)((decodeBuff >> 8) & 0x000000FF);
			message[k++] = (uint8_t)((decodeBuff) & 0x000000FF);
			decodeBuff = 0;
		}
		decodeBuff <<= 6;
	}
	j--;
	if( 0 == (j%4)) return k;
	temp1 = 4 - (j%4);
	if(temp1 == 1){
//		decodeBuff <<= 6;
		message[k++] = (uint8_t)((decodeBuff >> 16) & 0x000000FF);
		message[k++] = (uint8_t)((decodeBuff >> 8) & 0x000000FF);
	}else if(temp1 == 2){
		decodeBuff <<= 6;
		message[k++] = (uint8_t)((decodeBuff >> 16) & 0x000000FF);
	}

	return k;
}

uint32_t base64Encode(const uint8_t* message, uint8_t* b64message, uint32_t messageLen){
	uint32_t fullOctetCount;
	uint32_t remPart;
	uint32_t i, j;
	uint32_t decodeBuff;

	fullOctetCount = messageLen / 3U;
	remPart = messageLen % 3U;
	decodeBuff = 0;
	for(i = 0; i < fullOctetCount; i++){
		decodeBuff |= message[(i*3)]; decodeBuff <<= 8;
		decodeBuff |= message[(i*3)+1]; decodeBuff <<= 8;
		decodeBuff |= message[(i*3)+2];
		b64message[(i*4)+3] = base64TransTab[(decodeBuff) & 0x3F]; decodeBuff >>= 6;
		b64message[(i*4)+2] = base64TransTab[(decodeBuff) & 0x3F]; decodeBuff >>= 6;
		b64message[(i*4)+1] = base64TransTab[(decodeBuff) & 0x3F]; decodeBuff >>= 6;
		b64message[(i*4)] = base64TransTab[(decodeBuff) & 0x3F];
		decodeBuff = 0;
	}
	if(0 == remPart) return fullOctetCount * 4U;
	j = fullOctetCount * 4U;
	if(1 == remPart){
		decodeBuff |= message[messageLen - 1]; decodeBuff <<= 8;
		b64message[j++] = base64TransTab[(decodeBuff >> 10) & 0x3F];
		b64message[j++] = base64TransTab[(decodeBuff >> 4) & 0x3F];
		b64message[j++] = BASE64_PADDING;
		b64message[j] = BASE64_PADDING;
	}else if(2 == remPart){
		decodeBuff |= message[messageLen - 2]; decodeBuff <<= 8;
		decodeBuff |= message[messageLen - 1]; decodeBuff <<= 8;
		b64message[j++] = base64TransTab[(decodeBuff >> 18) & 0x3F];
		b64message[j++] = base64TransTab[(decodeBuff >> 12) & 0x3F];
		b64message[j++] = base64TransTab[(decodeBuff >> 6) & 0x3F];
		b64message[j] = BASE64_PADDING;
	}

	return (fullOctetCount + 1) * 4U;
}
