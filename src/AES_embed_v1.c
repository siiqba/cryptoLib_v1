/*
 ============================================================================
 Name        : AES_embed_v1.c
 Author      : sii
 Version     :
 Copyright   : free to usae
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <memory.h>

#include "sha2.h"
#include "base64.h"
#include "base64_testVectors.h"

int compareHash(uint8_t *a, uint8_t* b, uint32_t hashLen){
	for(int i=0; i<hashLen; i++)
		if(a[i] != b[i]) return i;
	return -1;
}

void sha5_test_fun(uint8_t* vectorIn, int vectorInLen){
	uint8_t hash[64]={0};
	uint8_t hash2[64]={0};
	printf("%i: ", vectorInLen);
//	sw_sha256(buff, messageLen, hash);
	sw_sha512(vectorIn, vectorInLen, hash2);
	swSha512(vectorIn, vectorInLen, hash);
	printf("%i\n", compareHash(hash, hash2, 64));
	fflush(stdout);
}

void sha2_test_fun(uint8_t* buff, int messageLen){
	uint8_t hash[32]={0};
	uint8_t hash2[32]={0};
	printf("%i: ", messageLen);
	sw_sha256(buff, messageLen, hash);
	swSha256(buff, messageLen, hash2);
	printf("%i\n", compareHash(hash, hash2, 32));
	fflush(stdout);
}

void sha2_test2_fun(uint8_t* buff, int chunkSize, int chunks){
	uint8_t hash[32]={0};
	uint8_t hash2[32]={0};
	printf("chunk size: %i; chunks: %i, message size: %i -> ", chunkSize, chunks, (chunks*chunkSize));
	sw_sha256(buff, (chunks*chunkSize), hash);
	swSha256Ctx_t ctx;
	swSha256Init(&ctx);
	for(int i=0; i < chunks; i++){
		swSha256Append(&ctx, &buff[i*chunkSize], chunkSize);
	}
	swSha256Final(&ctx, hash2);
//	sha2(buff, messageLen, hash2);
	printf("%i\n", compareHash(hash, hash2, 32));
	fflush(stdout);
}

void base64_Decode_test(const uint8_t* testVectBase64, const uint32_t testVectBase64Lenght,\
						const uint8_t* testVectReturn, const uint32_t returnVectorLenght){
	uint8_t returnVector[256];
	uint32_t len;
	len = base64DecodedLenght(testVectBase64, testVectBase64Lenght);
	printf("base64DecodedLenght return size: %i ", len);
	if(len == returnVectorLenght){
		printf("-> OK\n");
		fflush(stdout);
	}else{
		printf("-> ERROR - should be: %i\n", returnVectorLenght);
		fflush(stdout);
	}
	len = base64Decode(testVectBase64, returnVector, testVectBase64Lenght);
	printf("base64 Decode test return size: %i ", len);
	if(len == returnVectorLenght){
		printf("-> OK\n");
		fflush(stdout);
	}else{
		printf("-> ERROR - should be: %i\n", returnVectorLenght);
		fflush(stdout);
		return;
	}
	if( 0 == memcmp(testVectReturn, returnVector, returnVectorLenght)){
		printf("base64 Decode test vector -> OK\n");
		fflush(stdout);
	}else{
		printf("base64 Decode test vector -> ERROR\n");
		fflush(stdout);
	}
}

void base64_Encode_test(const uint8_t* testVect, const uint32_t testVectLenght,\
						const uint8_t* testVectReturn, const uint32_t returnVectorLenght){
	uint8_t returnVector[256];
	uint32_t len;
	len = base64EncodedLenght(testVectLenght);
	printf("base64EncodeLenght return size: %i ", len);
	if(len == returnVectorLenght){
		printf("-> OK\n");
	}else{
		printf("-> ERROR - should be: %i\n", returnVectorLenght);
	}
	fflush(stdout);
	len = base64Encode(testVect, returnVector, testVectLenght);
	printf("base64 Encode return size: %i ", len);
	if(len == returnVectorLenght){
		printf("-> OK\n");
	}else{
		printf("-> ERROR - should be: %i\n", returnVectorLenght);
	}
	fflush(stdout);
	if( 0 == memcmp(testVectReturn, returnVector, returnVectorLenght)){
		printf("base64 Encode test vector -> OK\n");
	}else{
		printf("base64 Encode test vector -> ERROR\n");
	}
	fflush(stdout);

}

int main(int argc, char* argv[]) {
	uint8_t buff[256]={	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xAA,\
						0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xAA,\
						0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xAA,\
						0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xAA,\
						0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xAA,\
						0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xAA,\
						0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xAA,\
						0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xAA,\
						0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xAA,\
						0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xAA,\
						0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xAA,\
						0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xAA,\
						0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xAA,\
						0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xAA,\
						0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xAA,\
						0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xAA};
//	uint8_t hash[32]={0};
//	uint8_t hash2[32]={0};
//	uint8_t _smartBuff[10+4] = {0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
//	uint16_t* temp16ptr = (uint16_t*)_smartBuff;
//	temp16ptr[0] = 10;
//	temp16ptr[1] = 5;
//	uint8_t* smartBuff = &_smartBuff[4];
//
//	uint16_t dummy1 = ((uint16_t*)smartBuff)[-2];
//	uint16_t dummy2 = ((uint16_t*)smartBuff)[-1];
//	(void) dummy1;
//	(void) dummy2;

//	sha2_test_fun(buff, 32);

//	int messageLen;
//	for(messageLen = 0; messageLen < 256; messageLen ++){
//		sha2_test_fun(buff, messageLen);
//	}
//	for(messageLen = 1; messageLen < 30; messageLen ++){
//		sha2_test2_fun(buff, 7, messageLen);
//	}
//	printf("\n");
//	uint8_t messageBase64_1[]="MTIzNDU="; //8 12345 "MTIzNDU="
//	uint8_t messageBase64_2[]="YWxhIG1hIGtvdGE="; //8 1234 "MTIzNA=="
//	uint8_t messageBase64_3[]="YWxhIG1hIGtvdGEu"; //4 123 "MTIz"
//	uint8_t testMessage_1[] = "12345";
//	uint8_t messageOrg[20]={0};
//	uint32_t len = base64DecodedLenght(messageBase64_1, 8);
//	len = base64Decode(messageBase64_1, messageOrg, 8);
//	memset(messageOrg, 0xFF, 20);
//	len = base64Decode(messageBase64_2, messageOrg, 16);
//	memset(messageOrg, 0xFF, 20);
//	len = base64Decode(messageBase64_3, messageOrg, 16);
//	memset(messageOrg, 0x00, 20);
//	len = base64Encode(testMessage_1, messageOrg, 5);
//	(void) len;
//	(void)messageOrg;

//base64 tests ==============================================================>
//	printf("<====================Start base64 Decode test vector 1>\n\n");
//	fflush(stdout);
//	base64_Decode_test(base64_testVector1, base64_testVector1Lenght, testVector1, testVector1Lenght);
//
//	printf("<=====================Start base64 Decode test vector 2>\n\n");
//	fflush(stdout);
//	base64_Decode_test(base64_testVector2, base64_testVector2Lenght, testVector2, testVector2Lenght);
//
//	printf("<=====================Start base64 Decode test vector 3>\n\n");
//	fflush(stdout);
//	base64_Decode_test(base64_testVector3, base64_testVector3Lenght, testVector3, testVector3Lenght);
//
//	printf("<====================Start base64 Encode test vector 1>\n\n");
//	fflush(stdout);
//	base64_Encode_test(testVector1, testVector1Lenght, base64_testVector1, base64_testVector1Lenght);
//
//	printf("<====================Start base64 Encode test vector 2>\n\n");
//	fflush(stdout);
//	base64_Encode_test(testVector2, testVector2Lenght, base64_testVector2, base64_testVector2Lenght);
//
//	printf("<====================Start base64 Encode test vector 1>\n\n");
//	fflush(stdout);
//	base64_Encode_test(testVector3, testVector3Lenght, base64_testVector3, base64_testVector3Lenght);
// END base64 test ============================================================>

// SHA512 test =================================================================>
//	uint8_t hash512[SHA512_DIGEST_SIZE]={0};
//	uint8_t hash512B[SHA512_DIGEST_SIZE]={0};
	printf("SHA256 TEST -->\n");
	for(int i=0; i<256; i++){
		sha2_test_fun(buff, i);
	}
	printf("SHA512 TEST -->\n");
	for(int i=0; i<256; i++){
		sha5_test_fun(buff, i);
	}

//	sw_sha512(buff, 4, hash512B);
// END SHA512 test =============================================================>

	(void)buff;
	return EXIT_SUCCESS;
}


