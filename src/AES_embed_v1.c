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
#include "x25519.h"

void printHex(const uint8_t *array, size_t length, const uint8_t modBreak) {
    for (size_t i = 0; i < length; ++i) {
        printf("%02X", array[i]);
        if ((i + 1) % modBreak == 0) printf("\n"); // New line after every 8 bytes
        else if (i + 1 < length) printf(" ");
    }
    printf("\n");
}
void printHexTest(const uint8_t *array, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        printf("%02X", array[i]);
    }
    printf("\n");
}
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

void x25519KeyGenTest(uint8_t seed1[], uint8_t seed2[]){
	uint8_t Asecret_key[X25519_KEY_SIZE];
	uint8_t Apublic_key[X25519_KEY_SIZE];
	uint8_t Bsecret_key[X25519_KEY_SIZE];
	uint8_t Bpublic_key[X25519_KEY_SIZE];

	compact_x25519_keygen(Asecret_key, Apublic_key, seed1);
	printf("A >> SECRET KEY:\n");
	printHexTest(Asecret_key, X25519_KEY_SIZE);
	printHex(Asecret_key, X25519_KEY_SIZE, 8);
	printf("B >> PUBLIC KEY:\n");
	printHexTest(Apublic_key, X25519_KEY_SIZE);
	printHex(Apublic_key, X25519_KEY_SIZE, 8);

	compact_x25519_keygen(Bsecret_key, Bpublic_key, seed2);
	printf("A >> SECRET KEY:\n");
	printHexTest(Bsecret_key, X25519_KEY_SIZE);
	printHex(Bsecret_key, X25519_KEY_SIZE, 8);
	printf("B >> PUBLIC KEY:\n");
	printHexTest(Bpublic_key, X25519_KEY_SIZE);
	printHex(Bpublic_key, X25519_KEY_SIZE, 8);

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

	uint8_t rfc7748_alice_sec[X25519_KEY_SIZE] = {
		0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
		0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
		0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
		0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
		};
	uint8_t rfc7748_bob_sec[X25519_KEY_SIZE] = {
		0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
		0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
		0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
		0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb
	};

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
//	printf("SHA256 TEST -->\n");
//	for(int i=0; i<256; i++){
//		sha2_test_fun(buff, i);
//	}
//	printf("SHA512 TEST -->\n");
//	for(int i=0; i<256; i++){
//		sha5_test_fun(buff, i);
//	}
// END SHA512 test =============================================================>

// X25519 test =================================================================>
	printf("X25519 TEST -->\n");
	x25519KeyGenTest(rfc7748_alice_sec, rfc7748_bob_sec);
	printf("X25519 TEST END\n");
// END X25519 test =============================================================>
	(void)buff;
	return EXIT_SUCCESS;
}


