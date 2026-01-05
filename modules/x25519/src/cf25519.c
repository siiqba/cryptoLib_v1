/*
 * cf25519.c
 *
 *  Created on: 5 sty 2026
 *      Author: sii
 */

#include "x25519.h"
const uint8_t f25519_one[F25519_SIZE] = {1};
const uint8_t c25519_base_x[F25519_SIZE] = {9};

void *compact_wipe(void *data, size_t length) {
// simplification of: https://www.cryptologie.net/article/419/zeroing-memory-compiler-optimizations-and-memset_s/
	 volatile unsigned char *p = data;
	 while (length--){
		 *p++ = 0;
	 }
	return data;
}

void swF25519Mul_distinct(uint8_t *r, const uint8_t *a, const uint8_t *b)
{
	uint32_t c = 0;
	int i;

	for (i = 0; i < F25519_SIZE; i++) {
		int j;

		c >>= 8;
		for (j = 0; j <= i; j++)
			c += ((uint32_t)a[j]) * ((uint32_t)b[i - j]);

		for (; j < F25519_SIZE; j++)
			c += ((uint32_t)a[j]) *
			     ((uint32_t)b[i + F25519_SIZE - j]) * 38;

		r[i] = c;
	}

	r[31] &= 127;
	c = (c >> 7) * 19;

	for (i = 0; i < F25519_SIZE; i++) {
		c += r[i];
		r[i] = c;
		c >>= 8;
	}
}

void swF25519Select(uint8_t *dst,
		   const uint8_t *zero, const uint8_t *one,
		   uint8_t condition)
{
	const uint8_t mask = -condition;
	int i;

	for (i = 0; i < F25519_SIZE; i++)
		dst[i] = zero[i] ^ (mask & (one[i] ^ zero[i]));
}

void swF25519Add(uint8_t *r, const uint8_t *a, const uint8_t *b)
{
	uint16_t c = 0;
	int i;

	/* Add */
	for (i = 0; i < F25519_SIZE; i++) {
		c >>= 8;
		c += ((uint16_t)a[i]) + ((uint16_t)b[i]);
		r[i] = c;
	}

	/* Reduce with 2^255 = 19 mod p */
	r[31] &= 127;
	c = (c >> 7) * 19;

	for (i = 0; i < F25519_SIZE; i++) {
		c += r[i];
		r[i] = c;
		c >>= 8;
	}
}

void swF25519Sub(uint8_t *r, const uint8_t *a, const uint8_t *b)
{
	uint32_t c = 0;
	int i;

	/* Calculate a + 2p - b, to avoid underflow */
	c = 218;
	for (i = 0; i + 1 < F25519_SIZE; i++) {
		c += 65280 + ((uint32_t)a[i]) - ((uint32_t)b[i]);
		r[i] = c;
		c >>= 8;
	}

	c += ((uint32_t)a[31]) - ((uint32_t)b[31]);
	r[31] = c & 127;
	c = (c >> 7) * 19;

	for (i = 0; i < F25519_SIZE; i++) {
		c += r[i];
		r[i] = c;
		c >>= 8;
	}
}

static inline void swF25519Copy(uint8_t *x, const uint8_t *a)
{
	int i;
	for(i = 0; i < F25519_SIZE; i++)
		x[i] = a[i];
//	memcpy(x, a, F25519_SIZE);
}

static inline void swC25519Prepare(uint8_t *key)
{
	key[0] &= 0xf8;
	key[31] &= 0x7f;
	key[31] |= 0x40;
}

void swF25519Mul_c(uint8_t *r, const uint8_t *a, uint32_t b)
{
	uint32_t c = 0;
	int i;

	for (i = 0; i < F25519_SIZE; i++) {
		c >>= 8;
		c += b * ((uint32_t)a[i]);
		r[i] = c;
	}

	r[31] &= 127;
	c >>= 7;
	c *= 19;

	for (i = 0; i < F25519_SIZE; i++) {
		c += r[i];
		r[i] = c;
		c >>= 8;
	}
}

void swF25519Inv_distinct(uint8_t *r, const uint8_t *x)
{
	uint8_t s[F25519_SIZE];
	int i;

	/* This is a prime field, so by Fermat's little theorem:
	 *
	 *     x^(p-1) = 1 mod p
	 *
	 * Therefore, raise to (p-2) = 2^255-21 to get a multiplicative
	 * inverse.
	 *
	 * This is a 255-bit binary number with the digits:
	 *
	 *     11111111... 01011
	 *
	 * We compute the result by the usual binary chain, but
	 * alternate between keeping the accumulator in r and s, so as
	 * to avoid copying temporaries.
	 */

	/* 1 1 */
	swF25519Mul_distinct(s, x, x);
	swF25519Mul_distinct(r, s, x);

	/* 1 x 248 */
	for (i = 0; i < 248; i++) {
		swF25519Mul_distinct(s, r, r);
		swF25519Mul_distinct(r, s, x);
	}

	/* 0 */
	swF25519Mul_distinct(s, r, r);

	/* 1 */
	swF25519Mul_distinct(r, s, s);
	swF25519Mul_distinct(s, r, x);

	/* 0 */
	swF25519Mul_distinct(r, s, s);

	/* 1 */
	swF25519Mul_distinct(s, r, r);
	swF25519Mul_distinct(r, s, x);

	/* 1 */
	swF25519Mul_distinct(s, r, r);
	swF25519Mul_distinct(r, s, x);
}

void swF25519Normalize(uint8_t *x)
{
	uint8_t minusp[F25519_SIZE];
	uint16_t c;
	int i;

	/* Reduce using 2^255 = 19 mod p */
	c = (x[31] >> 7) * 19;
	x[31] &= 127;

	for (i = 0; i < F25519_SIZE; i++) {
		c += x[i];
		x[i] = c;
		c >>= 8;
	}

	/* The number is now less than 2^255 + 18, and therefore less than
	 * 2p. Try subtracting p, and conditionally load the subtracted
	 * value if underflow did not occur.
	 */
	c = 19;

	for (i = 0; i + 1 < F25519_SIZE; i++) {
		c += x[i];
		minusp[i] = c;
		c >>= 8;
	}

	c += ((uint16_t)x[i]) - 128;
	minusp[31] = c;

	/* Load x-p if no underflow */
	swF25519Select(x, minusp, x, (c >> 15) & 1);
}

/* Double an X-coordinate */
static void xc_double(uint8_t *x3, uint8_t *z3,
		      const uint8_t *x1, const uint8_t *z1)
{
	/* Explicit formulas database: dbl-1987-m
	 *
	 * source 1987 Montgomery "Speeding the Pollard and elliptic
	 *   curve methods of factorization", page 261, fourth display
	 * compute X3 = (X1^2-Z1^2)^2
	 * compute Z3 = 4 X1 Z1 (X1^2 + a X1 Z1 + Z1^2)
	 */
	uint8_t x1sq[F25519_SIZE];
	uint8_t z1sq[F25519_SIZE];
	uint8_t x1z1[F25519_SIZE];
	uint8_t a[F25519_SIZE];

	swF25519Mul_distinct(x1sq, x1, x1);
	swF25519Mul_distinct(z1sq, z1, z1);
	swF25519Mul_distinct(x1z1, x1, z1);

	swF25519Sub(a, x1sq, z1sq);
	swF25519Mul_distinct(x3, a, a);

	swF25519Mul_c(a, x1z1, 486662);
	swF25519Add(a, x1sq, a);
	swF25519Add(a, z1sq, a);
	swF25519Mul_distinct(x1sq, x1z1, a);
	swF25519Mul_c(z3, x1sq, 4);
}

/* Differential addition */
static void xc_diffadd(uint8_t *x5, uint8_t *z5,
		       const uint8_t *x1, const uint8_t *z1,
		       const uint8_t *x2, const uint8_t *z2,
		       const uint8_t *x3, const uint8_t *z3)
{
	/* Explicit formulas database: dbl-1987-m3
	 *
	 * source 1987 Montgomery "Speeding the Pollard and elliptic curve
	 *   methods of factorization", page 261, fifth display, plus
	 *   common-subexpression elimination
	 * compute A = X2+Z2
	 * compute B = X2-Z2
	 * compute C = X3+Z3
	 * compute D = X3-Z3
	 * compute DA = D A
	 * compute CB = C B
	 * compute X5 = Z1(DA+CB)^2
	 * compute Z5 = X1(DA-CB)^2
	 */
	uint8_t da[F25519_SIZE];
	uint8_t cb[F25519_SIZE];
	uint8_t a[F25519_SIZE];
	uint8_t b[F25519_SIZE];

	swF25519Add(a, x2, z2);
	swF25519Sub(b, x3, z3); /* D */
	swF25519Mul_distinct(da, a, b);

	swF25519Sub(b, x2, z2);
	swF25519Add(a, x3, z3); /* C */
	swF25519Mul_distinct(cb, a, b);

	swF25519Add(a, da, cb);
	swF25519Mul_distinct(b, a, a);
	swF25519Mul_distinct(x5, z1, b);

	swF25519Sub(a, da, cb);
	swF25519Mul_distinct(b, a, a);
	swF25519Mul_distinct(z5, x1, b);
}

void swC25519Smult(uint8_t *result, const uint8_t *q, const uint8_t *e)
{
	/* Current point: P_m */
	uint8_t xm[F25519_SIZE];
	uint8_t zm[F25519_SIZE] = {1};

	/* Predecessor: P_(m-1) */
	uint8_t xm1[F25519_SIZE] = {1};
	uint8_t zm1[F25519_SIZE] = {0};

	int i;

	/* Note: bit 254 is assumed to be 1 */
	swF25519Copy(xm, q);

	for (i = 253; i >= 0; i--) {
		const int bit = (e[i >> 3] >> (i & 7)) & 1;
		uint8_t xms[F25519_SIZE];
		uint8_t zms[F25519_SIZE];

		/* From P_m and P_(m-1), compute P_(2m) and P_(2m-1) */
		xc_diffadd(xm1, zm1, q, f25519_one, xm, zm, xm1, zm1);
//		xc_diffadd(xm1, zm1, q, f25519_one, xm, zm, xm1, zm1);
		xc_double(xm, zm, xm, zm);

		/* Compute P_(2m+1) */
		xc_diffadd(xms, zms, xm1, zm1, xm, zm, q, f25519_one);

		/* Select:
		 *   bit = 1 --> (P_(2m+1), P_(2m))
		 *   bit = 0 --> (P_(2m), P_(2m-1))
		 */
		swF25519Select(xm1, xm1, xm, bit);
		swF25519Select(zm1, zm1, zm, bit);
		swF25519Select(xm, xm, xms, bit);
		swF25519Select(zm, zm, zms, bit);
	}

	/* Freeze out of projective coordinates */
	swF25519Inv_distinct(zm1, zm);
	swF25519Mul_distinct(result, zm1, xm);
	swF25519Normalize(result);
}

void swX25519Keygen(
    uint8_t private_key[X25519_KEY_SIZE],
    uint8_t public_key[X25519_KEY_SIZE],
    uint8_t random_seed[X25519_KEY_SIZE]
) {
    memcpy(private_key, random_seed, X25519_KEY_SIZE);
//    compact_wipe(random_seed, X25519_KEY_SIZE);
    swC25519Prepare(private_key);
    swC25519Smult(public_key, c25519_base_x, private_key);
    memcpy(private_key, random_seed, X25519_KEY_SIZE);
}

void swX25519Shared(
    uint8_t shared_secret[X25519_SHARED_SIZE],
    const uint8_t my_private_key[X25519_KEY_SIZE],
    const uint8_t their_public_key[X25519_KEY_SIZE]
) {
    // Ensure that supplied private key is clamped (fix issue #1).
    // Calling `c25519_prepare` multiple times for the same private key
    // is OK because it won't modify already clamped key.
    uint8_t clamped_private_key[X25519_KEY_SIZE];
    memcpy(clamped_private_key, my_private_key, X25519_KEY_SIZE);
    swC25519Prepare(clamped_private_key);
    swC25519Smult(shared_secret, their_public_key, clamped_private_key);
    (void)compact_wipe(clamped_private_key, X25519_KEY_SIZE);
}
