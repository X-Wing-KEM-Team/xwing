#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "align.h"
#include "params.h"

typedef ALIGNED_INT16(MLKEM_N) poly;

void poly_compress(uint8_t r[MLKEM_POLYCOMPRESSEDBYTES], const poly *a);
void poly_decompress(poly *r, const uint8_t a[MLKEM_POLYCOMPRESSEDBYTES]);

void poly_tobytes(uint8_t r[MLKEM_POLYBYTES], const poly *a);
void poly_frombytes(poly *r, const uint8_t a[MLKEM_POLYBYTES]);

void poly_frommsg(poly *r, const uint8_t msg[MLKEM_INDCPA_MSGBYTES]);
void poly_tomsg(uint8_t msg[MLKEM_INDCPA_MSGBYTES], const poly *r);

void poly_getnoise_eta1(poly *r, const uint8_t seed[MLKEM_SYMBYTES], uint8_t nonce);
void poly_getnoise_eta1_4x(poly *r0, poly *r1, poly *r2, poly *r3, const uint8_t seed[32], uint8_t nonce0, uint8_t nonce1, uint8_t nonce2, uint8_t nonce3);
void poly_getnoise_eta2(poly *r, const uint8_t seed[MLKEM_SYMBYTES], uint8_t nonce);

void poly_ntt(poly *r);
void poly_invntt_tomont(poly *r);
void poly_nttunpack(poly *r);
void poly_basemul_montgomery(poly *r, const poly *a, const poly *b);
void poly_tomont(poly *r);

void poly_reduce(poly *r);

void poly_add(poly *r, const poly *a, const poly *b);
void poly_sub(poly *r, const poly *a, const poly *b);

#endif
