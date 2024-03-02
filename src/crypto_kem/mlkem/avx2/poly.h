#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "align.h"
#include "params.h"

typedef ALIGNED_INT16(MLKEM_N) poly;

#define poly_compress MLKEM_NAMESPACE(poly_compress)
void poly_compress(uint8_t r[MLKEM_POLYCOMPRESSEDBYTES], const poly *a);
#define poly_decompress MLKEM_NAMESPACE(poly_decompress)
void poly_decompress(poly *r, const uint8_t a[MLKEM_POLYCOMPRESSEDBYTES]);

#define poly_tobytes MLKEM_NAMESPACE(poly_tobytes)
void poly_tobytes(uint8_t r[MLKEM_POLYBYTES], const poly *a);
#define poly_frombytes MLKEM_NAMESPACE(poly_frombytes)
void poly_frombytes(poly *r, const uint8_t a[MLKEM_POLYBYTES]);

#define poly_frommsg MLKEM_NAMESPACE(poly_frommsg)
void poly_frommsg(poly *r, const uint8_t msg[MLKEM_INDCPA_MSGBYTES]);
#define poly_tomsg MLKEM_NAMESPACE(poly_tomsg)
void poly_tomsg(uint8_t msg[MLKEM_INDCPA_MSGBYTES], const poly *r);

#define poly_getnoise_eta1 MLKEM_NAMESPACE(poly_getnoise_eta1)
void poly_getnoise_eta1(poly *r, const uint8_t seed[MLKEM_SYMBYTES], uint8_t nonce);

#define poly_getnoise_eta2 MLKEM_NAMESPACE(poly_getnoise_eta2)
void poly_getnoise_eta2(poly *r, const uint8_t seed[MLKEM_SYMBYTES], uint8_t nonce);

#ifndef mlkem_90S
#define poly_getnoise_eta1_4x MLKEM_NAMESPACE(poly_getnoise_eta2_4x)
void poly_getnoise_eta1_4x(poly *r0,
                           poly *r1,
                           poly *r2,
                           poly *r3,
                           const uint8_t seed[32],
                           uint8_t nonce0,
                           uint8_t nonce1,
                           uint8_t nonce2,
                           uint8_t nonce3);

#if MLKEM_K == 2
#define poly_getnoise_eta1122_4x MLKEM_NAMESPACE(poly_getnoise_eta1122_4x)
void poly_getnoise_eta1122_4x(poly *r0,
                              poly *r1,
                              poly *r2,
                              poly *r3,
                              const uint8_t seed[32],
                              uint8_t nonce0,
                              uint8_t nonce1,
                              uint8_t nonce2,
                              uint8_t nonce3);
#endif
#endif


#define poly_ntt MLKEM_NAMESPACE(poly_ntt)
void poly_ntt(poly *r);
#define poly_invntt_tomont MLKEM_NAMESPACE(poly_invntt_tomont)
void poly_invntt_tomont(poly *r);
#define poly_nttunpack MLKEM_NAMESPACE(poly_nttunpack)
void poly_nttunpack(poly *r);
#define poly_basemul_montgomery MLKEM_NAMESPACE(poly_basemul_montgomery)
void poly_basemul_montgomery(poly *r, const poly *a, const poly *b);
#define poly_tomont MLKEM_NAMESPACE(poly_tomont)
void poly_tomont(poly *r);

#define poly_reduce MLKEM_NAMESPACE(poly_reduce)
void poly_reduce(poly *r);

#define poly_add MLKEM_NAMESPACE(poly_add)
void poly_add(poly *r, const poly *a, const poly *b);
#define poly_sub MLKEM_NAMESPACE(poly_sub)
void poly_sub(poly *r, const poly *a, const poly *b);

#endif
