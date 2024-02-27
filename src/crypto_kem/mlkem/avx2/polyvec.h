#ifndef POLYVEC_H
#define POLYVEC_H

#include <stdint.h>
#include "params.h"
#include "poly.h"

typedef struct{
  poly vec[mlkem_K];
} polyvec;

#define polyvec_compress mlkem_NAMESPACE(polyvec_compress)
void polyvec_compress(uint8_t r[mlkem_POLYVECCOMPRESSEDBYTES+2], const polyvec *a);
#define polyvec_decompress mlkem_NAMESPACE(polyvec_decompress)
void polyvec_decompress(polyvec *r, const uint8_t a[mlkem_POLYVECCOMPRESSEDBYTES+12]);

#define polyvec_tobytes mlkem_NAMESPACE(polyvec_tobytes)
void polyvec_tobytes(uint8_t r[mlkem_POLYVECBYTES], const polyvec *a);
#define polyvec_frombytes mlkem_NAMESPACE(polyvec_frombytes)
void polyvec_frombytes(polyvec *r, const uint8_t a[mlkem_POLYVECBYTES]);

#define polyvec_ntt mlkem_NAMESPACE(polyvec_ntt)
void polyvec_ntt(polyvec *r);
#define polyvec_invntt_tomont mlkem_NAMESPACE(polyvec_invntt_tomont)
void polyvec_invntt_tomont(polyvec *r);

#define polyvec_basemul_acc_montgomery mlkem_NAMESPACE(polyvec_basemul_acc_montgomery)
void polyvec_basemul_acc_montgomery(poly *r, const polyvec *a, const polyvec *b);

#define polyvec_reduce mlkem_NAMESPACE(polyvec_reduce)
void polyvec_reduce(polyvec *r);

#define polyvec_add mlkem_NAMESPACE(polyvec_add)
void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b);

#endif
