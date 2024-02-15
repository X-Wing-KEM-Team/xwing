#ifndef CRYPTO_KEM_D
#define CRYPTO_KEM_D

#include <stdint.h>

void crypto_dkem_keypair(unsigned char *pk,
                         unsigned char *sk,
                         const unsigned char *randomness);

void crypto_dkem_enc(unsigned char *c,
                     unsigned char *m,
                     const unsigned char *pk,
                     const unsigned char *coins);

void crypto_dkem_dec(unsigned char *m,
                     const unsigned char *c,
                     const unsigned char *sk);

#endif