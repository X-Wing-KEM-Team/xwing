#ifndef CRYPTO_KEM_H
#define CRYPTO_KEM_H

#include <stdint.h>

void crypto_gkem_keypair(unsigned char *pk,
                         unsigned char *sk,
                         const unsigned char *randomness);

void crypto_gkem_enc(unsigned char *c,
                     unsigned char *m,
                     const unsigned char *pk,
                     const unsigned char *coins);

void crypto_gkem_dec(unsigned char *m,
                     const unsigned char *c,
                     const unsigned char *sk);

#endif