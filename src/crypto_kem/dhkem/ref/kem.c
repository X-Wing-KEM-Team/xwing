#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <lib25519.h>
#include <string.h>
#include "kem.h"
#include "params.h"



void crypto_dkem_keypair(unsigned char *pk,
                         unsigned char *sk,
                         const unsigned char *randomness)
{
}

void crypto_dkem_enc(unsigned char *c,
                     unsigned char *m,
                     const unsigned char *pk,
                     const unsigned char *coins)
{
    
}

void crypto_dkem_dec(unsigned char *m,
                     const unsigned char *c,
                     const unsigned char *sk)
{
}