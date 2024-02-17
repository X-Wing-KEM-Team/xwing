#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <lib25519.h>
#include <string.h>
#include "kem.h"
#include "params.h"
#include "derivekeypair.h"
#include "extractexpand.h"

void crypto_dkem_keypair(unsigned char *pk,
                         unsigned char *sk,
                         const unsigned char *randomness)
{
    *sk = *randomness;
    lib25519_nG_montgomery25519(pk, sk);
}

void crypto_dkem_enc(unsigned char *c,
                     unsigned char *m,
                     const unsigned char *pk,
                     const unsigned char *coins)
{
    unsigned char skE[DH_BYTES], dh[DH_BYTES], kemContext[DH_BYTES * 2];
    int i;
    deriveKeyPair(skE, c, coins);
    lib25519_dh(dh, pk, skE);

    for (i = 0; i < DH_BYTES; i++)
    {
        kemContext[i] = c[i];
        kemContext[i + DH_BYTES] = pk[i];
    }
    extractAndExpand(m, dh, kemContext);
}

void crypto_dkem_dec(unsigned char *m,
                     const unsigned char *c,
                     const unsigned char *sk)
{
    unsigned char pk[DH_BYTES], dh[DH_BYTES], kemContext[DH_BYTES * 2];
    int i;
    lib25519_dh(dh, c, sk);
    lib25519_nG_montgomery25519(pk, sk);

    for (i = 0; i < DH_BYTES; i++)
    {
        kemContext[i] = c[i];
        kemContext[i + DH_BYTES] = pk[i];
    }
    extractAndExpand(m, dh, kemContext);
}