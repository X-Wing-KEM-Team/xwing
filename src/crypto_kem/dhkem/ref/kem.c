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
    memcpy(sk, randomness, DH_BYTES);

    lib25519_nG_montgomery25519(pk, sk);
}

void crypto_dkem_enc(unsigned char *c,
                     unsigned char *m,
                     const unsigned char *pk,
                     const unsigned char *coins)
{
    unsigned char *skE, *dh, *kemContext;
    skE = malloc(DH_BYTES);
    dh = malloc(DH_BYTES);
    kemContext = malloc(2 * DH_BYTES);

    deriveKeyPair(skE, c, coins);
    lib25519_dh(dh, pk, skE);
    memcpy(kemContext, c, DH_BYTES);
    kemContext += DH_BYTES;
    memcpy(kemContext, pk, DH_BYTES);
    kemContext -= DH_BYTES;
    extractAndExpand(m, dh, kemContext);
    free(skE);
    free(dh);
    free(kemContext);
}

void crypto_dkem_dec(unsigned char *m,
                     const unsigned char *c,
                     const unsigned char *sk)
{
    unsigned char *dh, *kemContext, *pk;
    dh = malloc(DH_BYTES);
    pk = malloc(DH_BYTES);
    kemContext = malloc(2 * DH_BYTES);

    lib25519_dh(dh, sk, c);
    lib25519_nG_montgomery25519(pk, sk);

    memcpy(kemContext, c, DH_BYTES);
    kemContext += DH_BYTES;
    memcpy(kemContext, pk, DH_BYTES);
    kemContext -= DH_BYTES;
    extractAndExpand(m, dh, kemContext);
    free(dh);
    free(kemContext);
    free(pk);
}