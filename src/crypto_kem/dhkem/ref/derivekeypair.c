#include <stdlib.h>
#include <stdio.h>
#include <lib25519.h>
#include <stddef.h>
#include "extractexpand.h"
#include "params.h"

void deriveKeyPair(unsigned char *sk, unsigned char *pk, const unsigned char *ikm)
{
    unsigned char dkpPrkLabel[7] = {100, 107, 112, 95, 112, 114, 107};
    unsigned char skLabel[2] = {115, 107};
    unsigned char *dkpPrk = malloc(DH_BYTES);
    labeledExtract(dkpPrk, dkpPrkLabel, ikm);
    labeledExpand(sk, skLabel, dkpPrk, NULL, 0, 2);
    free(dkpPrk);
    lib25519_nG_montgomery25519(pk, sk);
}