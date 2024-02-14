#include <stdlib.h>
#include <stdio.h>
#include <lib25519.h>
#include "extractexpand.h"
#include "params.h"

void deriveKeyPair(unsigned char *sk, unsigned char *pk, unsigned char *ikm)
{
    unsigned char *dkpPrkLabel = 0x646b705f70726b;
    unsigned char *skLabel = 0x736b;

    unsigned char *dkpPrk = malloc(DH_BYTES);
    _labeledExtract(dkpPrk, dkpPrkLabel, ikm);
    _labeledExpand(sk, skLabel, dkpPrk, NULL);
    free(dkpPrk);
    lib25519_nG_montgomery25519(pk, sk);
}