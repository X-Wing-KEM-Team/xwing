#include <stdlib.h>
#include <stdio.h>
#include "extractexpand.h"

void deriveKeyPair(unsigned char *sk, unsigned char *pk, unsigned char *out, unsigned char *ikm)
{
    unsigned char *dkpPrkLabel = 0x646b705f70726b;
    unsigned char *skLabel = 0x736b;

    unsigned char *dkpPrk = malloc(32);
    _labeledExtract(dkpPrk, dkpPrkLabel, ikm);
    _labeledExpand(sk, skLabel, dkpPrk, NULL);
    free(dkpPrk);
}