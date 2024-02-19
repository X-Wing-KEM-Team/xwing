#include <stdlib.h>
#include <stdio.h>
#include <lib25519.h>
#include <string.h>
#include <sodium.h>
#include "extractexpand.h"
#include "params.h"

void deriveKeyPair(unsigned char *sk, unsigned char *pk, const unsigned char *ikm)
{
    unsigned char dkpPrk[DH_BYTES];
    unsigned char labeled_ikm[51] = {72, 80, 75, 69, 45, 118, 49, 75, 69, 77, 0, 32, 100, 107, 112, 95, 112, 114, 107};
    unsigned char labeled_info[16] = {0, 32, 72, 80, 75, 69, 45, 118, 49, 75, 69, 77, 0, 32, 115, 107};
    memcpy(labeled_ikm + 19, ikm, DH_BYTES);
    // int i;
    
    // for (i = 19; i < 51; i++)
    //     labeled_ikm[i] = ikm[i - 19];

    crypto_kdf_hkdf_sha256_extract(dkpPrk, NULL, 0, labeled_ikm, 51);
    crypto_kdf_hkdf_sha256_expand(sk, 32, (char *)labeled_info, 16, dkpPrk);
    lib25519_nG_montgomery25519(pk, sk);
}