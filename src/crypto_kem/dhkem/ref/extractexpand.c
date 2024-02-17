
#include <lib25519.h>
#include <stdlib.h>
#include <sodium.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "params.h"

void extractAndExpand(unsigned char *sharedSecret, unsigned char *dh, unsigned char *kemContext)
{
    unsigned char eaePrk[DH_BYTES];
    unsigned char labeled_ikm[51] = {72, 80, 75, 69, 45, 118, 49, 75, 69, 77, 0, 32, 101, 97, 101, 95, 112, 114, 107};
    unsigned char labeled_info[91] = {0, 32, 72, 80, 75, 69, 45, 118, 49, 75, 69, 77, 0, 32, 115, 104, 97, 114, 101, 100, 95, 115, 101, 99, 114, 101, 116};

    int i;
    for (i = 19; i < 51; i++)
        labeled_ikm[i] = dh[i - 19];
    for (i = 27; i < 91; i++)
        labeled_info[i] = kemContext[i - 27];

    crypto_kdf_hkdf_sha256_extract(eaePrk, NULL, 0, labeled_ikm, 51);
    crypto_kdf_hkdf_sha256_expand(sharedSecret, 32, (char *)labeled_info, 91, eaePrk);
}