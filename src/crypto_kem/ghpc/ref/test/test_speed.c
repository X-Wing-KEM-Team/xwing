#include <stdint.h>
#include <stdio.h>
#include "cpucycles.h"
#include "speed_print.h"
#include "../gkem.h"
#include "../params.h"

#define NTESTS 1000

uint64_t t[NTESTS];

int main(void) {
    size_t i;

    uint8_t pk[GHPC_PUBLICKEYBYTES];
    uint8_t sk[GHPC_SECRETKEYBYTES];
    uint8_t pt[GHPC_SSBYTES];
    uint8_t ct[GHPC_CIPHERTEXTBYTES];
    uint8_t randomness0[GHPC_SYMBYTES * 3];
    uint8_t randomness1[GHPC_SYMBYTES * 2];

    FILE *urandom = fopen("/dev/urandom", "r");
    fread(randomness0, 3 * GHPC_SYMBYTES, 1, urandom);
    fread(randomness1, 2 * GHPC_SYMBYTES, 1, urandom);
    fclose(urandom);

    for(i = 0; i < NTESTS; ++i) {
        t[i] = cpucycles();
        crypto_gkem_keypair(pk, sk, randomness0);
    }
    print_results("gkem_keypair:", t, NTESTS);


    for(i = 0; i < NTESTS; ++i) {
        t[i] = cpucycles();
        crypto_gkem_enc(ct, pt, pk, randomness1);
    }
    print_results("gkem_enc:", t, NTESTS);


    for(i = 0; i < NTESTS; ++i) {
        t[i] = cpucycles();
        crypto_gkem_dec(pt, ct, sk);
    }
    print_results("gkem_dec:", t, NTESTS);
}
