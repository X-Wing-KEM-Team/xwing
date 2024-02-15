#include <stdint.h>
#include <stdio.h>
#include "cpucycles.h"
#include "speed_print.h"
#include "../xkem.h"
#include "../params.h"

#define NTESTS 1000

uint64_t t[NTESTS];

int main(void) {
    size_t i;

    uint8_t pk[XWING_PUBLICKEYBYTES];
    uint8_t sk[XWING_SECRETKEYBYTES];
    uint8_t pt[XWING_SSBYTES];
    uint8_t ct[XWING_CIPHERTEXTBYTES];
    uint8_t randomness0[XWING_SYMBYTES * 3];
    uint8_t randomness1[XWING_SYMBYTES * 2];

    FILE *urandom = fopen("/dev/urandom", "r");
    fread(randomness0, 3 * XWING_SYMBYTES, 1, urandom);
    fread(randomness1, 2 * XWING_SYMBYTES, 1, urandom);
    fclose(urandom);

    for(i = 0; i < NTESTS; ++i) {
        t[i] = cpucycles();
        crypto_xkem_keypair(pk, sk, randomness0);
    }
    print_results("xkem_keypair:", t, NTESTS);


    for(i = 0; i < NTESTS; ++i) {
        t[i] = cpucycles();
        crypto_xkem_enc(ct, pt, pk, randomness1);
    }
    print_results("xkem_enc:", t, NTESTS);


    for(i = 0; i < NTESTS; ++i) {
        t[i] = cpucycles();
        crypto_xkem_dec(pt, ct, sk);
    }
    print_results("xkem_dec:", t, NTESTS);
}
