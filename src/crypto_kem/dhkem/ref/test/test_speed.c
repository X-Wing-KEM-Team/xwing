#include <stdint.h>
#include <stdio.h>
#include "cpucycles.h"
#include "speed_print.h"
#include "../kem.h"
#include "../params.h"

#define NTESTS 1000

uint64_t t[NTESTS];

int main(void) {
    size_t i;

    uint8_t pk[DH_BYTES];
    uint8_t sk[DH_BYTES];
    uint8_t pt[DH_BYTES];
    uint8_t ct[DH_BYTES];
    uint8_t randomness0[DH_BYTES * 3];
    uint8_t randomness1[DH_BYTES];

    FILE *urandom = fopen("/dev/urandom", "r");
    fread(randomness0, DH_BYTES, 1, urandom);
    fread(randomness1, DH_BYTES, 1, urandom);
    fclose(urandom);

    for(i = 0; i < NTESTS; ++i) {
        t[i] = cpucycles();
        crypto_dkem_keypair(pk, sk, randomness0);
    }
    print_results("dkem_keypair:", t, NTESTS);


    for(i = 0; i < NTESTS; ++i) {
        t[i] = cpucycles();
        crypto_dkem_enc(ct, pt, pk, randomness1);
    }
    print_results("dkem_enc:", t, NTESTS);


    for(i = 0; i < NTESTS; ++i) {
        t[i] = cpucycles();
        crypto_dkem_dec(pt, ct, sk);
    }
    print_results("dkem_dec:", t, NTESTS);
}
