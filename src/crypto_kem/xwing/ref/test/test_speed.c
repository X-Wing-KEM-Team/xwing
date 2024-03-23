#include "../../../mlkem/avx2/fips202.h"
#include "../xkem.h"
#include "cpucycles.h"
#include "speed_print.h"
#include <stdint.h>
#include <stdio.h>

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
  uint8_t randomness134[134];
  uint8_t randomness1222[1222];
  uint8_t randomness1536[1536];

  uint8_t output1[32];
  uint8_t output2[32];
  uint8_t output3[32];

  FILE *urandom = fopen("/dev/urandom", "r");
  fread(randomness0, 3 * XWING_SYMBYTES, 1, urandom);
  fread(randomness1, 2 * XWING_SYMBYTES, 1, urandom);
  fread(randomness134, 134, 1, urandom);
  fread(randomness1222, 1222, 1, urandom);
  fread(randomness1536, 1536, 1, urandom);

  fclose(urandom);

  for (i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    sha3_256(output1, randomness134, 134);
  }
  print_results("sha3-256-134:", t, NTESTS);

  for (i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    sha3_256(output2, randomness1222, 1222);
  }
  print_results("sha3-256-1222:", t, NTESTS);

  for (i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    sha3_256(output3, randomness1536, 1536);
  }
  print_results("sha3-256-1536:", t, NTESTS);
}
