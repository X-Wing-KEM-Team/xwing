#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../params.h"
#include "../xkem.h"

static int testFunctionality()
{
  unsigned char sk0[XWING_SECRETKEYBYTES];
  unsigned char pk0[XWING_PUBLICKEYBYTES];
  unsigned char ct0[XWING_CIPHERTEXTBYTES];
  unsigned char shk0[XWING_SSBYTES];
  unsigned char shk1[XWING_SSBYTES];

  unsigned char randomness0[XWING_SYMBYTES * 3];
  unsigned char randomness1[XWING_SYMBYTES * 2];

  FILE *urandom = fopen("/dev/urandom", "r");
  fread(randomness0, 3 * XWING_SYMBYTES, 1, urandom);
  fread(randomness1, 2 * XWING_SYMBYTES, 1, urandom);
  fclose(urandom);

  /* TEST KEYPAIR */
  crypto_xkem_keypair_derand(pk0, sk0, randomness0);

  /* TEST ENCAPSULATION */
  crypto_xkem_enc_derand(ct0, shk0, pk0, randomness1);

  /* TEST DECAPSULATION */
  crypto_xkem_dec(shk1, ct0, sk0);

  assert(memcmp(shk0, shk1, (long unsigned int)32) == 0);
  return 0;
}

int main(void)
{
  int test0;
  test0 = testFunctionality();

  return test0;
}
