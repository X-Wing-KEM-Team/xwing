#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sodium.h>

#include "../params.h"
#include "../gkem.h"

static int testFunctionality()
{
  unsigned char sk0[GHPC_SECRETKEYBYTES];
  unsigned char pk0[GHPC_PUBLICKEYBYTES];
  unsigned char ct0[GHPC_CIPHERTEXTBYTES];
  unsigned char shk0[GHPC_SSBYTES];
  unsigned char shk1[GHPC_SSBYTES];

  unsigned char randomness0[DH_BYTES];
  unsigned char randomness1[DH_BYTES];

  FILE *urandom = fopen("/dev/urandom", "r");
  fread(randomness0, 3 * DH_BYTES, 1, urandom);
  fread(randomness1, 2 * DH_BYTES, 1, urandom);
  fclose(urandom);

  /* TEST KEYPAIR */
  crypto_gkem_keypair(pk0, sk0, randomness0);

  /* TEST ENCAPSULATION */
  crypto_gkem_enc(ct0, shk0, pk0, randomness1);

  // /* TEST DECAPSULATION */
  crypto_gkem_dec(shk1, ct0, sk0);

  assert(memcmp(shk0, shk1, (long unsigned int)32) == 0);
  return 0;
}

int main(void)
{

  if (sodium_init() < 0) {
        return 1;
    }
  testFunctionality();

  return 0;
}
