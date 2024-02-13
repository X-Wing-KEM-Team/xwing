#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../params.h"
#include "../xkem.h"
#include "test_vectors.h"

static int testTestVectors()
{

  int i, j, error;
  error = 0;

  unsigned char sk0[XWING_SECRETKEYBYTES];
  unsigned char pk0[XWING_PUBLICKEYBYTES];
  unsigned char ct0[XWING_CIPHERTEXTBYTES];
  unsigned char shk0[XWING_SSBYTES];
  unsigned char shk1[XWING_SSBYTES];

  for (j = 0; j < 3; j++)
  {
    /* TEST KEYPAIR */
    crypto_xkem_keypair(pk0, sk0, XWING_SEED_TEST_VECTOR[j]);

    for (i = 0; i < XWING_SECRETKEYBYTES; i++)
    {
      if (sk0[i] != XWING_SECRETKEY_TEST_VECTOR[j][i])
      {
        printf("vector %d crypto_xkem_keypair sk : %d sk0= %#04X and XWING_SECRETKEY_TEST_VECTOR = %#04X\n", j, i, sk0[i], XWING_SECRETKEY_TEST_VECTOR[j][i]);
        error = 1;
      }
    }

    for (i = 0; i < XWING_PUBLICKEYBYTES; i++)
    {
      if (pk0[i] != XWING_PUBLICKEY_TEST_VECTOR[j][i])
      {
        printf("vector %d error crypto_xkem_keypair pk: %d pk0= %#04X - XWING_PUBLICKEY_TEST_VECTOR = %#04X\n", j, i, pk0[i], XWING_PUBLICKEY_TEST_VECTOR[j][i]);
        error = 1;
      }
    }
    crypto_xkem_enc(ct0, shk0, XWING_PUBLICKEY_TEST_VECTOR[j], XWING_ESEED_TEST_VECTOR[j]);

    for (i = 0; i < XWING_CIPHERTEXTBYTES; i++)
    {
      if (ct0[i] != XWING_CIPHERTEXT_TEST_VECTOR[j][i])
      {
        printf("error crypto_xkem_enc ct: %d ct0= %#04X - XWING_CIPHERTEXT_TEST_VECTOR = %#04X\n", i, ct0[i], XWING_CIPHERTEXT_TEST_VECTOR[j][i]);
        error = 1;
      }
    }

    for (i = 0; i < XWING_SSBYTES; i++)
    {
      if (shk0[i] != XWING_SHAREDKEY_TEST_VECTOR[j][i])
      {
        printf("error crypto_xkem_enc shk: %d shk0= %#04X - XWING_SHAREDKEY_TEST_VECTOR= %#04X\n", i, shk0[i], XWING_SHAREDKEY_TEST_VECTOR[j][i]);
        error = 1;
      }
    }

    /* TEST DECAPSULATION */

    crypto_xkem_dec(shk1, XWING_CIPHERTEXT_TEST_VECTOR[j], XWING_SECRETKEY_TEST_VECTOR[j]);

    for (i = 0; i < XWING_SSBYTES; i++)
    {
      if (shk1[i] != XWING_SHAREDKEY_TEST_VECTOR[j][i])
      {
        printf("error crypto_xkem_dec: %d shk1= %#04X - XWING_SHAREDKEY_TEST_VECTOR = %#04X\n", i, shk1[i], XWING_SHAREDKEY_TEST_VECTOR[j][i]);
        error = 1;
      }
    }
  }
  assert(error == 0);
  return 0;
}

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
  crypto_xkem_keypair(pk0, sk0, randomness0);

  /* TEST ENCAPSULATION */
  crypto_xkem_enc(ct0, shk0, pk0, randomness1);

  /* TEST DECAPSULATION */
  crypto_xkem_dec(shk1, ct0, sk0);
  assert(memcmp(shk0, shk1, (long unsigned int)32) == 0);
  return 0;
}

int main(void)
{
  int test0, test1;
  test0 = testFunctionality();
  test1 = testTestVectors();

  return -1 * (test0 && test1);
}
