#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "../params.h"
#include "../xkem.h"
#include "test_vectors.h"

int testTestVectors()
{
  int i;

  unsigned char sk0[XWING_SECRETKEYBYTES];
  unsigned char pk0[XWING_PUBLICKEYBYTES];
  unsigned char ct0[XWING_CIPHERTEXTBYTES];
  unsigned char shk0[XWING_SSBYTES];
  unsigned char shk1[XWING_SSBYTES];

  /* TEST KEYPAIR */
  crypto_xkem_keypair(pk0, sk0, XWING_SEED_TEST_VECTOR);

  for (i = 0; i < XWING_SECRETKEYBYTES; i++)
  {
    if (sk0[i] != XWING_SECRETKEY_TEST_VECTOR[i])
      printf("crypto_xkem_keypair sk : %d sk0= %#04X and XWING_SECRETKEY_TEST_VECTOR = %#04X\n", i, sk0[i], XWING_SECRETKEY_TEST_VECTOR[i]);
  }

  for (i = 0; i < XWING_PUBLICKEYBYTES; i++)
  {
    if (pk0[i] != XWING_PUBLICKEY_TEST_VECTOR[i])
      printf("error crypto_xkem_keypair pk: %d pk0= %#04X - XWING_PUBLICKEY_TEST_VECTOR = %#04X\n", i, pk0[i], XWING_PUBLICKEY_TEST_VECTOR[i]);
  }

  crypto_xkem_enc(ct0, shk0, XWING_PUBLICKEY_TEST_VECTOR, XWING_ESEED_TEST_VECTOR);

  for (i = 0; i < XWING_CIPHERTEXTBYTES; i++)
  {
    if (ct0[i] != XWING_CIPHERTEXT_TEST_VECTOR[i])
      printf("error crypto_xkem_enc ct: %d ct0= %#04X - XWING_CIPHERTEXT_TEST_VECTOR = %#04X\n", i, ct0[i], XWING_CIPHERTEXT_TEST_VECTOR[i]);
  }

  for (i = 0; i < XWING_SSBYTES; i++)
  {
    if (shk0[i] != XWING_SHAREDKEY_TEST_VECTOR[i])
      printf("error crypto_xkem_enc shk: %d shk0= %#04X - XWING_SHAREDKEY_TEST_VECTOR= %#04X\n", i, shk0[i], XWING_SHAREDKEY_TEST_VECTOR[i]);
  }

  /* TEST DECAPSULATION */

  crypto_xkem_dec(shk1, XWING_CIPHERTEXT_TEST_VECTOR, XWING_SECRETKEY_TEST_VECTOR);

  for (i = 0; i < XWING_SSBYTES; i++)
  {
    if (shk1[i] != XWING_SHAREDKEY_TEST_VECTOR[i])
      printf("error crypto_xkem_dec: %d shk2= %#04X - XWING_SHAREDKEY_TEST_VECTOR = %#04X\n", i, shk1[i], XWING_SHAREDKEY_TEST_VECTOR[i]);
  }
  return 0;
}

int testFunctionality()
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
  sodium_init();
  int test0, test1;
  test0 = testFunctionality();
  test1 = testTestVectors();

  return -1 * (test0 && test1);
}