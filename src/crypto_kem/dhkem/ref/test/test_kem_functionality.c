#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sodium.h>

#include "../params.h"
#include "../kem.h"
#include "test_vectors.h"

static int testTestVectors()
{
  int i, error;
  error = 0;

  unsigned char ct0[DH_BYTES];
  unsigned char shk0[DH_BYTES];
  // unsigned char shk1[DH_BYTES];

  crypto_dkem_enc(ct0, shk0, DHKEM_PUBLICKEY_TEST_VECTOR, DHKEM_IKM);

  // for (i = 0; i < DH_BYTES; i++)
  // {
  //   if (ct0[i] != DHKEM_CIPHERTEXT_TEST_VECTOR[i])
  //   {
  //     printf("error crypto_xkem_enc ct: %d ct0= %#04X - DHKEM_CIPHERTEXT_TEST_VECTOR = %#04X\n", i, ct0[i], DHKEM_CIPHERTEXT_TEST_VECTOR[i]);
  //     error = 1;
  //   }
  // }

  // for (i = 0; i < DH_BYTES; i++)
  // {
  //   if (shk0[i] != DHKEM_SHAREDKEY_TEST_VECTOR[i])
  //   {
  //     printf("error crypto_xkem_enc shk: %d shk0= %#04X - DHKEM_SHAREDKEY_TEST_VECTOR= %#04X\n", i, shk0[i], DHKEM_SHAREDKEY_TEST_VECTOR[i]);
  //     error = 1;
  //   }
  // }

  /* TEST DECAPSULATION */

  // crypto_xkem_dec(shk1, DHKEM_CIPHERTEXT_TEST_VECTOR, DHKEM_SECRETKEY_TEST_VECTOR);

  // for (i = 0; i < DH_BYTES; i++)
  // {
  //   if (shk1[i] != DHKEM_SHAREDKEY_TEST_VECTOR[i])
  //   {
  //     printf("error crypto_xkem_dec: %d shk1= %#04X - DHKEM_SHAREDKEY_TEST_VECTOR = %#04X\n", i, shk1[i], DHKEM_SHAREDKEY_TEST_VECTOR[i]);
  //     error = 1;
  //   }
  // }

  // assert(error == 0);
  return error;
}

static int testFunctionality()
{
  unsigned char sk0[DH_BYTES];
  unsigned char pk0[DH_BYTES];
  unsigned char ct0[DH_BYTES];
  unsigned char shk0[DH_BYTES];
  unsigned char shk1[DH_BYTES];

  unsigned char randomness0[DH_BYTES];
  unsigned char randomness1[DH_BYTES];

  FILE *urandom = fopen("/dev/urandom", "r");
  fread(randomness0, DH_BYTES, 1, urandom);
  fread(randomness1, DH_BYTES, 1, urandom);
  fclose(urandom);

  /* TEST KEYPAIR */
  crypto_dkem_keypair(pk0, sk0, randomness0);

  /* TEST ENCAPSULATION */
  crypto_dkem_enc(ct0, shk0, pk0, randomness1);

  // /* TEST DECAPSULATION */
  crypto_dkem_dec(shk1, ct0, sk0);

  // int i;
  // printf("shk0: ");
  // for (i = 0; i < DH_BYTES; i++)
  // {

  //   printf("%04X", shk0[i]);
  // }
  // printf("\n");

  // printf("shk1: ");
  // for (i = 0; i < DH_BYTES; i++)
  // {

  //   printf("%04X", shk1[i]);
  // }
  // printf("\n");

  // assert(memcmp(shk0, shk1, (long unsigned int)32) == 0);
  return 0;
}

int main(void)
{
  sodium_init();
  int test0, test1;
  // test0 = testFunctionality();
  // test1 = 0;
  test0 = 0;
  test1 = testTestVectors();

  return -1 * (test0 && test1);
}
