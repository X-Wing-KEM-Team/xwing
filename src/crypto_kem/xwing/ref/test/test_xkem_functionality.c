#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../../../mlkem/avx2/randombytes.h"
#include "../params.h"
#include "../xkem.h"
#include "test_vectors.h"


static int testInvalidSecretKey(void)
{
  unsigned char pk[XWING_PUBLICKEYBYTES];
  unsigned char sk[XWING_SECRETKEYBYTES];
  unsigned char ct[XWING_CIPHERTEXTBYTES];
  unsigned char key_a[XWING_SSBYTES];
  unsigned char key_b[XWING_SSBYTES];

  crypto_xkem_keypair(pk, sk);

  crypto_xkem_enc(ct, key_b, pk);

  randombytes(sk, XWING_SECRETKEYBYTES);

  crypto_xkem_dec(key_a, ct, sk);

  if(!memcmp(key_a, key_b, XWING_SSBYTES)) {
    printf("ERROR invalid sk\n");
    return 1;
  }

  return 0;
}

static int testInvalidCiphertext(void)
{
  unsigned char pk[XWING_PUBLICKEYBYTES];
  unsigned char sk[XWING_SECRETKEYBYTES];
  unsigned char ct[XWING_CIPHERTEXTBYTES];
  unsigned char key_a[XWING_SSBYTES];
  unsigned char key_b[XWING_SSBYTES];
  unsigned char b;
  size_t pos;

  do {
    randombytes(&b, sizeof(unsigned char));
  } while(!b);
  randombytes((unsigned char *)&pos, sizeof(unsigned char));

  //Alice generates a public key
  crypto_xkem_keypair(pk, sk);

  //Bob derives a secret key and creates a response
  crypto_xkem_enc(ct, key_b, pk);

  //Change some byte in the ciphertext (i.e., encapsulated key)
  ct[pos % XWING_CIPHERTEXTBYTES] ^= b;

  //Alice uses Bobs response to get her shared key
  crypto_xkem_dec(key_a, ct, sk);

  if(!memcmp(key_a, key_b, XWING_SSBYTES)) {
    printf("ERROR invalid ciphertext\n");
    return 1;
  }

  return 0;
}

static int testTestVectors(void)
{
  int i, error;
  error = 0;

  unsigned char sk0[XWING_SECRETKEYBYTES];
  unsigned char pk0[XWING_PUBLICKEYBYTES];
  unsigned char ct0[XWING_CIPHERTEXTBYTES];
  unsigned char shk0[XWING_SSBYTES];
  unsigned char shk1[XWING_SSBYTES];

    /* TEST KEYPAIR */
    crypto_xkem_keypair_derand(pk0, sk0, XWING_SEED_TEST_VECTOR);

    for (i = 0; i < XWING_PUBLICKEYBYTES; i++)
    {
      if (pk0[i] != XWING_PUBLICKEY_TEST_VECTOR[i])
      {
        printf("error crypto_xkem_keypair_derand pk: %d pk0= %#04X - XWING_PUBLICKEY_TEST_VECTOR = %#04X\n", i, pk0[i], XWING_PUBLICKEY_TEST_VECTOR[i]);
        error = 1;
      }
    }

    for (i = 0; i < XWING_SECRETKEYBYTES; i++)
    {
      if (sk0[i] != XWING_SECRETKEY_TEST_VECTOR[i])
      {
        printf("crypto_xkem_keypair_derand sk : %d sk0= %#04X and XWING_SECRETKEY_TEST_VECTOR = %#04X\n", i, sk0[i], XWING_SECRETKEY_TEST_VECTOR[i]);
        error = 1;
      }
    }

    /* TEST ENCAPSULATION */    
    crypto_xkem_enc_derand(ct0, shk0, XWING_PUBLICKEY_TEST_VECTOR, XWING_ESEED_TEST_VECTOR);

    for (i = 0; i < XWING_CIPHERTEXTBYTES; i++)
    {
      if (ct0[i] != XWING_CIPHERTEXT_TEST_VECTOR[i])
      {
        printf("error crypto_xkem_enc_derand ct: %d ct0= %#04X - XWING_CIPHERTEXT_TEST_VECTOR = %#04X\n", i, ct0[i], XWING_CIPHERTEXT_TEST_VECTOR[i]);
        error = 1;
      }
    }

    for (i = 0; i < XWING_SSBYTES; i++)
    {
      if (shk0[i] != XWING_SHAREDKEY_TEST_VECTOR[i])
      {
        printf("error crypto_xkem_enc_derand shk: %d shk0= %#04X - XWING_SHAREDKEY_TEST_VECTOR= %#04X\n", i, shk0[i], XWING_SHAREDKEY_TEST_VECTOR[i]);
        error = 1;
      }
    }

   /* TEST DECAPSULATION */
    crypto_xkem_dec(shk1, XWING_CIPHERTEXT_TEST_VECTOR, XWING_SECRETKEY_TEST_VECTOR);

    for (i = 0; i < XWING_SSBYTES; i++)
    {
      if (shk1[i] != XWING_SHAREDKEY_TEST_VECTOR[i])
      {
        printf("error crypto_xkem_dec: %d shk1= %#04X - XWING_SHAREDKEY_TEST_VECTOR = %#04X\n", i, shk1[i], XWING_SHAREDKEY_TEST_VECTOR[i]);
        error = 1;
      }
    }

  assert(error == 0);
  return 0;
}

static int testFunctionality(void)
{
  unsigned char sk0[XWING_SECRETKEYBYTES];
  unsigned char pk0[XWING_PUBLICKEYBYTES];
  unsigned char ct0[XWING_CIPHERTEXTBYTES];
  unsigned char shk0[XWING_SSBYTES];
  unsigned char shk1[XWING_SSBYTES];

  unsigned char randomness0[XWING_SYMBYTES];
  unsigned char randomness1[XWING_SYMBYTES * 2];

  FILE *urandom = fopen("/dev/urandom", "r");
  fread(randomness0, XWING_SYMBYTES, 1, urandom);
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
  testFunctionality();
  testTestVectors();
  testInvalidSecretKey();
  testInvalidCiphertext();

  return 0;
}
