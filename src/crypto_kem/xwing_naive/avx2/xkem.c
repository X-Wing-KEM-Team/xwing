#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <lib25519.h>
#include <string.h>
#include "xkem.h"
#include "../../kyber/avx2/kem.h"
#include "../../kyber/avx2/fips202.h"
#include "params.h"

/*************************************************
 * Name:        crypto_xkem_keypair
 *
 * Description: Generates public and private key for the CCA-secure
 *              X-Wing key encapsulation mechanism
 *
 * Arguments:   - unsigned char *pk:               pointer to output public key (of length XWING_PUBLICKEYBYTES bytes)
 *              - unsigned char *sk:               pointer to output private key (of length XWING_SECRETKEYBYTES bytes)
 *              - const unsigned char *randomness: pointer to input random coins used as seed (of length 3*XWING_SYMBYTES bytes)
 *                                                 to deterministically generate all randomness
 **************************************************/
void crypto_xkem_keypair(unsigned char *pk,
                         unsigned char *sk,
                         const unsigned char *randomness)
{
  crypto_kem_keypair_derand(pk, sk, randomness);
  pk += MLKEM_PUBLICKEYBYTES;
  sk += MLKEM_SECRETKEYBYTES;
  randomness += 2 * XWING_SYMBYTES;
  lib25519_nG_montgomery25519(pk, randomness);

  int i;
  for (i = 0; i < DH_BYTES; i++)
  {
    sk[i] = randomness[i];
    sk[i + DH_BYTES] = pk[i];
  }
}

/*************************************************
 * Name:        crypto_xkem_enc
 *
 * Description: Generates cipher text and shared
 *              secret for given public key
 *
 * Arguments:   - unsigned char *ct:          pointer to output ciphertext (of length XWING_CIPHERTEXTBYTES bytes)
 *              - unsigned char *ss:          pointer to output decrypted message (of length XWING_SSBYTES bytes)
 *              - const unsigned char *pk:    pointer to input public key (of length XWING_PUBLICKEYBYTES bytes)
 *              - const unsigned char *coins: pointer to input random coins used as seed (of length 2*XWING_SYMBYTES bytes)
 *                                            to deterministically generate all randomness
 **************************************************/
void crypto_xkem_enc(unsigned char *ct,
                     unsigned char *ss,
                     const unsigned char *pk,
                     const unsigned char *coins)
{
  unsigned char bufPointer[XWING_PRFINPUT];
  unsigned char mlkemBuffer[MLKEM_SSBYTES];
  unsigned char dhBuffer[DH_BYTES];

  int i;
  for (i = 0; i < 6; i++)
    bufPointer[i] = XWING_LABEL[i];

  crypto_kem_enc_derand(ct, mlkemBuffer, pk, coins);

  pk += MLKEM_PUBLICKEYBYTES;
  ct += MLKEM_CIPHERTEXTBYTES;
  coins += DH_BYTES;

  lib25519_nG_montgomery25519(ct, coins);
  lib25519_dh(dhBuffer, pk, coins);

  for (i = 0; i < DH_BYTES; i++)
  {
    bufPointer[i + 6] = mlkemBuffer[i];
    bufPointer[i + 6 + MLKEM_CIPHERTEXTBYTES + MLKEM_SSBYTES] = dhBuffer[i];
    bufPointer[i + 6 + MLKEM_CIPHERTEXTBYTES + MLKEM_SSBYTES + DH_BYTES] = ct[i];
    bufPointer[i + 6 + MLKEM_CIPHERTEXTBYTES + MLKEM_SSBYTES + DH_BYTES + DH_BYTES] = pk[i];
  }

  for (i = MLKEM_SSBYTES; i < MLKEM_CIPHERTEXTBYTES + MLKEM_SSBYTES; i++)
    bufPointer[i + 6] = ct[i - MLKEM_CIPHERTEXTBYTES];

  sha3_256(ss, bufPointer, XWING_PRFINPUT);
}

/*************************************************
 * Name:        crypto_xkem_dec
 *
 * Description: Generates shared secret for given
 *              cipher text and private key
 *
 * Arguments:   - unsigned char *ss:        pointer to output decrypted message (of length XWING_SSBYTES bytes)
 *              - const unsigned char *ct:  pointer to input ciphertext (of length XWING_CIPHERTEXTKEYBYTES bytes)
 *              - const unsigned char *sk:  pointer to input secret key (of length XWING_SECRETKEYBYTES bytes)
 **************************************************/
void crypto_xkem_dec(uint8_t *ss,
                     const uint8_t *ct,
                     const uint8_t *sk)
{
  unsigned char bufPointer[XWING_PRFINPUT];
  unsigned char mlkemBuffer[MLKEM_SSBYTES];
  unsigned char dhBuffer[DH_BYTES];

  int i;
  for (i = 0; i < 6; i++)
    bufPointer[i] = XWING_LABEL[i];

  crypto_kem_dec(mlkemBuffer, ct, sk);
  sk += MLKEM_SECRETKEYBYTES;
  ct += MLKEM_CIPHERTEXTBYTES;

  lib25519_dh(dhBuffer, ct, sk);
  sk += DH_BYTES;

  for (i = 0; i < DH_BYTES; i++)
  {
    bufPointer[i + 6] = mlkemBuffer[i];
    bufPointer[i + 6 + MLKEM_CIPHERTEXTBYTES + MLKEM_SSBYTES] = dhBuffer[i];
    bufPointer[i + 6 + MLKEM_CIPHERTEXTBYTES + MLKEM_SSBYTES + DH_BYTES] = ct[i];
    bufPointer[i + 6 + MLKEM_CIPHERTEXTBYTES + MLKEM_SSBYTES + DH_BYTES + DH_BYTES] = sk[i];
  }

  for (i = MLKEM_SSBYTES; i < MLKEM_CIPHERTEXTBYTES + MLKEM_SSBYTES; i++)
    bufPointer[i + 6] = ct[i - MLKEM_CIPHERTEXTBYTES];

  sha3_256(ss, bufPointer, XWING_PRFINPUT);
}
