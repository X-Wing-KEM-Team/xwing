#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <lib25519.h>
#include <string.h>
#include "gkem.h"
#include "../../kyber/avx2/kem.h"
#include "../../kyber/avx2/fips202.h"
#include "params.h"

/*************************************************
 * Name:        crypto_gkem_keypair
 *
 * Description: Generates public and private key for the CCA-secure
 *              X-Wing key encapsulation mechanism
 *
 * Arguments:   - unsigned char *pk:               pointer to output public key (of length GHPC_PUBLICKEYBYTES bytes)
 *              - unsigned char *sk:               pointer to output private key (of length GHPC_SECRETKEYBYTES bytes)
 *              - const unsigned char *randomness: pointer to input random coins used as seed (of length 3*GHPC_SYMBYTES bytes)
 *                                                 to deterministically generate all randomness
 **************************************************/
void crypto_gkem_keypair(unsigned char *pk,
                         unsigned char *sk,
                         const unsigned char *randomness)
{
  crypto_kem_keypair_derand(pk, sk, randomness);
  pk += MLKEM_PUBLICKEYBYTES;
  sk += MLKEM_SECRETKEYBYTES;
  randomness += 2 * GHPC_SYMBYTES;
  crypto_dkem_keypair(pk, sk, randomness);
}

/*************************************************
 * Name:        crypto_gkem_enc
 *
 * Description: Generates cipher text and shared
 *              secret for given public key
 *
 * Arguments:   - unsigned char *ct:          pointer to output ciphertext (of length GHPC_CIPHERTEXTBYTES bytes)
 *              - unsigned char *ss:          pointer to output decrypted message (of length GHPC_SSBYTES bytes)
 *              - const unsigned char *pk:    pointer to input public key (of length GHPC_PUBLICKEYBYTES bytes)
 *              - const unsigned char *coins: pointer to input random coins used as seed (of length 2*GHPC_SYMBYTES bytes)
 *                                            to deterministically generate all randomness
 **************************************************/
void crypto_gkem_enc(unsigned char *ct,
                     unsigned char *ss,
                     const unsigned char *pk,
                     const unsigned char *coins)
{
  unsigned char bufPointer[GHPC_PRFINPUT];
  unsigned char mlkemBuffer[MLKEM_SSBYTES];
  unsigned char dhBuffer[DH_BYTES];

  crypto_kem_enc_derand(ct, mlkemBuffer, pk, coins); // h

  // memcpy(bufPointer, ct, MLKEM_CIPHERTEXTBYTES); h

  pk += MLKEM_PUBLICKEYBYTES;
  ct += MLKEM_CIPHERTEXTBYTES;
  coins += DH_BYTES;

  crypto_dkem_enc(ct, dhBuffer, pk, coins);

  // memcpy(bufPointer, ct, DH_BYTES); h

  int i;

  for (i = 0; i < DH_BYTES; i++)
  {
    bufPointer[i] = mlkemBuffer[i];
    bufPointer[i + MLKEM_SSBYTES + MLKEM_CIPHERTEXTBYTES] = dhBuffer[i];
    bufPointer[i + MLKEM_SSBYTES + MLKEM_CIPHERTEXTBYTES + DH_BYTES] = ct[i];
  }

  memcpy(bufPointer + MLKEM_SSBYTES, ct - MLKEM_CIPHERTEXTBYTES, MLKEM_CIPHERTEXTBYTES);

  sha3_256(ss, bufPointer, GHPC_PRFINPUT);
}

/*************************************************
 * Name:        crypto_gkem_dec
 *
 * Description: Generates shared secret for given
 *              cipher text and private key
 *
 * Arguments:   - unsigned char *ss:        pointer to output decrypted message (of length GHPC_SSBYTES bytes)
 *              - const unsigned char *ct:  pointer to input ciphertext (of length GHPC_CIPHERTEXTKEYBYTES bytes)
 *              - const unsigned char *sk:  pointer to input secret key (of length GHPC_SECRETKEYBYTES bytes)
 **************************************************/
void crypto_gkem_dec(uint8_t *ss,
                     const uint8_t *ct,
                     const uint8_t *sk)
{
  unsigned char bufPointer[GHPC_PRFINPUT];
  unsigned char mlkemBuffer[MLKEM_SSBYTES];
  unsigned char dhBuffer[DH_BYTES];

  crypto_kem_dec(mlkemBuffer, ct, sk);

  sk += MLKEM_SECRETKEYBYTES;
  ct += MLKEM_CIPHERTEXTBYTES;

  crypto_dkem_dec(dhBuffer, ct, sk);

  int i;

  for (i = 0; i < DH_BYTES; i++)
  {
    bufPointer[i] = mlkemBuffer[i];
    bufPointer[i + MLKEM_SSBYTES + MLKEM_CIPHERTEXTBYTES] = dhBuffer[i];
    bufPointer[i + MLKEM_SSBYTES + MLKEM_CIPHERTEXTBYTES + DH_BYTES] = ct[i];
  }

  memcpy(bufPointer + MLKEM_SSBYTES, ct - MLKEM_CIPHERTEXTBYTES, MLKEM_CIPHERTEXTBYTES);

  sha3_256(ss, bufPointer, GHPC_PRFINPUT);
}
