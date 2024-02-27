#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <lib25519.h>
#include <string.h>
#include "gkem.h"
#include "../../mlkem/avx2/kem.h"
#include "../../mlkem/avx2/fips202.h"
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
  unsigned char buffer[GHPC_PRFINPUT];
  unsigned char *bufferPointer = buffer;

  crypto_kem_enc_derand(ct, bufferPointer, pk, coins); // h

  pk += MLKEM_PUBLICKEYBYTES;
  bufferPointer += MLKEM_SSBYTES;
  memcpy(bufferPointer, ct, MLKEM_CIPHERTEXTBYTES);
  bufferPointer += MLKEM_CIPHERTEXTBYTES;
  ct += MLKEM_CIPHERTEXTBYTES;
  coins += DH_BYTES;

  crypto_dkem_enc(ct, bufferPointer, pk, coins);
  bufferPointer += DH_BYTES;
  memcpy(bufferPointer, ct, DH_BYTES);

  sha3_256(ss, buffer, GHPC_PRFINPUT);
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
  unsigned char buffer[GHPC_PRFINPUT];
  unsigned char *bufferPointer = buffer;

  crypto_kem_dec(bufferPointer, ct, sk);
  bufferPointer += MLKEM_SSBYTES;
  memcpy(bufferPointer, ct, MLKEM_CIPHERTEXTBYTES);
  bufferPointer += MLKEM_CIPHERTEXTBYTES;
  sk += MLKEM_SECRETKEYBYTES;
  ct += MLKEM_CIPHERTEXTBYTES;

  crypto_dkem_dec(bufferPointer, ct, sk);
  bufferPointer += DH_BYTES;
  memcpy(bufferPointer, ct, DH_BYTES);
  sha3_256(ss, buffer, GHPC_PRFINPUT);
}
