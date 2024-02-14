#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <lib25519.h>
#include "gkem.h"
#include "params.h"
#include "../../mlkem/ref/symmetric.h"
#include "../../mlkem/ref/kem.h"
#include "../../dhkem/ref/kem.h"

static const unsigned char X25519_BASE[32] = {9};

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
  crypto_kem_keypair(pk, sk, randomness);
  pk += MLKEM_PUBLICKEYBYTES;
  sk += MLKEM_SECRETKEYBYTES;
  randomness += 2 * GHPC_SYMBYTES;
  lib25519_dh(pk, X25519_BASE, randomness);

  memcpy(sk, randomness, DH_BYTES);
  sk += DH_BYTES;
  memcpy(sk, pk, DH_BYTES);
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
  unsigned char *bufPointer = malloc(GHPC_PRFINPUT);

  bufPointer += 6;

  crypto_kem_enc(ct, bufPointer, pk, coins);

  bufPointer += MLKEM_SSBYTES;
  pk += MLKEM_PUBLICKEYBYTES;
  ct += MLKEM_CIPHERTEXTBYTES;
  coins += DH_BYTES;

  lib25519_dh(ct, X25519_BASE, coins);
  lib25519_dh(bufPointer, pk, coins);
  bufPointer += DH_BYTES;

  memcpy(bufPointer, ct, DH_BYTES);
  bufPointer += DH_BYTES;
  memcpy(bufPointer, pk, DH_BYTES);

  bufPointer -= 102; // go back 132 - 32 bytes

  sha3_256(ss, bufPointer, GHPC_PRFINPUT);
  free(bufPointer);
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
  unsigned char *bufPointer = malloc(GHPC_PRFINPUT);

  bufPointer += 6;

  crypto_kem_dec(bufPointer, ct, sk);
  bufPointer += MLKEM_SSBYTES;
  sk += MLKEM_SECRETKEYBYTES;
  ct += MLKEM_CIPHERTEXTBYTES;

  lib25519_dh(bufPointer, ct, sk);
  bufPointer += DH_BYTES;
  sk += DH_BYTES;

  memcpy(bufPointer, ct, DH_BYTES);
  bufPointer += DH_BYTES;
  memcpy(bufPointer, sk, DH_BYTES);

  bufPointer -= 102; // go back 132 - 32 bytes

  sha3_256(ss, bufPointer, GHPC_PRFINPUT);
  free(bufPointer);
}