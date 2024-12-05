#include <stdio.h>
#include <string.h>
#include <lib25519.h>
#include "xkem.h"
#include "params.h"
#include "../../mlkem/ref/kem.h"
#include "../../mlkem/ref/symmetric.h"
#include "../../mlkem/ref/randombytes.h"

/*************************************************
 * Name:        crypto_xkem_keypair_derand
 *
 * Description: Generates public and private key for the CCA-secure
 *              X-Wing key encapsulation mechanism
 *
 * Arguments:   - unsigned char *pk:               pointer to output public key (of length XWING_PUBLICKEYBYTES bytes)
 *              - unsigned char *sk:               pointer to output private key (of length XWING_SECRETKEYBYTES bytes)
 *              - const unsigned char *randomness: pointer to input random coins used as seed (of length XWING_SYMBYTES bytes)
 *                                                 to deterministically generate all randomness
 **************************************************/
int crypto_xkem_keypair_derand(unsigned char *pk,
                                unsigned char *sk,
                                const unsigned char *randomness)
{
  unsigned char expanded[3 * XWING_SYMBYTES];
  unsigned char *expandedPointer = expanded;
  unsigned char skm[KYBER_SECRETKEYBYTES]; // not used in the end as sk = randomness
  unsigned char *skmPointer = skm;  
  shake256(expandedPointer, 3 * XWING_SYMBYTES, randomness, XWING_SYMBYTES);    
  crypto_kem_keypair_derand(pk, skmPointer, expandedPointer);
  pk += KYBER_PUBLICKEYBYTES;
  expandedPointer += 2 * XWING_SYMBYTES;
  lib25519_nG_montgomery25519(pk, expandedPointer);  
  memcpy(sk, randomness, XWING_SYMBYTES);  
  
  return 0;
}

/*************************************************
 * Name:        crypto_xkem_keypair
 *
 * Description: Generates public and private key for the CCA-secure
 *              X-Wing key encapsulation mechanism
 *
 * Arguments:   - unsigned char *pk:               pointer to output public key (of length XWING_PUBLICKEYBYTES bytes)
 *              - unsigned char *sk:               pointer to output private key (of length XWING_SECRETKEYBYTES bytes)
 **************************************************/
int crypto_xkem_keypair(unsigned char *pk,
                         unsigned char *sk)
{
  unsigned char buf[XWING_SYMBYTES];
  randombytes(buf, XWING_SYMBYTES);
  return crypto_xkem_keypair_derand(pk, sk, buf);
}

/*************************************************
 * Name:        crypto_xkem_enc_derand
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
int crypto_xkem_enc_derand(unsigned char *ct,
                            unsigned char *ss,
                            const unsigned char *pk,
                            const unsigned char *coins)
{
  unsigned char buffer[XWING_PRFINPUT];
  unsigned char *bufferPointer = buffer;
  crypto_kem_enc_derand(ct, bufferPointer, pk, coins);
  
  pk += KYBER_PUBLICKEYBYTES;
  ct += KYBER_CIPHERTEXTBYTES;
  coins += XWING_SYMBYTES;
  bufferPointer += XWING_SYMBYTES;
  lib25519_dh(bufferPointer, pk, coins);
  bufferPointer += XWING_SYMBYTES;
  lib25519_nG_montgomery25519(ct, coins);
  memcpy(bufferPointer, ct, XWING_SYMBYTES);
  bufferPointer += XWING_SYMBYTES;
  memcpy(bufferPointer, pk, XWING_SYMBYTES);
  bufferPointer += XWING_SYMBYTES;
  memcpy(bufferPointer, XWING_LABEL, 6);
  sha3_256(ss, buffer, XWING_PRFINPUT);
  return 0;
}

/*************************************************
 * Name:        crypto_xkem_enc
 *
 * Description: Generates cipher text and shared
 *              secret for given public key
 *
 * Arguments:   - unsigned char *ct:          pointer to output ciphertext (of length XWING_CIPHERTEXTBYTES bytes)
 *              - unsigned char *ss:          pointer to output decrypted message (of length XWING_SSBYTES bytes)
 **************************************************/
int crypto_xkem_enc(unsigned char *ct,
                     unsigned char *ss,
                     const unsigned char *pk)
{
  unsigned char buf[2 * XWING_SYMBYTES];
  randombytes(buf, 2 * XWING_SYMBYTES);

  return crypto_xkem_enc_derand(ct, ss, pk, buf);
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
int crypto_xkem_dec(uint8_t *ss,
                     const uint8_t *ct,
                     const uint8_t *sk)
{
  unsigned char buffer[XWING_PRFINPUT];
  unsigned char *bufferPointer = buffer;  
  unsigned char expanded[3 * XWING_SYMBYTES];
  unsigned char *expandedPointer = expanded;
  unsigned char skm[KYBER_SECRETKEYBYTES]; // not used in the end as sk = randomness
  unsigned char *skmPointer = skm;  
  unsigned char pkm[KYBER_PUBLICKEYBYTES]; // not used in the end as sk = randomness
  unsigned char *pkmPointer = pkm;  
  
  shake256(expandedPointer, 3 * XWING_SYMBYTES, sk, XWING_SYMBYTES);
  crypto_kem_keypair_derand(pkmPointer, skmPointer, expandedPointer);    
  crypto_kem_dec(bufferPointer, ct, skmPointer);  
  expandedPointer += 2*XWING_SYMBYTES;
  ct += KYBER_CIPHERTEXTBYTES;
  bufferPointer += XWING_SYMBYTES;
  lib25519_dh(bufferPointer, ct, expandedPointer);
  bufferPointer += XWING_SYMBYTES;  
  memcpy(bufferPointer, ct, DH_BYTES);
  bufferPointer += XWING_SYMBYTES;
  lib25519_nG_montgomery25519(bufferPointer, expandedPointer);
  bufferPointer += XWING_SYMBYTES;
  memcpy(bufferPointer, XWING_LABEL, 6);
  sha3_256(ss, buffer, XWING_PRFINPUT);
  return 0;
}
