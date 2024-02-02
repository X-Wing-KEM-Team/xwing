#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sodium.h>
#include "xkem.h"
#include "symmetric.h"
#include "kem.h"

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
  unsigned char mlkemPublicKey[MLKEM_PUBLICKEYBYTES];
  unsigned char mlkemSecretKey[MLKEM_SECRETKEYBYTES];

  unsigned char mlkemRandomness[2 * MLKEM_SYMBYTES];
  unsigned char dhSecretKey[DH_BYTES];
  unsigned char dhPublicKey[DH_BYTES];

  int i;
  for (i = 0; i < 3 * XWING_SYMBYTES; i++)
  {
    if (i >= 64)
    {
      dhSecretKey[i - 64] = randomness[i];
    }
    else
    {
      mlkemRandomness[i] = randomness[i];
    }
  }

  unsigned char *mlkemRandomnessPointer = mlkemRandomness;
  unsigned char *mlkemPublicKeyPointer = mlkemPublicKey;
  unsigned char *mlkemSecretKeyPointer = mlkemSecretKey;

  unsigned char *dhPublicKeyPointer = dhPublicKey;
  unsigned char *dhSecretKeyPointer = dhSecretKey;

  crypto_kem_keypair(mlkemPublicKeyPointer, mlkemSecretKeyPointer, mlkemRandomnessPointer);
  crypto_scalarmult_base(dhPublicKeyPointer, dhSecretKeyPointer);

  for (i = 0; i < MLKEM_PUBLICKEYBYTES; i++)
  {
    pk[i] = mlkemPublicKey[i];
  }

  for (i = 0; i < MLKEM_SECRETKEYBYTES; i++)
  {
    sk[i] = mlkemSecretKey[i];
  }

  for (i = 0; i < DH_BYTES; i++)
  {
    pk[MLKEM_PUBLICKEYBYTES + i] = dhPublicKey[i];
    sk[MLKEM_SECRETKEYBYTES + i] = dhSecretKey[i];
    sk[MLKEM_SECRETKEYBYTES + DH_BYTES + i] = dhPublicKey[i];
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
  unsigned char mlkemPublicKey[MLKEM_PUBLICKEYBYTES];
  unsigned char mlkemSharedSecret[MLKEM_SSBYTES];
  unsigned char mlkemCiphertext[MLKEM_CIPHERTEXTBYTES];
  unsigned char mlkemCoins[MLKEM_SYMBYTES];

  unsigned char dhPublicKey[DH_BYTES];
  unsigned char dhSharedSecret[DH_BYTES];
  unsigned char dhCiphertext[DH_BYTES];
  unsigned char dhEphermeralKey[DH_BYTES];

  int i;
  for (i = 0; i < MLKEM_PUBLICKEYBYTES; i++)
  {
    mlkemPublicKey[i] = pk[i];
  }

  for (i = 0; i < DH_BYTES; i++)
  {
    dhPublicKey[i] = pk[MLKEM_PUBLICKEYBYTES + i];
    dhEphermeralKey[i] = coins[i + DH_BYTES];
    mlkemCoins[i] = coins[i];
  }

  unsigned char *mlkemPublicKeyPointer = mlkemPublicKey;
  unsigned char *mlkemSharedSecretPointer = mlkemSharedSecret;
  unsigned char *mlkemCiphertextPointer = mlkemCiphertext;
  unsigned char *mlkemCoinsPointer = mlkemCoins;

  crypto_kem_enc(mlkemCiphertextPointer, mlkemSharedSecretPointer, mlkemPublicKeyPointer, mlkemCoinsPointer);

  unsigned char *dhPublicKeyPointer = dhPublicKey;
  unsigned char *dhSharedSecretPointer = dhSharedSecret;
  unsigned char *dhCiphertextPointer = dhCiphertext;
  unsigned char *dhEphermeralKeyPointer = dhEphermeralKey;

  crypto_scalarmult_base(dhCiphertextPointer, dhEphermeralKeyPointer);
  crypto_scalarmult(dhSharedSecretPointer, dhEphermeralKeyPointer, dhPublicKeyPointer);

  for (i = 0; i < MLKEM_CIPHERTEXTBYTES; i++)
  {
    ct[i] = mlkemCiphertextPointer[i];
  }

  for (i = 0; i < DH_BYTES; i++)
  {
    ct[i + MLKEM_CIPHERTEXTBYTES] = dhCiphertext[i];
  }

  unsigned char xwingInputToHash[XWING_PRFINPUT];

  for (i = 0; i < 6; i++)
  {
    xwingInputToHash[i] = XWING_LABEL[i];
  }

  for (i = 0; i < XWING_SYMBYTES; i++)
  {
    xwingInputToHash[i + 6] = mlkemSharedSecretPointer[i];
    xwingInputToHash[i + 6 + XWING_SYMBYTES] = dhSharedSecretPointer[i];
    xwingInputToHash[i + 6 + 2 * XWING_SYMBYTES] = dhCiphertextPointer[i];
    xwingInputToHash[i + 6 + 3 * XWING_SYMBYTES] = dhPublicKeyPointer[i];
  }

  unsigned char *xwingInputToHashPointer = xwingInputToHash;

  sha3_256(ss, xwingInputToHashPointer, XWING_PRFINPUT);
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
  unsigned char mlkemSecretKey[MLKEM_SECRETKEYBYTES];
  unsigned char mlkemSharedSecret[MLKEM_SSBYTES];
  unsigned char mlkemCiphertext[MLKEM_CIPHERTEXTBYTES];

  unsigned char dhSecretKey[DH_BYTES];
  unsigned char dhPublicKey[DH_BYTES];
  unsigned char dhSharedSecret[DH_BYTES];
  unsigned char dhCiphertext[DH_BYTES];

  int i;
  for (i = 0; i < MLKEM_CIPHERTEXTBYTES; i++)
  {
    mlkemCiphertext[i] = ct[i];
  }

  for (i = 0; i < DH_BYTES; i++)
  {
    dhCiphertext[i] = ct[i + MLKEM_CIPHERTEXTBYTES];
  }

  for (i = 0; i < MLKEM_SECRETKEYBYTES; i++)
  {
    mlkemSecretKey[i] = sk[i];
  }

  for (i = 0; i < DH_BYTES; i++)
  {
    dhSecretKey[i] = sk[i + MLKEM_SECRETKEYBYTES];
    dhPublicKey[i] = sk[i + DH_BYTES + MLKEM_SECRETKEYBYTES];
  }

  unsigned char *mlkemSecretKeyPointer = mlkemSecretKey;
  unsigned char *mlkemSharedSecretPointer = mlkemSharedSecret;
  unsigned char *mlkemCiphertextPointer = mlkemCiphertext;

  unsigned char *dhSecretKeyPointer = dhSecretKey;
  unsigned char *dhSharedSecretPointer = dhSharedSecret;
  unsigned char *dhCiphertextPointer = dhCiphertext;
  unsigned char *dhPublicKeyPointer = dhPublicKey;

  crypto_kem_dec(mlkemSharedSecretPointer, mlkemCiphertextPointer, mlkemSecretKeyPointer);
  crypto_scalarmult(dhSharedSecretPointer, dhSecretKeyPointer, dhCiphertextPointer);

  unsigned char xwingInputToHash[XWING_PRFINPUT];

  for (i = 0; i < 6; i++)
  {
    xwingInputToHash[i] = XWING_LABEL[i];
  }

  for (i = 0; i < XWING_SYMBYTES; i++)
  {
    xwingInputToHash[i + 6] = mlkemSharedSecretPointer[i];
    xwingInputToHash[i + 6 + XWING_SYMBYTES] = dhSharedSecretPointer[i];
    xwingInputToHash[i + 6 + 2 * XWING_SYMBYTES] = dhCiphertextPointer[i];
    xwingInputToHash[i + 6 + 3 * XWING_SYMBYTES] = dhPublicKeyPointer[i];
  }

  unsigned char *xwingInputToHashPointer = xwingInputToHash;

  sha3_256(ss, xwingInputToHashPointer, XWING_PRFINPUT);
}
