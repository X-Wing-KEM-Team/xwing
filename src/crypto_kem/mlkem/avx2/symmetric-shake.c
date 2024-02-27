#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "params.h"
#include "symmetric.h"
#include "fips202.h"

/*************************************************
* Name:        mlkem_shake128_absorb
*
* Description: Absorb step of the SHAKE128 specialized for the mlkem context.
*
* Arguments:   - keccak_state *state: pointer to (uninitialized) output Keccak state
*              - const uint8_t *seed: pointer to mlkem_SYMBYTES input to be absorbed into state
*              - uint8_t i: additional byte of input
*              - uint8_t j: additional byte of input
**************************************************/
void mlkem_shake128_absorb(keccak_state *state,
                           const uint8_t seed[mlkem_SYMBYTES],
                           uint8_t x,
                           uint8_t y)
{
  uint8_t extseed[mlkem_SYMBYTES+2];

  memcpy(extseed, seed, mlkem_SYMBYTES);
  extseed[mlkem_SYMBYTES+0] = x;
  extseed[mlkem_SYMBYTES+1] = y;

  shake128_absorb_once(state, extseed, sizeof(extseed));
}

/*************************************************
* Name:        mlkem_shake256_prf
*
* Description: Usage of SHAKE256 as a PRF, concatenates secret and public input
*              and then generates outlen bytes of SHAKE256 output
*
* Arguments:   - uint8_t *out: pointer to output
*              - size_t outlen: number of requested output bytes
*              - const uint8_t *key: pointer to the key (of length mlkem_SYMBYTES)
*              - uint8_t nonce: single-byte nonce (public PRF input)
**************************************************/
void mlkem_shake256_prf(uint8_t *out, size_t outlen, const uint8_t key[mlkem_SYMBYTES], uint8_t nonce)
{
  uint8_t extkey[mlkem_SYMBYTES+1];

  memcpy(extkey, key, mlkem_SYMBYTES);
  extkey[mlkem_SYMBYTES] = nonce;

  shake256(out, outlen, extkey, sizeof(extkey));
}

/*************************************************
* Name:        mlkem_shake256_prf
*
* Description: Usage of SHAKE256 as a PRF, concatenates secret and public input
*              and then generates outlen bytes of SHAKE256 output
*
* Arguments:   - uint8_t *out: pointer to output
*              - size_t outlen: number of requested output bytes
*              - const uint8_t *key: pointer to the key (of length mlkem_SYMBYTES)
*              - uint8_t nonce: single-byte nonce (public PRF input)
**************************************************/
void mlkem_shake256_rkprf(uint8_t out[mlkem_SSBYTES], const uint8_t key[mlkem_SYMBYTES], const uint8_t input[mlkem_CIPHERTEXTBYTES])
{
  keccak_state s;

  shake256_init(&s);
  shake256_absorb(&s, key, mlkem_SYMBYTES);
  shake256_absorb(&s, input, mlkem_CIPHERTEXTBYTES);
  shake256_finalize(&s);
  shake256_squeeze(out, mlkem_SSBYTES, &s);
}
