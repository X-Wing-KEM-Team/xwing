#ifndef SYMMETRIC_H
#define SYMMETRIC_H

#include <stddef.h>
#include <stdint.h>
#include "params.h"

#include "fips202.h"
#include "fips202x4.h"

typedef keccak_state xof_state;

void mlkem_shake128_absorb(keccak_state *s,
                           const uint8_t seed[MLKEM_SYMBYTES],
                           uint8_t x,
                           uint8_t y);

void mlkem_shake256_prf(uint8_t *out, size_t outlen, const uint8_t key[MLKEM_SYMBYTES], uint8_t nonce);

void mlkem_shake256_rkprf(uint8_t out[MLKEM_SSBYTES], const uint8_t key[MLKEM_SYMBYTES], const uint8_t input[MLKEM_CIPHERTEXTBYTES]);

#define XOF_BLOCKBYTES SHAKE128_RATE

#define hash_h(OUT, IN, INBYTES) sha3_256(OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) sha3_512(OUT, IN, INBYTES)
#define xof_absorb(STATE, SEED, X, Y) mlkem_shake128_absorb(STATE, SEED, X, Y)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) shake128_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define prf(OUT, OUTBYTES, KEY, NONCE) mlkem_shake256_prf(OUT, OUTBYTES, KEY, NONCE)
#define rkprf(OUT, KEY, INPUT) mlkem_shake256_rkprf(OUT, KEY, INPUT)

#endif /* SYMMETRIC_H */
