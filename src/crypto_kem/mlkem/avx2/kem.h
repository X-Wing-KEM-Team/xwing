#ifndef KEM_HK
#define KEM_HK

#include <stdint.h>
#include "params.h"

#define crypto_kem_keypair_derand mlkem_NAMESPACE(keypair_derand)
int crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);

#define crypto_kem_keypair mlkem_NAMESPACE(keypair)
int crypto_kem_keypair(uint8_t *pk, uint8_t *sk);

#define crypto_kem_enc_derand mlkem_NAMESPACE(enc_derand)
int crypto_kem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);

#define crypto_kem_enc mlkem_NAMESPACE(enc)
int crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);

#define crypto_kem_dec mlkem_NAMESPACE(dec)
int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif
