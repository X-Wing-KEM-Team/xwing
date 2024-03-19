#ifndef KEM_HR
#define KEM_HR

#include <stdint.h>
#include "params.h"

#define CRYPTO_SECRETKEYBYTES  xwing_naive_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES  xwing_naive_PUBLICKEYBYTES
#define CRYPTO_CIPHERTEXTBYTES xwing_naive_CIPHERTEXTBYTES
#define CRYPTO_BYTES           xwing_naive_SSBYTES
#define CRYPTO_ALGNAME         "xwing_naive_naive"

#define crypto_xkem_keypair_derand xwing_naive_NAMESPACE(keypair_derand)
int crypto_xkem_keypair_derand(unsigned char *pk, unsigned char *sk, const unsigned char *coins);

#define crypto_xkem_keypair xwing_naive_NAMESPACE(keypair)
int crypto_xkem_keypair(unsigned char *pk, unsigned char *sk);

#define crypto_xkem_enc_derand xwing_naive_NAMESPACE(enc_derand)
int crypto_xkem_enc_derand(unsigned char *ct, unsigned char *ss, const unsigned char *pk, const unsigned char *coins);

#define crypto_xkem_enc xwing_naive_NAMESPACE(enc)
int crypto_xkem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);

#define crypto_xkem_dec xwing_naive_NAMESPACE(dec)
int crypto_xkem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif
