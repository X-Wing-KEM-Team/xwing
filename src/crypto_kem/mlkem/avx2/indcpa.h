#ifndef INDCPA_H
#define INDCPA_H

#include <stdint.h>
#include "params.h"
#include "polyvec.h"

#define gen_matrix mlkem_NAMESPACE(gen_matrix)
void gen_matrix(polyvec *a, const uint8_t seed[mlkem_SYMBYTES], int transposed);

#define indcpa_keypair_derand mlkem_NAMESPACE(indcpa_keypair_derand)
void indcpa_keypair_derand(uint8_t pk[mlkem_INDCPA_PUBLICKEYBYTES],
                           uint8_t sk[mlkem_INDCPA_SECRETKEYBYTES],
                           const uint8_t coins[mlkem_SYMBYTES]);

#define indcpa_enc mlkem_NAMESPACE(indcpa_enc)
void indcpa_enc(uint8_t c[mlkem_INDCPA_BYTES],
                const uint8_t m[mlkem_INDCPA_MSGBYTES],
                const uint8_t pk[mlkem_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[mlkem_SYMBYTES]);

#define indcpa_dec mlkem_NAMESPACE(indcpa_dec)
void indcpa_dec(uint8_t m[mlkem_INDCPA_MSGBYTES],
                const uint8_t c[mlkem_INDCPA_BYTES],
                const uint8_t sk[mlkem_INDCPA_SECRETKEYBYTES]);

#endif
