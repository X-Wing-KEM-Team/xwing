#ifndef API_H
#define API_H

#include <stdint.h>

#define xwing_SECRETKEYBYTES 2464
#define xwing_PUBLICKEYBYTES 1216
#define xwing_CIPHERTEXTBYTES 1120
#define xwing_KEYPAIRCOINBYTES 96
#define xwing_ENCCOINBYTES 64
#define xwing_BYTES 32

#define xwing_avx2_SECRETKEYBYTES xwing_SECRETKEYBYTES
#define xwing_avx2_PUBLICKEYBYTES xwing_PUBLICKEYBYTES
#define xwing_avx2_CIPHERTEXTBYTES xwing_CIPHERTEXTBYTES
#define xwing_avx2_KEYPAIRCOINBYTES xwing_KEYPAIRCOINBYTES
#define xwing_avx2_ENCCOINBYTES xwing_ENCCOINBYTES
#define xwing_avx2_BYTES xwing_BYTES

int xwing_avx2_keypair_derand(unsigned char *pk, unsigned char *sk, const unsigned char *coins);
int xwing_avx2_keypair(unsigned char *pk, unsigned char *sk);
int xwing_avx2_enc_derand(unsigned char *ct, unsigned char *ss, const unsigned char *pk, const unsigned char *coins);
int xwing_avx2_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int xwing_avx2_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif
