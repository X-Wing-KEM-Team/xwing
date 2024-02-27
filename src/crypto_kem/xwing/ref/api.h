#ifndef API_H
#define API_H

#include <stdint.h>

#define xwing_SECRETKEYBYTES 2464
#define xwing_PUBLICKEYBYTES 1216
#define xwing_CIPHERTEXTBYTES 1120
#define xwing_KEYPAIRCOINBYTES 96
#define xwing_ENCCOINBYTES 64
#define xwing_BYTES 32

#define xwing_ref_SECRETKEYBYTES xwing_SECRETKEYBYTES
#define xwing_ref_PUBLICKEYBYTES xwing_PUBLICKEYBYTES
#define xwing_ref_CIPHERTEXTBYTES xwing_CIPHERTEXTBYTES
#define xwing_ref_KEYPAIRCOINBYTES xwing_KEYPAIRCOINBYTES
#define xwing_ref_ENCCOINBYTES xwing_ENCCOINBYTES
#define xwing_ref_BYTES xwing_BYTES

int xwing_ref_keypair_derand(unsigned char *pk, unsigned char *sk, const unsigned char *coins);
int xwing_ref_keypair(unsigned char *pk, unsigned char *sk);
int xwing_ref_enc_derand(unsigned char *ct, unsigned char *ss, const unsigned char *pk, const unsigned char *coins);
int xwing_ref_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int xwing_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif