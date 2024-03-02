#ifndef PARAMS_HM
#define PARAMS_HM

// #define MLKEM_90S	/* Uncomment this if you want the 90S variant */

#define MLKEM_NAMESPACE(s) pqcrystals_MLKEM768_avx2_##s

#define MLKEM_K 3
#define MLKEM_N 256
#define MLKEM_Q 3329

#define MLKEM_SYMBYTES 32 /* size in bytes of hashes, and seeds */
#define MLKEM_SSBYTES 32  /* size in bytes of shared key */

#define MLKEM_ETA1 2
#define MLKEM_ETA2 2

#define MLKEM_ETA 2
#define MLKEM_POLYBYTES 384
#define MLKEM_POLYVECBYTES 1152
#define MLKEM_POLYCOMPRESSEDBYTES 128
#define MLKEM_POLYVECCOMPRESSEDBYTES 960
#define MLKEM_INDCPA_MSGBYTES 32
#define MLKEM_INDCPA_PUBLICKEYBYTES 1184
#define MLKEM_INDCPA_SECRETKEYBYTES 1152
#define MLKEM_INDCPA_BYTES 1088
#define MLKEM_PUBLICKEYBYTES 1184
#define MLKEM_SECRETKEYBYTES 2400
#define MLKEM_CIPHERTEXTBYTES 1088
#endif
