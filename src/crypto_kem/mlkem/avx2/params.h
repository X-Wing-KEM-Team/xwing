#ifndef PARAMS_H
#define PARAMS_H

#ifndef mlkem_K
#define mlkem_K 3	/* Change this for different security strengths */
#endif

//#define mlkem_90S	/* Uncomment this if you want the 90S variant */

/* Don't change parameters below this line */
#if   (mlkem_K == 2)
#ifdef mlkem_90S
#define mlkem_NAMESPACE(s) pqcrystals_mlkem512_90s_avx2_##s
#else
#define mlkem_NAMESPACE(s) pqcrystals_mlkem512_avx2_##s
#endif
#elif (mlkem_K == 3)
#ifdef mlkem_90S
#define mlkem_NAMESPACE(s) pqcrystals_mlkem768_90s_avx2_##s
#else
#define mlkem_NAMESPACE(s) pqcrystals_mlkem768_avx2_##s
#endif
#elif (mlkem_K == 4)
#ifdef mlkem_90S
#define mlkem_NAMESPACE(s) pqcrystals_mlkem1024_90s_avx2_##s
#else
#define mlkem_NAMESPACE(s) pqcrystals_mlkem1024_avx2_##s
#endif
#else
#error "mlkem_K must be in {2,3,4}"
#endif

#define mlkem_N 256
#define mlkem_Q 3329

#define mlkem_SYMBYTES 32   /* size in bytes of hashes, and seeds */
#define mlkem_SSBYTES  32   /* size in bytes of shared key */

#define mlkem_POLYBYTES		384
#define mlkem_POLYVECBYTES	(mlkem_K * mlkem_POLYBYTES)

#if mlkem_K == 2
#define mlkem_ETA1 3
#define mlkem_POLYCOMPRESSEDBYTES    128
#define mlkem_POLYVECCOMPRESSEDBYTES (mlkem_K * 320)
#elif mlkem_K == 3
#define mlkem_ETA1 2
#define mlkem_POLYCOMPRESSEDBYTES    128
#define mlkem_POLYVECCOMPRESSEDBYTES (mlkem_K * 320)
#elif mlkem_K == 4
#define mlkem_ETA1 2
#define mlkem_POLYCOMPRESSEDBYTES    160
#define mlkem_POLYVECCOMPRESSEDBYTES (mlkem_K * 352)
#endif

#define mlkem_ETA2 2

#define mlkem_INDCPA_MSGBYTES       (mlkem_SYMBYTES)
#define mlkem_INDCPA_PUBLICKEYBYTES (mlkem_POLYVECBYTES + mlkem_SYMBYTES)
#define mlkem_INDCPA_SECRETKEYBYTES (mlkem_POLYVECBYTES)
#define mlkem_INDCPA_BYTES          (mlkem_POLYVECCOMPRESSEDBYTES + mlkem_POLYCOMPRESSEDBYTES)

#define mlkem_PUBLICKEYBYTES  (mlkem_INDCPA_PUBLICKEYBYTES)
/* 32 bytes of additional space to save H(pk) */
#define mlkem_SECRETKEYBYTES  (mlkem_INDCPA_SECRETKEYBYTES + mlkem_INDCPA_PUBLICKEYBYTES + 2*mlkem_SYMBYTES)
#define mlkem_CIPHERTEXTBYTES (mlkem_INDCPA_BYTES)

#endif
