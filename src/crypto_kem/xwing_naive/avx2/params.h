#ifndef PARAMS_X
#define PARAMS_X

#define MLKEM_K 3
#define MLKEM_N 256
#define MLKEM_Q 3329
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
#define MLKEM_SYMBYTES 32
#define MLKEM_SSBYTES 32

#define DH_BYTES 32

#define XWING_SYMBYTES 32
#define XWING_SSBYTES 32
#define XWING_PUBLICKEYBYTES 1216
#define XWING_SECRETKEYBYTES 2464
#define XWING_CIPHERTEXTBYTES 1120
#define XWING_PRFINPUT 134 + MLKEM_CIPHERTEXTBYTES
#define XWING_LABEL "\\.//^\\"

#endif
