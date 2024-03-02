#ifndef NTT_H
#define NTT_H

#include <stdint.h>
#include <immintrin.h>

void ntt_avx(__m256i *r, const __m256i *qdata);
void invntt_avx(__m256i *r, const __m256i *qdata);

void nttpack_avx(__m256i *r, const __m256i *qdata);
void nttunpack_avx(__m256i *r, const __m256i *qdata);

void basemul_avx(__m256i *r,
                 const __m256i *a,
                 const __m256i *b,
                 const __m256i *qdata);

void ntttobytes_avx(uint8_t *r, const __m256i *a, const __m256i *qdata);
void nttfrombytes_avx(__m256i *r, const uint8_t *a, const __m256i *qdata);

#endif
