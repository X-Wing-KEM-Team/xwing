#ifndef REDUCE_H
#define REDUCE_H

#include "params.h"
#include <immintrin.h>

void reduce_avx(__m256i *r, const __m256i *qdata);
void tomont_avx(__m256i *r, const __m256i *qdata);

#endif
