#ifndef CBD_H
#define CBD_H

#include <stdint.h>
#include <immintrin.h>
#include "params.h"
#include "poly.h"

void poly_cbd_eta1(poly *r, const __m256i buf[MLKEM_ETA1*MLKEM_N/128+1]);

void poly_cbd_eta2(poly *r, const __m256i buf[MLKEM_ETA2*MLKEM_N/128]);

#endif
