#ifndef CBD_H
#define CBD_H

#include <stdint.h>
#include <immintrin.h>
#include "params.h"
#include "poly.h"

#define poly_cbd_eta1 mlkem_NAMESPACE(poly_cbd_eta1)
void poly_cbd_eta1(poly *r, const __m256i buf[mlkem_ETA1*mlkem_N/128+1]);

#define poly_cbd_eta2 mlkem_NAMESPACE(poly_cbd_eta2)
void poly_cbd_eta2(poly *r, const __m256i buf[mlkem_ETA2*mlkem_N/128]);

#endif
