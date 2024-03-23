#ifndef ALIGN_H
#define ALIGN_H

#include <stdint.h>
#include <immintrin.h>


#ifdef ALIGN
#undef ALIGN
#endif

#if defined(__GNUC__)
#define ALIGN(x) __attribute__ ((aligned(x)))
#elif defined(_MSC_VER)
#define ALIGN(x) __declspec(align(x))
#elif defined(__ARMCC_VERSION)
#define ALIGN(x) __align(x)
#else
#define ALIGN(x)
#endif

#define ALIGNED_UINT8(N)        \
    union {                     \
        uint8_t coeffs[N];      \
        __m256i vec[(N+31)/32]; \
    }

#define ALIGNED_INT16(N)        \
    union {                     \
        int16_t coeffs[N];      \
        __m256i vec[(N+15)/16]; \
    }

#endif
