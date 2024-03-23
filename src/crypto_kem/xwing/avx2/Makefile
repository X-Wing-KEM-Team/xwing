# -*- Makefile -*-

-include ../../../../Makefile.conf

CC     ?= /usr/bin/cc
CFLAGS := -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls -Wshadow -Wpointer-arith -mavx2 -mbmi2 -mpopcnt -march=native -mtune=native -O3 -fomit-frame-pointer  -l25519
OS     := $(shell uname -s)

all: test shared

default: test

test: test/test_xkem_functionality test/test_speed

shared: libxwing_avx2.so

MLKEMHEADERS = ../../mlkem/avx2/params.h ../../mlkem/avx2/align.h ../../mlkem/avx2/kem.h ../../mlkem/avx2/indcpa.h ../../mlkem/avx2/polyvec.h ../../mlkem/avx2/poly.h ../../mlkem/avx2/reduce.h fq.inc shuffle.inc ../../mlkem/avx2/ntt.h ../../mlkem/avx2/consts.h ../../mlkem/avx2/rejsample.h ../../mlkem/avx2/cbd.h ../../mlkem/avx2/verify.h ../../mlkem/avx2/symmetric.h ../../mlkem/avx2/randombytes.h ../../mlkem/avx2/fips202.h ../../mlkem/avx2/fips202x4.h ../../mlkem/avx2/keccak/KeccakP-1600-AVX2.h  ../../mlkem/avx2/keccak/KeccakP-1600-SnP.h  ../../mlkem/avx2/keccak/KeccakSponge-common.h ../../mlkem/avx2/keccak/KeccakSpongeWidth1600.h ../../mlkem/avx2/keccak/namespace.h 
HEADERS = $(MLKEMHEADERS) xkem.h params.h
TESTHEADERS = $(HEADERS) test/test_vectors.h test/cpucycles.h test/speed_print.h

MLKEMSOURCES =    ../../mlkem/avx2/kem.c ../../mlkem/avx2/indcpa.c  ../../mlkem/avx2/polyvec.c ../../mlkem/avx2/poly.c fq.S shuffle.S ntt.S invntt.S basemul.S ../../mlkem/avx2/consts.c ../../mlkem/avx2/randombytes.c ../../mlkem/avx2/rejsample.c ../../mlkem/avx2/cbd.c ../../mlkem/avx2/verify.c ../../mlkem/avx2/fips202.c ../../mlkem/avx2/fips202x4.c ../../mlkem/avx2/symmetric-shake.c ../../mlkem/avx2/keccak4x/KeccakP-1600-times4-SIMD256.o ../../mlkem/avx2/keccak/KeccakP-1600-AVX2.c  ../../mlkem/avx2/keccak/KeccakSpongeWidth1600.c   
SOURCES =  $(MLKEMSOURCES) xkem.c
TESTSOURCES = $(SOURCES) test/cpucycles.c test/speed_print.c 

test/test_xkem_functionality: $(TESTSOURCES) $(TESTHEADERS) test/test_xkem_functionality.c
	$(CC) $(CFLAGS) -DMLKEM_K=3 $(TESTSOURCES) test/test_xkem_functionality.c -o $@

test/test_speed: $(TESTSOURCES) $(TESTHEADERS) test/test_speed.c
	$(CC) $(CFLAGS) -DMLKEM_K=3 $(TESTSOURCES) test/test_speed.c -o $@

libxwing_avx2.so: $(SOURCES) $(HEADERS)
	$(CC) -shared -fpic $(CFLAGS) -DMLKEM_K=3 $(SOURCES) -o libxwing_avx2.so

.PHONY: clean

clean:
	-rm -f test/test_xkem_functionality
	-rm -f test/test_speed
	-rm -f *.s
	-rm -f *.so
ifeq ($(OS),Darwin)
	-rm -rf test/*.dSYM
endif
