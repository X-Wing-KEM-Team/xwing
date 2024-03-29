# -*- Makefile -*-

-include ../../../../Makefile.conf

CC     ?= /usr/bin/cc
CFLAGS := -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls -Wshadow -Wpointer-arith -mavx2 -mbmi2 -mpopcnt -march=native -mtune=native -O3 -fomit-frame-pointer  -l25519 -lsodium
OS     := $(shell uname -s)

default: test

test: test/test_gkem_functionality test/test_speed

MLKEMHEADERS = ../../mlkem/avx2/params.h ../../mlkem/avx2/align.h ../../mlkem/avx2/kem.h ../../mlkem/avx2/indcpa.h ../../mlkem/avx2/polyvec.h ../../mlkem/avx2/poly.h ../../mlkem/avx2/reduce.h fq.inc shuffle.inc ../../mlkem/avx2/ntt.h ../../mlkem/avx2/consts.h ../../mlkem/avx2/rejsample.h ../../mlkem/avx2/cbd.h ../../mlkem/avx2/verify.h ../../mlkem/avx2/symmetric.h ../../mlkem/avx2/randombytes.h
DHKEMHEADERS = ../../dhkem/ref/params.h ../../dhkem/ref/kem.h ../../dhkem/ref/derivekeypair.h ../../dhkem/ref/extractexpand.h
HEADERS = $(MLKEMHEADERS) $(DHKEMHEADERS) gkem.h params.h
TESTHEADERS = $(HEADERS) test/cpucycles.h test/speed_print.h

MLKEMSOURCES = ../../mlkem/avx2/kem.c ../../mlkem/avx2/indcpa.c ../../mlkem/avx2/polyvec.c ../../mlkem/avx2/poly.c fq.S shuffle.S ntt.S invntt.S basemul.S ../../mlkem/avx2/consts.c ../../mlkem/avx2/randombytes.c ../../mlkem/avx2/rejsample.c ../../mlkem/avx2/cbd.c ../../mlkem/avx2/verify.c ../../mlkem/avx2/fips202.c ../../mlkem/avx2/fips202x4.c ../../mlkem/avx2/symmetric-shake.c ../../mlkem/avx2/keccak4x/KeccakP-1600-times4-SIMD256.o
DHKEMSOURCES = ../../dhkem/ref/kem.c ../../dhkem/ref/derivekeypair.c ../../dhkem/ref/extractexpand.c
SOURCES =  $(MLKEMSOURCES) $(DHKEMSOURCES) gkem.c
TESTSOURCES = $(SOURCES) test/cpucycles.c test/speed_print.c 

test/test_gkem_functionality: $(TESTSOURCES) $(TESTHEADERS) test/test_gkem_functionality.c
	$(CC) $(CFLAGS) -Dmlkem_K=3 $(TESTSOURCES) test/test_gkem_functionality.c -o $@

test/test_speed: $(TESTSOURCES) $(TESTHEADERS) test/test_speed.c
	$(CC) $(CFLAGS) -Dmlkem_K=3 $(TESTSOURCES) test/test_speed.c -o $@

.PHONY: clean

clean:
	-rm -f test/test_gkem_functionality
	-rm -f test/test_speed
	-rm -f *.s
ifeq ($(OS),Darwin)
	-rm -rf test/*.dSYM
endif
