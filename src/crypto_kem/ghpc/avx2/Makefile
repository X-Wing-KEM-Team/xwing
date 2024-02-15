# -*- Makefile -*-

-include ../../../../Makefile.conf

CC     ?= /usr/bin/cc
CFLAGS := -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls -Wshadow -Wpointer-arith -mavx2 -mbmi2 -mpopcnt -march=native -mtune=native -O3 -fomit-frame-pointer -z noexecstack -l25519 -lsodium
OS     := $(shell uname -s)

default: test

test: test/test_gkem_functionality

HEADERS = gkem.h  ../../kyber/avx2/params.h ../../kyber/avx2/align.h ../../kyber/avx2/kem.h ../../kyber/avx2/indcpa.h ../../kyber/avx2/polyvec.h ../../kyber/avx2/poly.h ../../kyber/avx2/reduce.h fq.inc shuffle.inc ../../kyber/avx2/ntt.h ../../kyber/avx2/consts.h ../../kyber/avx2/rejsample.h ../../kyber/avx2/cbd.h ../../kyber/avx2/verify.h ../../kyber/avx2/symmetric.h ../../kyber/avx2/randombytes.h ../../kyber/avx2/fips202.h ../../kyber/avx2/fips202x4.h ../../dhkem/ref/kem.h ../../dhkem/ref/extractexpand.h ../../dhkem/ref/derivekeypair.h ../../dhkem/ref/params.h

SOURCES =  gkem.c ../../kyber/avx2/kem.c ../../kyber/avx2/indcpa.c ../../kyber/avx2/polyvec.c ../../kyber/avx2/poly.c fq.S shuffle.S ntt.S invntt.S basemul.S ../../kyber/avx2/consts.c ../../kyber/avx2/rejsample.c ../../kyber/avx2/cbd.c ../../kyber/avx2/verify.c ../../kyber/avx2/fips202.c ../../kyber/avx2/fips202x4.c ../../kyber/avx2/symmetric-shake.c ../../kyber/avx2/keccak4x/KeccakP-1600-times4-SIMD256.o ../../dhkem/ref/kem.c ../../dhkem/ref/extractexpand.c ../../dhkem/ref/derivekeypair.c

test/test_gkem_functionality: $(SOURCES) $(HEADERS) test/test_gkem_functionality.c
	$(CC) $(CFLAGS) -DKYBER_K=3 $(SOURCES) ../../kyber/avx2/randombytes.c test/test_gkem_functionality.c -o $@

.PHONY: clean

clean:
	-rm -f test/test_gkem_functionality
	-rm -f *.s
ifeq ($(OS),Darwin)
	-rm -rf test/*.dSYM
endif
