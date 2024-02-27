# -*- Makefile -*-

-include ../../../../Makefile.conf

CC     ?= /usr/bin/cc
CFLAGS := -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls -Wshadow -Wpointer-arith -mavx2 -mbmi2 -mpopcnt -march=native -mtune=native -O3 -fomit-frame-pointer -z noexecstack -l25519 -lsodium
OS     := $(shell uname -s)

default: test

test: test/test_gkem_functionality test/test_speed

HEADERS = gkem.h  ../../mlkem/avx2/params.h ../../mlkem/avx2/align.h ../../mlkem/avx2/kem.h ../../mlkem/avx2/indcpa.h ../../mlkem/avx2/polyvec.h ../../mlkem/avx2/poly.h ../../mlkem/avx2/reduce.h fq.inc shuffle.inc ../../mlkem/avx2/ntt.h ../../mlkem/avx2/consts.h ../../mlkem/avx2/rejsample.h ../../mlkem/avx2/cbd.h ../../mlkem/avx2/verify.h ../../mlkem/avx2/symmetric.h ../../mlkem/avx2/randombytes.h ../../mlkem/avx2/fips202.h ../../mlkem/avx2/fips202x4.h ../../dhkem/ref/kem.h ../../dhkem/ref/extractexpand.h ../../dhkem/ref/derivekeypair.h ../../dhkem/ref/params.h test/cpucycles.h test/speed_print.h

SOURCES =  gkem.c ../../mlkem/avx2/kem.c ../../mlkem/avx2/indcpa.c ../../mlkem/avx2/polyvec.c ../../mlkem/avx2/poly.c fq.S shuffle.S ntt.S invntt.S basemul.S ../../mlkem/avx2/consts.c ../../mlkem/avx2/rejsample.c ../../mlkem/avx2/cbd.c ../../mlkem/avx2/verify.c ../../mlkem/avx2/fips202.c ../../mlkem/avx2/fips202x4.c ../../mlkem/avx2/symmetric-shake.c ../../mlkem/avx2/keccak4x/KeccakP-1600-times4-SIMD256.o ../../dhkem/ref/kem.c ../../dhkem/ref/extractexpand.c ../../dhkem/ref/derivekeypair.c test/cpucycles.c test/speed_print.c

test/test_gkem_functionality: $(SOURCES) $(HEADERS) test/test_gkem_functionality.c
	$(CC) $(CFLAGS) -Dmlkem_K=3 $(SOURCES) ../../mlkem/avx2/randombytes.c test/test_gkem_functionality.c -o $@

test/test_speed: test/test_speed.c $(HEADERS) $(SOURCES) $(INCS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $<

.PHONY: clean

clean:
	-rm -f test/test_gkem_functionality
	-rm -f test/test_speed
	-rm -f *.s
ifeq ($(OS),Darwin)
	-rm -rf test/*.dSYM
endif
