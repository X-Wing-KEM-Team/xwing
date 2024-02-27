# -*- Makefile -*-

-include ../../../../Makefile.conf

CC     ?= /usr/bin/cc
CFLAGS := Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls -Wshadow -Wpointer-arith -mavx2 -mbmi2 -mpopcnt -maes -march=native -mtune=native -O3 -fomit-frame-pointer -l25519
OS     := $(shell uname -s)

default: test

test: test/test_xkem_functionality test/test_speed

KYBERHEADERS =  ../../kyber/ref/params.h ../../kyber/ref/kem.h ../../kyber/ref/indcpa.h ../../kyber/ref/polyvec.h ../../kyber/ref/poly.h ../../kyber/ref/randombytes.h ../../kyber/ref/ntt.h ../../kyber/ref/cbd.h ../../kyber/ref/reduce.c ../../kyber/ref/verify.h ../../kyber/ref/symmetric.h
HEADERS = $(KYBERHEADERS) xkem.h params.h
TESTHEADERS = $(HEADERS) test/cpucycles.h test/speed_print.h

KYBERSOURCES =  ../../kyber/ref/kem.c ../../kyber/ref/indcpa.c ../../kyber/ref/polyvec.c ../../kyber/ref/poly.c ../../kyber/ref/randombytes.c ../../kyber/ref/ntt.c ../../kyber/ref/cbd.c ../../kyber/ref/reduce.c ../../kyber/ref/verify.c ../../kyber/ref/fips202.c ../../kyber/ref/symmetric-shake.c
SOURCES =  $(KYBERSOURCES) xkem.c
TESTSOURCES = $(SOURCES) test/cpucycles.c test/speed_print.c 

test/test_xkem_functionality: $(TESTSOURCES) $(TESTHEADERS) test/test_xkem_functionality.c
	$(CC) $(CFLAGS) -Dkyber_K=3 $(TESTSOURCES) test/test_xkem_functionality.c -o $@

test/test_speed: $(TESTSOURCES) $(TESTHEADERS) test/test_speed.c
	$(CC) $(CFLAGS) -Dkyber_K=3 $(TESTSOURCES) test/test_speed.c -o $@

.PHONY: clean

clean:
	-rm -f test/test_xkem_functionality
	-rm -f test/test_speed
	-rm -f *.s
ifeq ($(OS),Darwin)
	-rm -rf test/*.dSYM
endif
