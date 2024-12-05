# -*- Makefile -*-

-include ../../../../Makefile.conf

CC     ?= /usr/bin/cc
CFLAGS := -Wall -Wextra -g -O3 -fomit-frame-pointer -l25519
OS     := $(shell uname -s)

all: test shared

default: test

test: test/test_xkem_functionality test/test_speed

shared: libxwing_ref.so

MLKEMHEADERS =  ../../mlkem/ref/cbd.h ../../mlkem/ref/fips202.h ../../mlkem/ref/indcpa.h ../../mlkem/ref/kem.h ../../mlkem/ref/ntt.h ../../mlkem/ref/params.h ../../mlkem/ref/poly.h ../../mlkem/ref/polyvec.h ../../mlkem/ref/randombytes.h ../../mlkem/ref/reduce.h ../../mlkem/ref/symmetric.h ../../mlkem/ref/verify.h
HEADERS = $(MLKEMHEADERS) xkem.h params.h
TESTHEADERS = $(HEADERS) test/test_vectors.h test/cpucycles.h test/speed_print.h

MLKEMSOURCES = ../../mlkem/ref/cbd.c ../../mlkem/ref/fips202.c ../../mlkem/ref/indcpa.c ../../mlkem/ref/kem.c ../../mlkem/ref/ntt.c ../../mlkem/ref/poly.c ../../mlkem/ref/polyvec.c ../../mlkem/ref/randombytes.c ../../mlkem/ref/reduce.c ../../mlkem/ref/symmetric-shake.c ../../mlkem/ref/verify.c
SOURCES =  $(MLKEMSOURCES) xkem.c
TESTSOURCES = $(SOURCES) test/cpucycles.c test/speed_print.c 

test/test_xkem_functionality: $(TESTSOURCES) $(TESTHEADERS) test/test_xkem_functionality.c
	$(CC) $(CFLAGS) $(TESTSOURCES) test/test_xkem_functionality.c -o $@

test/test_speed: $(TESTSOURCES) $(TESTHEADERS) test/test_speed.c
	$(CC) $(CFLAGS) $(TESTSOURCES) test/test_speed.c -o $@

libxwing_ref.so: $(SOURCES) $(HEADERS)
	$(CC) -shared -fpic $(CFLAGS) $(SOURCES) -o libxwing_ref.so

.PHONY: clean

clean:
	-rm -f test/test_xkem_functionality
	-rm -f test/test_speed
	-rm -f *.s
	-rm -f *.so
ifeq ($(OS),Darwin)
	-rm -rf test/*.dSYM
endif
