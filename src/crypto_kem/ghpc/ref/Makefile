# -*- Makefile -*-

-include ../../../../Makefile.conf

CC     ?= /usr/bin/cc
CFLAGS := -Wall -Wextra -g -O3 -fomit-frame-pointer -l25519 -lsodium
OS     := $(shell uname -s)

default: test

test: test/test_gkem_functionality test/test_speed

MLKEMHEADERS = ../../mlkem/ref/cbd.h ../../mlkem/ref/fips202.h ../../mlkem/ref/indcpa.h ../../mlkem/ref/kem.h ../../mlkem/ref/ntt.h ../../mlkem/ref/params.h ../../mlkem/ref/poly.h ../../mlkem/ref/polyvec.h ../../mlkem/ref/reduce.h ../../mlkem/ref/symmetric.h
DHKEMHEADERS = ../../dhkem/ref/params.h ../../dhkem/ref/kem.h ../../dhkem/ref/derivekeypair.h ../../dhkem/ref/extractexpand.h
HEADERS = $(MLKEMHEADERS) $(DHKEMHEADERS) gkem.h params.h
TESTHEADERS = $(HEADERS) test/cpucycles.h test/speed_print.h

MLKEMSOURCES = ../../mlkem/ref/cbd.c ../../mlkem/ref/fips202.c ../../mlkem/ref/indcpa.c ../../mlkem/ref/kem.c ../../mlkem/ref/ntt.c ../../mlkem/ref/poly.c ../../mlkem/ref/polyvec.c ../../mlkem/ref/reduce.c ../../mlkem/ref/symmetric-fips202.c
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
