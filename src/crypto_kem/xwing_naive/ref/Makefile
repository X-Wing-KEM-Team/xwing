# -*- Makefile -*-

-include ../../../../Makefile.conf

CC     ?= /usr/bin/gcc
CFLAGS := -Wall -Wextra -g -O3 -fomit-frame-pointer -l25519
OS     := $(shell uname -s)

default: test

test: test/test_xkem_functionality test/test_speed

HEADERS = xkem.h test/test_vectors.h ../../mlkem/ref/symmetric.h ../../mlkem/ref/reduce.h ../../mlkem/ref/polyvec.h ../../mlkem/ref/poly.h params.h ../../mlkem/ref/ntt.h ../../mlkem/ref/kem.h ../../mlkem/ref/indcpa.h ../../mlkem/ref/fips202.h ../../mlkem/ref/cbd.h ../../mlkem/ref/params.h test/cpucycles.h test/speed_print.h test/test_vectors.h

SOURCES =  xkem.c ../../mlkem/ref/symmetric-fips202.c ../../mlkem/ref/reduce.c ../../mlkem/ref/polyvec.c ../../mlkem/ref/poly.c ../../mlkem/ref/ntt.c ../../mlkem/ref/kem.c ../../mlkem/ref/indcpa.c ../../mlkem/ref/fips202.c ../../mlkem/ref/cbd.c test/cpucycles.c test/speed_print.c

test/test_xkem_functionality: test/test_xkem_functionality.c $(HEADERS) $(SOURCES) $(INCS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $<

test/test_speed: test/test_speed.c $(HEADERS) $(SOURCES) $(INCS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $<

.PHONY: clean

clean:
	-rm -f test/test_xkem_functionality
	-rm -f test/test_speed
	-rm -f *.s
ifeq ($(OS),Darwin)
	-rm -rf test/*.dSYM
endif
