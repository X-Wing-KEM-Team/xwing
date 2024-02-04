# -*- Makefile -*-

-include ../../Makefile.conf

CC     ?= /usr/bin/gcc
CFLAGS := -Wall -Wextra -g -O3 -fomit-frame-pointer -lsodium
OS     := $(shell uname -s)

default: test

test: test/test_xkem_functionality

HEADERS = xkem.h ../mlkem/symmetric.h ../mlkem/reduce.h ../mlkem/polyvec.h ../mlkem/poly.h params.h ../mlkem/ntt.h ../mlkem/kem.h ../mlkem/indcpa.h ../mlkem/fips202.h ../mlkem/cbd.h ../mlkem/params.h

SOURCES =  xkem.c ../mlkem/symmetric-fips202.c ../mlkem/reduce.c ../mlkem/polyvec.c ../mlkem/poly.c ../mlkem/ntt.c ../mlkem/kem.c ../mlkem/indcpa.c ../mlkem/fips202.c ../mlkem/cbd.c

test/test_xkem_functionality: test/test_xkem_functionality.c $(HEADERS) $(SOURCES) $(INCS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $<

.PHONY: clean

clean:
	-rm -f test/xtest_kem
	-rm -f *.s
ifeq ($(OS),Darwin)
	-rm -rf test/*.dSYM
endif
