# -*- Makefile -*-

-include ../../Makefile.conf

CC     ?= /usr/bin/gcc
CFLAGS := -Wall -Wextra -g -O3 -fomit-frame-pointer -lsodium
OS     := $(shell uname -s)

default: test

test: test/test_xkem_functionality

HEADERS = xkem.h symmetric.h reduce.h polyvec.h poly.h params.h ntt.h kem.h indcpa.h fips202.h cbd.h

SOURCES =  xkem.c symmetric-fips202.c reduce.c polyvec.c poly.c ntt.c kem.c indcpa.c fips202.c cbd.c

test/test_xkem_functionality: test/test_xkem_functionality.c $(HEADERS) $(SOURCES) $(INCS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $<

.PHONY: clean

clean:
	-rm -f test/xtest_kem
ifeq ($(OS),Darwin)
	-rm -rf test/*.dSYM
endif
