# -*- Makefile -*-

-include ../../../../Makefile.conf

CC     ?= /usr/bin/gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls -Wshadow -Wpointer-arith -mavx2 -mbmi2 -mpopcnt -march=native -mtune=native -O3 -fomit-frame-pointer -z noexecstack -l25519 -lsodium
OS     := $(shell uname -s)

default: test

test: test/test_gkem_functionality

HEADERS = gkem.h ../../mlkem/ref/symmetric.h ../../mlkem/ref/reduce.h ../../mlkem/ref/polyvec.h ../../mlkem/ref/poly.h params.h ../../mlkem/ref/ntt.h ../../mlkem/ref/kem.h ../../mlkem/ref/indcpa.h ../../mlkem/ref/fips202.h ../../mlkem/ref/cbd.h ../../mlkem/ref/params.h ../../dhkem/ref/kem.h ../../dhkem/ref/extractexpand.h ../../dhkem/ref/derivekeypair.h ../../dhkem/ref/params.h test/cpucycles.h test/speed_print.h

SOURCES =  gkem.c ../../mlkem/ref/symmetric-fips202.c ../../mlkem/ref/reduce.c ../../mlkem/ref/polyvec.c ../../mlkem/ref/poly.c ../../mlkem/ref/ntt.c ../../mlkem/ref/kem.c ../../mlkem/ref/indcpa.c ../../mlkem/ref/fips202.c ../../mlkem/ref/cbd.c  ../../dhkem/ref/kem.c ../../dhkem/ref/extractexpand.c ../../dhkem/ref/derivekeypair.c test/cpucycles.c test/speed_print.c

test/test_gkem_functionality: test/test_gkem_functionality.c $(HEADERS) $(SOURCES) $(INCS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $<

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
