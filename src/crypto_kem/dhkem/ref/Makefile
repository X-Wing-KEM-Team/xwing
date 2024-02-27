# -*- Makefile -*-

-include ../../../../Makefile.conf

CC     ?= /usr/bin/gcc
CFLAGS := -Wall -Wextra -g -O3 -fomit-frame-pointer -l25519 -lsodium
OS     := $(shell uname -s)

default: test

test: test/test_kem_functionality

HEADERS = kem.h extractexpand.h derivekeypair.h params.h test/test_vectors.h test/cpucycles.h test/speed_print.h
SOURCES =  kem.c extractexpand.c derivekeypair.c test/cpucycles.c test/speed_print.c 

test/test_kem_functionality: $(HEADERS) $(SOURCES) test/test_kem_functionality.c
	$(CC) $(CFLAGS) $(SOURCES) test/test_kem_functionality.c -o $@

test/test_speed: $(HEADERS) $(SOURCES) test/test_speed.c
	$(CC) $(CFLAGS) $(SOURCES) test/test_speed.c -o $@

.PHONY: clean

clean:
	-rm -f test/test_kem_functionality
	-rm -f test/test_speed
	-rm -f *.s
ifeq ($(OS),Darwin)
	-rm -rf test/*.dSYM
endif
