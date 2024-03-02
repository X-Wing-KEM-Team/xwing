# -*- Makefile -*-

-include ../../../../Makefile.conf

CC     ?= /usr/bin/gcc
CFLAGS := -Wall -Wextra -g -O3 -fomit-frame-pointer -l25519 -lsodium
OS     := $(shell uname -s)

default: test

test: test/test_kem_functionality

HEADERS = kem.h extractexpand.h derivekeypair.h params.h test/test_vectors.h
SOURCES =  kem.c extractexpand.c derivekeypair.c 

test/test_kem_functionality: $(HEADERS) $(SOURCES) test/test_kem_functionality.c
	$(CC) $(CFLAGS) $(SOURCES) test/test_kem_functionality.c -o $@

.PHONY: clean

clean:
	-rm -f test/test_kem_functionality
	-rm -f *.s
ifeq ($(OS),Darwin)
	-rm -rf test/*.dSYM
endif
