#!/bin/sh -e

cd src/crypto_kem/xwing/ref

make -B test/test_xkem_functionality CFLAGS="-O0 -g --coverage -l25519"
./test/test_xkem_functionality
lcov -c -d . -o ../../../../xwing.lcov
lcov -z -d .
rm test/test_xkem_functionality

lcov -r ../../../../xwing.lcov -o ../../../../xwing.lcov \
    '*/test/*' 	'*/randombytes.c'

exit 0
