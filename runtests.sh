#!/bin/sh -e

ARCH="${ARCH:-amd64}"
ARCH="${TRAVIS_CPU_ARCH:-$ARCH}"

if [ "$ARCH" = "amd64" -a "$TRAVIS_OS_NAME" != "osx" ]; then
    DIRS="src/crypto_kem/xwing/ref src/crypto_kem/xwing/avx2"
else
    DIRS="src/crypto_kem/xwing/ref"
fi

if [ "$ARCH" = "amd64" ]; then
    export CC="clang"
fi

for dir in $DIRS; do
    make -j$(nproc) -C $dir
    valgrind --vex-guest-max-insns=25 ./$dir/test/test_xkem_functionality
    ./$dir/test/test_xkem_functionality &
    PID1=$!
    wait $PID1
done

exit 0
