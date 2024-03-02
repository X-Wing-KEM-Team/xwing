#!/bin/sh

echo "Running timing tests for GHPC..."
for i in {0..100}; do
    echo "$i"
    ./src/crypto_kem/ghpc/ref/test/test_speed >>results_ghpc_ref
    ./src/crypto_kem/ghpc/avx2/test/test_speed >>results_ghpc_avx2
done
echo "Running timing tests for X-Wing Naive..."
for i in {0..100}; do
    echo "$i"
    ./src/crypto_kem/xwing_naive/ref/test/test_speed >>results_xwing_naive_ref
    ./src/crypto_kem/xwing_naive/avx2/test/test_speed >>results_xwing_naive_avx2
done
echo "Running timing tests for X-Wing..."
for i in {0..100}; do
    echo "$i"
    ./src/crypto_kem/xwing/ref/test/test_speed >>results_xwing_ref
    ./src/crypto_kem/xwing/avx2/test/test_speed >>results_xwing_avx2
done
