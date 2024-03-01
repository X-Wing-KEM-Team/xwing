#!/bin/sh
echo "Running functionality tests for GHPC..."
./src/crypto_kem/ghpc/ref/test/test_gkem_functionality
./src/crypto_kem/ghpc/avx2/test/test_gkem_functionality
echo "Running functionality tests for X-Wing Naive..."
./src/crypto_kem/xwing_naive/ref/test/test_xkem_functionality
./src/crypto_kem/xwing_naive/avx2/test/test_xkem_functionality
echo "Running functionality tests for X-Wing..."
./src/crypto_kem/xwing/ref/test/test_xkem_functionality
./src/crypto_kem/xwing/avx2/test/test_xkem_functionality
