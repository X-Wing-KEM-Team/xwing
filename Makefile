default: xwing ghpc xwing_naive

xwing:
	cd src/crypto_kem/xwing/ref && $(MAKE) 
	cd src/crypto_kem/xwing/avx2 && $(MAKE)

xwing_naive:
	cd src/crypto_kem/xwing_naive/ref && $(MAKE) 
	cd src/crypto_kem/xwing_naive/avx2 && $(MAKE)

ghpc:
	cd src/crypto_kem/ghpc/ref && $(MAKE)
	cd src/crypto_kem/ghpc/avx2 && $(MAKE)

clean:
	cd src/crypto_kem/xwing/ref && $(MAKE) clean
	cd src/crypto_kem/xwing/avx2 && $(MAKE) clean
	cd src/crypto_kem/xwing_naive/ref && $(MAKE) clean
	cd src/crypto_kem/xwing_naive/avx2 && $(MAKE) clean
	cd src/crypto_kem/ghpc/ref && $(MAKE) clean
	cd src/crypto_kem/ghpc/avx2 && $(MAKE) clean
	rm -f results_*