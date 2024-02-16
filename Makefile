default: xwing ghpc

xwing:
	cd src/crypto_kem/xwing/ref && $(MAKE) 
	cd src/crypto_kem/xwing/avx2 && $(MAKE)

ghpc:
	cd src/crypto_kem/ghpc/ref && $(MAKE)
	cd src/crypto_kem/ghpc/avx2 && $(MAKE)
