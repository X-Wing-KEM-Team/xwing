# X-Wing: The Hybrid KEM You’ve Been Looking For

[![Coverage Status](https://coveralls.io/repos/github/JoaoDiogoDuarte/xwing/badge.svg?branch=main)](https://coveralls.io/github/JoaoDiogoDuarte/xwing?branch=main)

> [!TIP]  
> For the -06 draft implementation, see the [06-draft branch](https://github.com/X-Wing-KEM-Team/xwing/tree/06-draft).
 
Optimised and reference C implementation of the X-Wing hybrid KEM as defined in [draft-connolly-cfrg-xwing-kem](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/) and analysed in [https://eprint.iacr.org/2024/039](https://eprint.iacr.org/2024/039) by Barbosa et al.

Both implementations conform to the [libsodium API format](https://doc.libsodium.org/). 
The optimised implementation targets the x86 architecture and CPUs with the AVX2 instruction set. 

## Code reuse

This reuses and adapts code from some C files and headers, README, and Makefiles from [https://github.com/pq-crystals/kyber/tree/standard](https://github.com/pq-crystals/kyber/tree/standard) for the optimised ML-KEM-768 implementation (named just kyber in the repo), and is in the Public Domain or licensed by Apache Version 2. 

The SHA3-256 and SHA3-512 uses code directly from `kcp/optimized1600AVX2`, which is used in SUPERCOP, [https://bench.cr.yp.to/impl-hash/sha3256.html](https://bench.cr.yp.to/impl-hash/sha3256.html), which is in the Public Domain.

Furthermore, this code also reuses and adapts some C files and headers, and Makefiles from [https://github.com/formosa-crypto/hakyber](https://github.com/formosa-crypto/hakyber) for the reference ML-KEM-768 implementation, which is in the Public Domain or licensed by Apache Version 2. 

## Note on benchmarking

For benchmarking purposes, this repo also contains a reference and optimised implementation of the the generic combiner (GHPC) proposed by [Giacon, Heuer and Poettering](https://eprint.iacr.org/2018/024.pdf) and a naive X-Wing version that also hashes the ML-KEM-768 ciphertext. 

The GHPC combines ML-KEM-768 and DHKEM.
For this reason, an unautheticated version of DHKEM is also implemented in the repo. 
Note that the DHKEM implementation only works for this specific instance, whereby it is *not* authenticated and, uses X25519 and HKDF-SHA256 as its underlying primitives.

As the GHPC, DHKEM and X-Wing naive implementations are *only* for benchmarking purposes, they do not conform to the [libsodium API format](https://doc.libsodium.org/).

## Build instructions

The implementations contain several test, a functionality and a speed benchmarking programs and a Makefile to facilitate compilation.

### Prerequisites

For all X25519 operations, [lib25519](https://lib25519.cr.yp.to/) is required and must either be installed system wide or Nix can be used.
After downloading the latest release, instructions for compilation can be found on the lib25519 homepage, but can be summarised as:

```sh
./configure && make -j8 install
```
whereby `-j8` indicates the number of CPU cores to use during the make install.
If necessary, run `export LD_LIBRARY_PATH=/usr/local/lib/:LD_LIBRARY_PATH` or add the line `/usr/local/lib` to `/etc/ld.so.conf.d/myCustomLibraries.conf` and then run `ldconfig` as the superuser. 

For the HKDF-SHA256 implementation, [libsodium](https://doc.libsodium.org/) is a requirement.
This can often either be installed from the Linux distrubtion's package manager (e.g., `pacman -S libsodium` or `apt install libsodium-dev`) or from source by downloading and extracting the source tarball and running:

```sh
./configure
make && make check
sudo make install

```
More detailed instructions can be found on libsodium's official website.

For analysing the results of the benchmarking, Python is a requirement.

### Building all binaries

To compile the test and benchmarking programs on Linux or macOS, either run `make` from the root of the repository or go to the `ref/` or `avx2/` directory in each KEM implementation and run `make`.

This will produce the executables:

```sh
# for X-Wing an X-Wing naive
test/test_xkem_functionality
test/test_speed

# for GHPC
test/test_gkem_functionality
test/test_speed

# for DHKEM
test/test_kem_functionality
```

As per the [PQ-Crystals](https://github.com/pq-crystals/kyber) tests:

* `test_speed` reports the median and average cycle counts of 1000 executions of various internal functions 
  and the API functions for key generation, encapsulation and decapsulation. 
  This, at the moment, uses the RHPMC registers by default and hence, will only work on Intel chips. There are plans to have this option included as a flag before compilation, as is done by PQ-Crystals. For AMD chips, commenting out the `#define USE_RDPMC` in the `cpucycles.h` file.  
* `test_{x,g}kem_functionality`  Generates a random keypair, uses the resulting public key for encapsulation to output a shared key and ciphertext and checks whether the ciphertext is correctly decapsulated. 
  If avaialble, it will also check whether the implementation conforms to the test vectors provided by [draft-connolly-cfrg-xwing-kem](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/).
  The program will abort with an error message and return 1 if there was an error.
  

## Benchmarking

By running the script `scripts/run_speed_tests.sh`, it will run each of the `test_speed` executables 100 times and output the results to a file with the name `results_$KEM_$IMP` whereby `$KEM` is either `ghpc`, `xwing` or `xwing-naive` and $IMP is either `ref` or `avx2`.
The average of all the results obtained by running the aforementioned script, can be obtained by running `python scripts/analyse.py`.
This will output a JSON named `test_speed_results.json` with the following format:

```json
{
  "system_info": {
    "platform": "Linux",
    "platform-release": "6.7.6-arch1-1",
    "platform-version": "#1 SMP PREEMPT_DYNAMIC Fri, 23 Feb 2024 16:31:48 +0000",
    "architecture": "x86_64",
    "processor": " AMD Ryzen 7 7840HS with Radeon 780M Graphics",
    "min_requency": "5000.00Mhz",
    "max_requency": "5000.00Mhz",
    "frequency_used": "3.6Mhz",
    "physical cores": 8,
    "total cores": 16,
    "ram": "29.1 GB"
  },
  "xwing_avx2": {
    "keypair": 40253,
    "enc": 85374,
    "dec": 70184
  },
  "xwing_naive_avx2": {
    "keypair": 40127,
    "enc": 90694,
    "dec": 76188
  }
  ...
```

## Shared libraries

The reference and optimised implementation of X-Wing can be compiled into shared libraries by running in either the `ref` or `avx2` directories:

```sh
make shared
```
For example in the directory `ref/` of the reference implementation, this produces the libraries

```sh
libxwing_ref.so
```

All global symbols in the libraries lie in the namespaces `xwing_ref`. The corresponding API header file is `ref/api.h`, which contains prototypes for all API functions and preprocessor defines for the key and signature lengths.
