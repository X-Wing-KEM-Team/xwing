Optimised and reference C implementation of the (derandomnised) X-Wing hybrid KEM as defined in [draft-connolly-cfrg-xwing-kem](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/) and analysed in [https://eprint.iacr.org/2024/039](https://eprint.iacr.org/2024/039) by Barbosa et al.

This reuses code from some C files and headers, and adapted Makefiles from [https://github.com/pq-crystals/kyber/tree/standard](https://github.com/pq-crystals/kyber/tree/standard) for the optimised mlkem implementation (named just kyber in the repo), and is in the Public Domain or licensed by Apache Version 2. Furthermore, this code also reuses some C files and headers, and adapted Makefiles from [https://github.com/formosa-crypto/hakyber](https://github.com/formosa-crypto/hakyber) for the reference mlkem implementation. The license for this code is unknown.  

For benchmarking purposes, DHKEM from the [HPKE RFC](https://www.rfc-editor.org/rfc/rfc9180.html) and the generic combiner proposed by [Giacon, Heuer and Poettering](https://eprint.iacr.org/2018/024.pdf).

lib25519 is a requirement and must either be installed system wide or Nix can be used (for GHPC, libsodium is also a dependency).

