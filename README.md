C implementation of the (derandomnised) X-Wing hybrid KEM as defined in [draft-connolly-cfrg-xwing-kem](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/) and analysed in [https://eprint.iacr.org/2024/039](https://eprint.iacr.org/2024/039) by Barbosa et al.

This reuses code from some C files and headers (including the MLKEM implementation) and the Makefiles from  [https://github.com/formosa-crypto/hakyber](https://github.com/formosa-crypto/hakyber). I cannot find the license for said code, so I am acknolwedging it here. Whenever the license is uploaded, I will refelct those changes. 

Libsodium is also a dependency.
