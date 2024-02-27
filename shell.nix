{ pkgs ? import <nixpkgs> {} }:
with pkgs;
let
  librandombytes = stdenv.mkDerivation rec {
    pname = "librandombytes";
    version = "20230919";

    src = fetchzip {
      url = "https://randombytes.cr.yp.to/librandombytes-${version}.tar.gz";
      hash = "sha256-wr44x45AwEU1v4kvbmG37npUJGmRprnUtAzQvJJuPyw=";
    };

    nativeBuildInputs = [ python3 ];

    buildInputs = [ openssl ];

    configurePhase = ''
      patchShebangs configure
      patchShebangs scripts-build
      ./configure --prefix=${placeholder "out"}
    '';
  };

  libcpucycles = stdenv.mkDerivation rec {
    pname = "libcpucycles";
    version = "20240114";

    src = fetchzip {
      url = "https://cpucycles.cr.yp.to/libcpucycles-${version}.tar.gz";
      hash = "sha256-EWUmQjsoHZfSC6xPxKaNW0M5X1AIHerWC9HbC84CLtY=";
    };

    nativeBuildInputs = [ python3 ];

    configurePhase = ''
      patchShebangs configure
      patchShebangs scripts-build
      ./configure --prefix=${placeholder "out"}
    '';
  };

  lib25519 = stdenv.mkDerivation rec {
    pname = "lib25519";
    version = "20230630";

    src = fetchzip {
      url = "https://lib25519.cr.yp.to/lib25519-${version}.tar.gz";
      hash = "sha256-mZ6U3ZbcCW+frnf8/TB8x/5LgxW/96lmSB+oX4tvCpQ=";
    };

    nativeBuildInputs = [ python3 ];

    buildInputs = [ librandombytes libcpucycles ];

    configurePhase = ''
      patchShebangs configure
      patchShebangs scripts-build
      ./configure --prefix=${placeholder "out"}
    '';
  };

  benchmark = pkgs.writeShellApplication {
    name = "run-benchmark";
    text = ''
echo 2 | sudo tee /sys/devices/cpu/rdpmc
sudo cpupower frequency-set -f 3.6Ghz
make
for i in {0..100}; do echo "$i"; src/crypto_kem/xwing/ref/test/test_speed >> results_xwing_ref; src/crypto_kem/xwing/avx2/test/test_speed >> results_xwing_avx2; done
for i in {0..100}; do echo "$i"; src/crypto_kem/xwing_naive/ref/test/test_speed >> results_xwing_naive_ref; src/crypto_kem/xwing_naive/avx2/test/test_speed >> results_xwing_naive_avx2; done
for i in {0..100}; do echo "$i"; src/crypto_kem/ghpc/ref/test/test_speed >> results_ghpc_ref; src/crypto_kem/ghpc/avx2/test/test_speed >> results_ghpc_avx2; done
python ./analyse.py
    '';
  };
in
pkgs.mkShell {
   nativeBuildInputs = [
    gnumake
    gcc
    valgrind
    benchmark
    gef
    python3
   ];

   buildInputs = [
      libsodium
      lib25519
   ];
 }

