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
in
pkgs.mkShell {
   nativeBuildInputs = [
    gnumake
    gcc
    valgrind
   ];

   buildInputs = [
      libsodium
      lib25519
   ];
 }

