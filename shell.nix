{ pkgs ? import <nixpkgs> {} }:
with pkgs;
pkgs.mkShell {
   nativeBuildInputs = [
    gnumake
    gcc
    valgrind
   ];

   buildInputs = [
      libsodium
   ];
 }

