{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  hardeningDisable = [
    "zerocallusedregs"
  ];

  buildInputs = [
    pkgs.clang
    pkgs.go
  ];
}
