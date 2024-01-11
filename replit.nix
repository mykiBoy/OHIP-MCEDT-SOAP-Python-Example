{ pkgs }: {
  deps = [
    pkgs.gmp
    pkgs.zlib
    pkgs.xcodebuild
    pkgs.rustc
    pkgs.pkg-config
    pkgs.openssl
    pkgs.libxcrypt
    pkgs.libiconv
    pkgs.cargo
    pkgs.temurin-jre-bin-17
  ];
}