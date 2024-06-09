#!/usr/bin/env bash

set -e -u -o pipefail



td=$(pwd)
script_dir="$(realpath -- "$(dirname "$0")")"

export CC=musl-gcc
export CFLAGS='  -march=sandybridge -mtune=generic -O2 -pipe -fno-plt'
export CXXFLAGS='-march=sandybridge -mtune=generic -O2 -pipe -fno-plt'
export LDFLAGS=--static
export LIBRARY_PATH=$td/lib



echo '=== Building FLAC ============================================================'

if [[ ! -e flac ]]; then
  sudo pacman --noconfirm --needed -S cmake ninja git nasm musl upx

  git clone https://github.com/xiph/flac
  cd flac
  git checkout 1.4.3

  ./autogen.sh
  ./configure -prefix=$td --disable-shared --disable-doxygen-docs --disable-examples --disable-thorough-tests
  make check && make install
  cd -
fi



echo '=== Building Opus ============================================================'

if [[ ! -e opus ]]; then
  git clone https://github.com/xiph/opus
  cd opus
  git checkout v1.4

  ./autogen.sh
  ./configure -prefix=$td --disable-shared --disable-doc --disable-extra-programs
  make check && make install
  cd -
fi



echo '=== Building Libopusenc ======================================================'

# Always use the latest.
if [[ ! -e libopusenc ]]; then
  git clone https://github.com/xiph/libopusenc
  cd libopusenc

  ./autogen.sh
  ./configure -prefix=$td --disable-shared --disable-doc --disable-examples
  make check && make install
  cd -
fi



echo '=== Building Opusglenc ======================================================='

$CC "$script_dir/main.c" -Wall -lFLAC -lopusenc -lopus -lm -I$td/include -I$td/include/opus -static -o opusglenc

# Checking that it is a static executable indeed.
# ldd exits with error, so I need a jiggery pokery:
{ ldd opusglenc || true; } |& grep -q 'not a dynamic executable'

# An alternative way to check that this is a static executable. If it were
# dynamic it would print:
#
# Elf file type is DYN (Shared object file)
readelf --program-headers opusglenc | grep -q '^Elf file type is EXEC'

strip -s opusglenc
upx      opusglenc
