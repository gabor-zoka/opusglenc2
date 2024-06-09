#!/usr/bin/env bash

set -e -u -o pipefail

script_dir="$(realpath -- "$(dirname "$0")")"

sudo pacman --noconfirm --needed -S flac libopusenc

export CC=gcc
export CFLAGS='  -march=sandybridge -mtune=generic -O2 -pipe -fno-plt'
export CXXFLAGS='-march=sandybridge -mtune=generic -O2 -pipe -fno-plt'

$CC "$script_dir/main.c"\
  $(pkgconf --cflags --libs flac)\
  $(pkgconf --cflags --libs libopusenc)\
  $(pkgconf --cflags --libs opus) -lm -g -O1 -o opusglenc 
