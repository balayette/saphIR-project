#!/usr/bin/env sh

set -e

if [ "$#" -lt 3 ]; then
        echo "usage: $0 input.jit out_asm.S out_binary [verbose]"
        exit 1
fi

tmp=$(mktemp --suffix=.cpp.jit)
cpp -ftrack-macro-expansion=0 -P "$1" > "$tmp"
if [ "$#" -eq 4 ]; then
        ./jit -m aarch64 -i "$tmp" -o "$2"
else
        ./jit -m aarch64 -i "$tmp" -o "$2" > /dev/null
fi

aarch64-linux-gnu-gcc "$2" -o "$3"

echo "source: $1"
echo "preprocessed: $tmp"
echo "asm: $2"
echo "binary: $3"
