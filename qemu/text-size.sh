#!/usr/bin/env bash
# Prints the .text bytes that each operation adds to an empty Cortex-M33 binary, with opt-level
# "s" and LTO. Each operation includes everything it calls, such as SHA-3.
set -euo pipefail
cd "$(dirname "$0")"

text() {
    cargo build --release --quiet --bin text-size "$@"
    llvm-size -A target/thumbv8m.main-none-eabihf/release/text-size | awk '$1 == ".text" { print $2 }'
}

base=$(text)
echo "Code size in bytes (.text) on a Cortex-M33, opt-level s:"
for op in keygen ek-check bind encapsulate decapsulate; do
    printf "  %-12s %6d\n" "$op" $(($(text --features "$op") - base))
done
printf "  %-12s %6d\n" all $(($(text --features keygen,ek-check,bind,encapsulate,decapsulate) - base))
