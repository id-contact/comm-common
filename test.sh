#!/usr/bin/env bash

# Prerequisites:
# rustup component add llvm-tools-preview
# cargo install grcov
# apt install lcov

export COV_OUTPUT_DIR="./target/debug/coverage"
export LLVM_PROFILE_DIR="./target/debug/prof"
export LLVM_PROFILE_FILE="$LLVM_PROFILE_DIR/prof-%p-%m.profraw"

export RUSTFLAGS="-Zinstrument-coverage"
export RUSTUP_TOOLCHAIN="nightly" # Needed for gcov and -Z Rust flag

rm -r $COV_OUTPUT_DIR/* ||  mkdir -p $COV_OUTPUT_DIR;
rm -r $LLVM_PROFILE_DIR/* || true

cargo build
cargo test

grcov -s $LLVM_PROFILE_DIR --binary-path ./target/debug/ --llvm -t lcov --branch --ignore-not-existing  -o $COV_OUTPUT_DIR/lcov.info .
genhtml -o $COV_OUTPUT_DIR --show-details --highlight --ignore-errors source --legend $COV_OUTPUT_DIR/lcov.info

# xdg-open $COV_OUTPUT_DIR/index.html
echo "Done!"