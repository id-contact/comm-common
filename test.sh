#!/usr/bin/env bash

rustup component add llvm-tools-preview
cargo install grcov

export RUSTFLAGS="-Zinstrument-coverage"
cargo +nightly build
export LLVM_PROFILE_FILE="id-contact-comm-common-%p-%m.profraw"
rm target/debug/coverage/* || true
cargo +nightly test

grcov . -s ./target/debug/coverage --binary-path ./target/debug/ -t lcov --branch --ignore-not-existing -o ./target/debug/coverage/
bash <(curl -s https://codecov.io/bash) -f lcov.info