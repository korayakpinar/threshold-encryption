#!/bin/bash
# cargo run --release --example create_transcript -- -n 2
# cargo run --release --example create_helpers -- -n 2
cargo run --release --example create_keys -- -n 2 -k 1
cargo run --release -- --bls-key keys/1-bls --transcript transcript-2 --api-port 8080 --test &
cd tests
go run main.go