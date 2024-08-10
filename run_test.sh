#!/bin/bash
cargo run --release --example create_transcript -- -n 32
cargo run --release --example create_helpers -- -n 32
cargo run --release --example create_keys -- -n 32 -k 1
cargo run --release -- --bls-key keys/1-bls --transcript transcript --api-port 8080 &
cd tests
go run main.go