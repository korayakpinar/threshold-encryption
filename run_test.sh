#!/bin/bash
cargo build --release --example create_keys
cargo build --release --example mempool
cargo build --release
target/release/examples/create_keys -n 2 -k 1
target/release/examples/mempool --port 65534 --test &
sleep 5
target/release/silent-threshold --bls-key keys/1-bls --transcript transcript-512 --api-port 8080 --mempool-port 65534 &
sleep 5
cd tests
go run main.go