#!/bin/bash
cargo run --example initkeys --release -- -n 2 -k 1
cargo run --release -- --bls-key keys/1-bls --transcript transcript --api-port 8080 &
cd tests
go run main.go