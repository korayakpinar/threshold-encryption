#!/bin/bash
cargo run --example main
cd tests
source venv/bin/activate
python3 test.py