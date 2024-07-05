#!/bin/bash
cargo run --example main
cp tests/sks/24 ~/.sk
cargo run &
sleep 15
cd tests
source venv/bin/activate
python3 test.py
ps aux | grep "silent-threshold" | awk -F ' ' '{ print $2 }' | xargs kill;