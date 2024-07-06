#!/bin/bash
cargo run --example main
cargo run &
sleep 45
cd tests
source venv/bin/activate
python3 test.py
ps aux | grep "silent-threshold" | awk -F ' ' '{ print $2 }' | xargs kill;