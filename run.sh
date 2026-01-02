#!/bin/bash
set -e
sudo ip link delete tun0 2>/dev/null || true
cargo build --release
sudo setcap cap_net_admin=eip target/release/tcp-rust
target/release/tcp-rust &
pid=$!
sleep 1
sudo ip addr add 192.168.0.1/24 dev tun0
sudo ip link set dev tun0 up
trap "sudo ip link delete tun0; kill $pid" INT TERM EXIT

wait $pid
