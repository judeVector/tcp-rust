# tcp-rust

A TCP/IP stack implementation in Rust from scratch, built on top of a TUN device.

## Overview

This project implements the core TCP protocol following RFC 793 specifications. It creates a virtual network interface (TUN device) and handles TCP connections at the packet level, including connection establishment (three-way handshake) and state management.

## Features

- Custom TCP state machine (Listen, SynRcvd, Closed)
- Three-way handshake implementation (SYN, SYN-ACK, ACK)
- Send and Receive Sequence Space management
- Connection tracking using a quad (source IP:port, destination IP:port)
- Raw packet parsing and construction

## Dependencies

- `etherparse` - For parsing and constructing IP and TCP headers
- `tun-tap` - For creating and managing TUN/TAP devices

## How It Works

1. Creates a TUN device named "tun0"
2. Listens for incoming packets on the interface
3. Parses IPv4 and TCP headers
4. Manages TCP connections in a HashMap indexed by connection quads
5. Handles TCP state transitions and sends appropriate responses

## Usage
```bash
# Run with appropriate permissions (requires root/sudo for TUN device creation)
sudo cargo run
```

## Project Structure

- `main.rs` - Main event loop, packet reception, and connection management
- `tcp.rs` - TCP connection state machine and packet handling logic

## Learning Goals

This project is designed to understand:
- How TCP works at a low level
- Network packet structure and parsing
- State machine implementation
- Systems programming in Rust
