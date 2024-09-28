# hostRecon

## Overview

This repository contains code designed and developed as a CLI-based networking utility to facilitate local network host enumeration. It allows users to ping hosts within a specified subnet to determine their availability, leveraging low-level packet manipulation with `libpcap`. This tool is ideal for network administrators, security professionals, and anyone interested in exploring their local network.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Current State](#current-state)
- [Future State](#future-state)
- [Contributing](#contributing)
- [License](#license)

## Features

- Efficient ICMP Echo Request (ping) implementation
- Captures and analyzes responses from active hosts
- Customizable source and destination IP addresses
- Concurrent pinging of multiple hosts
- Error handling for network interface and packet capturing
- User-friendly output for active hosts

## Installation

### Prerequisites

- [libpcap](https://www.tcpdump.org/)
- A C++ compiler (g++, clang, etc.)
- CMake (optional for build automation)

### Steps

1. Clone this repository:

   ```bash
   https://github.com/kmccol1/hostRecon.git
   cd network-scanner

2. Compile the project:

   ```bash
   g++ networkScanner.cpp -o networkScanner -lpcap

3. Run the scanner with appropriate privileges (usually as root):

   ```bash
   sudo ./networkScanner

Usage

To use hostRecon, simply run the compiled executable. The tool will automatically scan the local subnet for active hosts and display the results.
Current State

As of now, the hostRecon successfully provides:

    Establishes a capture session to listen for ICMP Echo Replies.
    Constructs and sends ICMP Echo Request packets to specified IP addresses within a /24 subnet.
    Captures responses and accurately determines the active hosts based on received packets.
    Displays the list of active hosts in a clear and concise format.

The tool is currently focused on:

    ICMP Protocol: Handling only ICMP packets to identify live hosts.
    Basic Host Discovery: Scanning a predefined range of IP addresses (192.168.1.93 to 192.168.1.95).
    Single-threaded Operation: Performing pings sequentially, limiting the speed of discovery.

Future State

In the upcoming versions, we plan to enhance hostRecon with the following features:

    Multi-threading Support: Implement concurrent pings to improve scanning speed and efficiency.
    Configurable Subnet: Allow users to specify the IP range and subnet mask dynamically.
    Advanced Protocol Support: Expand capabilities to include TCP/UDP port scanning.
    Detailed Reporting: Generate reports with additional information (e.g., response time, packet loss).
    Improved Error Handling: Handle different network errors more gracefully with user feedback.
    Graphical User Interface (GUI): Explore a GUI option for easier user interaction and visual representation of the network status.

Contributing

Contributions are welcome! Please read the CONTRIBUTING.md file for guidelines on how to contribute to this project.

License

This project is licensed under the MIT License - see the LICENSE file for details.
