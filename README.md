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

To run the **hostRecon** network scanner, you'll need the following:

- **[libpcap](https://www.tcpdump.org/)**:
  - A packet capture library required for capturing and injecting packets.
  - Installation can be done via your package manager:

    For Ubuntu/Debian:

    ```bash
    sudo apt-get install libpcap-dev
    ```

    For Fedora:

    ```bash
    sudo dnf install libpcap-devel
    ```

    For macOS:

    ```bash
    brew install libpcap
    ```

- **C++ Compiler**:
  - A C++ compiler such as `g++`, `clang++`, or any standard C++ compiler.

- **CMake** (Optional for build automation):
  - While optional, **CMake** is recommended for automating the build process, especially for larger projects.
  - Installation (for Linux):

    ```bash
    sudo apt-get install cmake
    ```

    For macOS:

    ```bash
    brew install cmake
    ```

### Steps

1. Clone this repository:

   \`\`\`bash
   git clone https://github.com/kmccol1/hostRecon.git
   cd hostRecon
   \`\`\`

2. Create a `build` directory and navigate into it:

   \`\`\`bash
   mkdir build
   cd build
   \`\`\`

3. Compile the project using CMake:

   \`\`\`bash
   cmake ..
   make
   \`\`\`

4. Run the scanner with appropriate privileges (usually as root):

   \`\`\`bash
   sudo ./networkScanner
   \`\`\`

5. (Optional) Run the tests:

   To run the tests, execute the following:

   \`\`\`bash
   ./test_network_scanner
   \`\`\`
"""

## Usage

To use hostRecon, simply run the compiled executable. The tool will automatically scan the local subnet for active hosts and display the results.

## Current State

As of now, the hostRecon successfully provides:

    Establishes a capture session to listen for ICMP Echo Replies.
    Constructs and sends ICMP Echo Request packets to specified IP addresses within a /24 subnet.
    Captures responses and accurately determines the active hosts based on received packets.
    Displays the list of active hosts in a clear and concise format.

The tool is currently focused on:

    ICMP Protocol: Handling only ICMP packets to identify live hosts.
    Basic Host Discovery: Scanning a predefined range of IP addresses (192.168.1.93 to 192.168.1.95).
    Single-threaded Operation: Performing pings sequentially, limiting the speed of discovery.

## Future State

In the upcoming versions, we plan to enhance hostRecon with the following features:

    Multi-threading Support: Implement concurrent pings to improve scanning speed and efficiency.
    Configurable Subnet: Allow users to specify the IP range and subnet mask dynamically.
    Advanced Protocol Support: Expand capabilities to include TCP/UDP port scanning.
    Detailed Reporting: Generate reports with additional information (e.g., response time, packet loss).
    Improved Error Handling: Handle different network errors more gracefully with user feedback.
    Graphical User Interface (GUI): Explore a GUI option for easier user interaction and visual representation of the network status.

## Contributing

Contributions are welcome! Please read the CONTRIBUTING.md file for guidelines on how to contribute to this project.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
