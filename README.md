
# hostRecon

![Build Status](https://img.shields.io/github/workflow/status/kmccol1/hostRecon/CI?logo=github)

## Overview

**hostRecon** is a fast, efficient, and easy-to-use CLI-based network scanner that facilitates host discovery and availability checks on local networks. Leveraging the power of `libpcap`, this tool performs network reconnaissance through ICMP Echo Request (ping) messages and captures responses from live hosts. It’s a valuable tool for network administrators, cybersecurity professionals, and anyone wanting to explore their local network.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Current State](#current-state)
- [Future State](#future-state)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Fast & Efficient**: Designed for quick host discovery via ICMP Echo Requests.
- **Low-Level Packet Manipulation**: Uses `libpcap` for low-level packet capture and injection.
- **Multi-Host Scanning**: Allows the concurrent scanning of multiple hosts to save time.
- **Customizable Network Configuration**: Set custom source and destination IP addresses.
- **Real-Time Active Host Display**: Instantly shows hosts that are up and responsive.
- **Error Resilience**: Includes robust error handling for packet capture failures and network interface issues.

## Installation

### Prerequisites

To run **hostRecon**, you will need the following:

- **[libpcap](https://www.tcpdump.org/)**:
  - A packet capture library required for capturing and injecting packets.
  - Install via your package manager:

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

   ```bash
   git clone https://github.com/kmccol1/hostRecon.git
   cd hostRecon
   ```

2. Create a `build` directory and navigate into it:

   ```bash
   mkdir build
   cd build
   ```

3. Compile the project using CMake:

   ```bash
   cmake ..
   make
   ```

4. Run the scanner with appropriate privileges (usually as root):

   ```bash
   sudo ./networkScanner
   ```

5. (Optional) Run the tests:

   To run the tests, execute the following:

   ```bash
   ./test_network_scanner
   ```

## Usage

Once compiled, **hostRecon** can be run from the command line. The tool will automatically detect and scan the local subnet for active hosts, displaying the list of hosts that respond to the ICMP Echo Request.

### Example:

```bash
sudo ./networkScanner
```

The tool will output the list of active hosts in your local network.

## Current State

As of now, **hostRecon** provides the following functionality:

- Establishes a capture session to listen for ICMP Echo Replies.
- Constructs and sends ICMP Echo Request packets to specified IP addresses in a /24 subnet.
- Captures responses and accurately identifies active hosts based on received packets.
- Displays the results in a clear and concise format.

### Current Limitations:
- **Single-threaded Operation**: Scans hosts sequentially, which may limit speed in larger networks.
- **Limited Protocol Support**: Currently supports only ICMP-based host discovery.

## Future State

In future releases, we plan to add:

- **Multi-threaded Support**: Enable concurrent pinging for faster scans, improving efficiency.
- **Configurable Subnets**: Allow users to specify the IP range and subnet dynamically.
- **Expanded Protocols**: Include TCP/UDP port scanning and other protocols.
- **Detailed Reporting**: Enhance reporting features, providing additional data like response times and packet loss.
- **Improved Error Handling**: Offer better feedback for various network-related errors.
- **Graphical User Interface (GUI)**: Implement a GUI for a more user-friendly experience.

## Contributing

We welcome contributions from the community! Whether it’s submitting bug reports, suggesting new features, or contributing code, your input is valuable. Please refer to the [CONTRIBUTING.md](CONTRIBUTING.md) file for guidelines on how to contribute.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
