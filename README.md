hostRecon - libpcap C++ network scanner

**Purpose of hostRecon:**
The purpose of this project involves developing advanced network scanning capabilities to enhance security measures and improve network visibility.
Leveraging innovating techniques such as ping sweeps, the project aims to provide comprehensive insights into network infrastructure, detect potential vulnerabilities, and strengthen overall security posture.
With this network scanning program, users can painlessly gain insights into their networks,
and troubleshoot potential issues effectively.

**Current State:**
The project currently implements the ping sweep functionality, allowing for efficient detection of active network hosts within a /24 subnet on a traditional LAN.

The current implementation also uses custom logic to handle ICMP Echo requests and responses without relying on system calls like to the 'ping' program/command.

We are now focusing on optimizing and fine-tuning of the host response verification functionality and handling of captured network data packets to build a comprehensive list of active hosts.

**Future State:**
For the future, we aim to introduce ARP scans and SYN ACK scans to further enhance our network scanning capabilities.

The ARP scan will facilitate local network host discovery, while SYN ACK scans will offer valuable port status information.

This implementation will give us a more comprehensive view of the network, enabling us to detect and address security issues effectively. Stay tuned for these new features!
