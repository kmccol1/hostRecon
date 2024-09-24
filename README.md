hostRecon - libpcap C++ network scanner

**Purpose of hostRecon:**
The purpose of this project involves developing advanced network scanning capabilities to enhance security measures and improve network visibility.
Leveraging innovating techniques such as ping sweeps, the project aims to provide comprehensive insights into network infrastructure, detect potential vulnerabilities, and strengthen overall security posture.
With this network scanning program, users can painlessly gain insights into their networks,
and troubleshoot potential issues effectively.

**Current State:**
<<<<<<< HEAD
The project currently implements the ping sweep functionality, allowing for efficient detection of active network hosts within a /24 subnet on a traditional LAN.

The current implementation also uses custom logic to handle ICMP Echo requests and responses without relying on system calls like to the 'ping' program/command.

We are now focusing on optimizing and fine-tuning of the host response verification functionality and handling of captured network data packets to build a comprehensive list of active hosts.

**Future State:**
For the future, we aim to introduce ARP scans and SYN ACK scans to further enhance our network scanning capabilities.

The ARP scan will facilitate local network host discovery, while SYN ACK scans will offer valuable port status information.

This implementation will give us a more comprehensive view of the network, enabling us to detect and address security issues effectively. Stay tuned for these new features!
=======
The current state of the project successfully captures and analyzes IPv4 network packets.
The latest version of the project also includes a significant improvement in the network packet handling process, specfically within the callBack function used in the pcap_loop() call inside of the pingSweep function. The issue with detecting the appropriate timing to end the packet capture has been resolved by adjusting the active host conditional checks. The callBack function now effectively detects when to exit the pcap_loop() based on the captured packet's response details, ensuring that the network scanning process terminates correctly upon completion.
This fix has greatly enhanced the stability and efficiency of the network scanner, preventing potential crashes and improving overall performance.

**Future State:**
In the future, enhancing the error handling mechanisms within the app can help in identifying and resolving issues more effectively.
User-interface enhancements to develop a more intuitve and user-friendly interface.
Improving the scanner with additional protocol support.
Implementing robust logging functionalities to track the packet capture process can aid in troubleshooting any potential bottlenecks.
Furthermore, incorperating real-time visualization of captured packets and adding filtering options based on specific criteria can
elevate the app's functionality and user experience. Also, test driven development may offer additional benefits in the future.
>>>>>>> ping_sweep
