hostRecon - lightweight libpcap C++ network scanner

**Purpose of hostRecon:**
The app aims to efficiently capture network packets for analysis and monitoring purposes.
By providing a platform to capture and process packets, it enables users to gain insights into network traffic,
and troubleshoot potential issues effectively.

**Current State:**
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
