hostRecon - lightweight libpcap C++ network scanner

**Purpose of hostRecon:**
The app aims to efficiently capture network packets for analysis and monitoring purposes.
By providing a platform to capture and process packets, it enables users to gain insights into network traffic,
and troubleshoot potential issues effectively.

**Current State:**
Currently, the app is encoutering issues within the 'capturePackets()' function, where it seems to be stuck and not capturing any packets.
To address this, we are reviewing the dev test environment NIC config and set up for packet capture.

**Future State:**
In the future, enhancing the error handling mechanisms within the app can help in identifying and resolving issues more effectively.
Implementing robust logging functionalities to track the packet capture process can aid in troubleshooting any potential bottlenecks.
Furthermore, incorperating real-time visualization of captured packets and adding filtering options based on specific criteria can
elevate the app's functionality and user experience. Also, test driven development may offer additional benefits in the future.
