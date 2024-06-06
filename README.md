hostRecon - lightweight libpcap C++ network scanner

**Purpose of hostRecon:**
The app aims to efficiently capture network packets for analysis and monitoring purposes.
By providing a platform to capture and process packets, it enables users to gain insights into network traffic,
and troubleshoot potential issues effectively.

**Current State:**
The current state of the project successfully captures and analyzes IPv4 network packets.
However, we have identified an issue with some entries in the hostList, resulting in special Unicode characters in the program output. We are actively investigating the conversion process for storing IP addresses to ensure proper formatting in the 'hostList' char array. By reviewing and refining this process, we aim to resolve this issue expeditiously and therefore improve the overall functionality and user-friendliness of the application.

**Future State:**
In the future, enhancing the error handling mechanisms within the app can help in identifying and resolving issues more effectively.
Implementing robust logging functionalities to track the packet capture process can aid in troubleshooting any potential bottlenecks.
Furthermore, incorperating real-time visualization of captured packets and adding filtering options based on specific criteria can
elevate the app's functionality and user experience. Also, test driven development may offer additional benefits in the future.
