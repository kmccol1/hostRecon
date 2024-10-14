//****************************************************************************************
//
//    Filename:    networkScanner.cpp
//    Author:      Kyle McColgan
//    Date:        14 October 2024
//    Description: CLI based networking utility for local network host enumeration.
//
//****************************************************************************************

#include <iostream>
#include "hostReconLib.h"
using namespace std;

//****************************************************************************************

int main()
{
    bool result = false;
    char hostList [MAX_HOSTS][16]; //Assuming each IP addr is stored in a 16-character array.
    int numHosts = 0;
    char sendErrorMsg [PCAP_ERRBUF_SIZE];
    char capErrorMsg [PCAP_ERRBUF_SIZE];
    pcap_t * captureSession;
    pcap_t * sendSession;
    int timeout = 2000; //Timeout value in milliseconds.

    std::cout << " _               _   ____                          \n";
    std::cout << "| |__   ___  ___| |_|  _ \\ ___  ___ ____   _____  \n";
    std::cout << "| '_ \\/ _ \\/ __| __| |_) / _ \\/ __/ _ \\| '_ \\ \n";
    std::cout << "| | |  | (_) \\__ \\ |_|  _ <  __/ (_| (_) | | | | \n";
    std::cout << "|_| |_|\\___/|___/\\__|_| \\_\\___|\\____/\\_|_| |_| \n";
    cout << "----------------------------------\n";

    //Open session handlers with a timeout of 1000 ms...
    cout << "Initializing network interface sessions...\n";
    sendSession = pcap_open_live("enp34s0", BUFSIZ, 0, timeout, sendErrorMsg);
    captureSession = pcap_open_live("enp34s0", BUFSIZ, 0, timeout, capErrorMsg);

    if(sendSession == nullptr)
    {
        cerr << "[ERROR] Could not access network interface for injection: " << sendErrorMsg << endl;
        return 1;
    }
    else if (captureSession == nullptr)
    {
        cerr << "[ERROR] Could not access the network interface for capture: " << capErrorMsg << endl;
        return 1;
    }

    cout << "[OK] Network interfaces initialized successfully!\n";

    //Set the filter for ICMP packets
    struct bpf_program filter;
    bpf_u_int32 net;
    char filterExp[] = "icmp";
    // char filterExp[] = "icmp[icmptype] == icmp-echoreply";
    // char filterExp[] = "icmp and icmp[icmptype] == 0";
    //char filterExp[] = "icmp[icmpcode] == 0 and icmp[icmptype] == 0";

    cout << "Applying ICMP filter...\n";

    //Compile the filter expression...
    if (pcap_compile(captureSession, &filter, filterExp, 0, net) == -1)
    {
        cerr << "[ERROR] Failed to compile filter: " << filterExp << "\n";
        cerr << "       " << pcap_geterr(captureSession) << "\n";

        return 1;
    }

    //Apply the filter expression...
    if (pcap_setfilter(captureSession, &filter) == -1)
    {
        cerr << "[ERROR] Failed to apply filter: " << filterExp << "\n";
        cerr << "       " << pcap_geterr(captureSession) << "\n";

        return 1;
    }

    cout << "[OK] ICMP filter applied successfully!\n";
    //cout << "----------------------------------" << endl;

    cout << "\nStarting host discovery...\n";
    CaptureContext context{captureSession, result, .sendSession=sendSession};

    getHosts(hostList, numHosts, context);
    cout << "----------------------------------" << endl;

    cout << "Host discovery completed.\n";
    displayHostList(hostList, numHosts);

    cout << "\nReleasing resources...\n";
    pcap_freecode(&filter);
    pcap_close(context.captureSession);
    pcap_close(context.sendSession);
    cout << "[OK] Resources released successfully.\n";

    cout << "Scan complete.\n";
    cout << "----------------------------------\n";

    return 0;
}

//****************************************************************************************

/*
 _               _   ____
| |__   ___  ___| |_|  _ \ ___  ___ ____   _____
| '_ \/ _ \/ __| __| |_) / _ \/ __/ _ \| '_ \
| | |  | (_) \__ \ |_|  _ <  __/ (_| (_) | | | |
|_| |_|\___/|___/\__|_| \_\___|\____/\_|_| |_|
----------------------------------
Initializing network interface sessions...
[OK] Network interfaces initialized successfully!
Applying ICMP filter...
[OK] ICMP filter applied successfully!

No response.
Host 192.168.1.253 is inactive.

***Pinging 192.168.1.254...

Received ICMP ECHO Reply packet from 192.168.1.254
Response received from 192.168.1.254
Host 192.168.1.254 is active!
Copying 13 chars to list at index: 13

hostList updated.
----------------------------------
Active Hosts List:
1. 192.168.1.66
2. 192.168.1.67
3. 192.168.1.94
4. 192.168.1.100
5. 192.168.1.108
6. 192.168.1.214
7. 192.168.1.215
8. 192.168.1.224
9. 192.168.1.227
10. 192.168.1.228
11. 192.168.1.235
12. 192.168.1.236
13. 192.168.1.246
14. 192.168.1.254
----------------------------------
*/
