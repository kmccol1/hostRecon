//****************************************************************************************
//
//    Filename:    networkScanner.cpp
//    Author:      Kyle McColgan
//    Date:        7 October 2024
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

    //Open session handlers with a timeout of 1000 ms...
    sendSession = pcap_open_live("enp34s0", BUFSIZ, 0, timeout, sendErrorMsg);
    captureSession = pcap_open_live("enp34s0", BUFSIZ, 0, timeout, capErrorMsg);

    if(sendSession == nullptr)
    {
        cout << "Error accessing the network interface for injection: " << sendErrorMsg << endl;
        return 1;
    }
    else if (captureSession == nullptr)
    {
        cout << "Error accessing the network interface for capture: " << capErrorMsg << endl;
        return 1;
    }

    //Set the filter for ICMP packets
    struct bpf_program filter;
    bpf_u_int32 net;
    char filterExp[] = "icmp";
    // char filterExp[] = "icmp[icmptype] == icmp-echoreply";
    // char filterExp[] = "icmp and icmp[icmptype] == 0";
    //char filterExp[] = "icmp[icmpcode] == 0 and icmp[icmptype] == 0";

    //Compile the filter expression...
    if (pcap_compile(captureSession, &filter, filterExp, 0, net) == -1)
    {
        cout << "Could not parse filter: " << filterExp << ": "
             << pcap_geterr(captureSession) << endl;

        return 1;
    }

    //Apply the filter expression...
    if (pcap_setfilter(captureSession, &filter) == -1)
    {
        cout << "Could not install filter: " << filterExp << ": "
             << pcap_geterr(captureSession) << endl;

        return 1;
    }

    cout << "\nFilter applied successfully!" << endl;
    cout << "----------------------------------" << endl;

    CaptureContext context{captureSession, result, .sendSession=sendSession};

    getHosts(hostList, numHosts, context);
    cout << "----------------------------------" << endl;
    displayHostList(hostList, numHosts);

    pcap_freecode(&filter);

    pcap_close(context.captureSession);
    pcap_close(context.sendSession);

    return 0;
}

//****************************************************************************************

/*
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
