//****************************************************************************************
//
//    Filename: networkScanner.cpp
//    Author:   Kyle McColgan
//    Date:     30 September 2024
//    Description: CLI based networking utility for local network host enumeration.
//
//****************************************************************************************

#include <iostream>
#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <cstring>
#include <arpa/inet.h>
#include <algorithm> //For std::reverse()
#include <cstdlib>
#include <thread>
#include <chrono>
#include <netinet/in.h> //For struct definitions
using namespace std;

//****************************************************************************************

const int MAX_HOSTS = 254; //Covers a typical /24 subnet, w/ 254 usable hosts.

//****************************************************************************************

struct CaptureContext
{
    pcap_t * captureSession;
    bool & result;
    struct in_addr destination;
    pcap_t * sendSession;
};

//****************************************************************************************

void copyAddr(char (*hostList)[16], const char * source, int index)
{
    int adrLen = strlen(source);
    cout << "Copying " << adrLen << " chars to list at index: " << index << endl;
    strncpy(hostList[index], source, adrLen);
    hostList[index][adrLen] = '\0';
    cout << "\nhostList updated." << endl;
}

//****************************************************************************************

void intToCharArray(int num, char * buffer)
{
    int i = 0;
    if (num ==0)
    {
        buffer[i++] = '0';
    }
    else
    {
        while(num > 0)
        {
            buffer[i++] = '0' + (num % 10);
            num /= 10;
        }
    }
    buffer[i] = '\0';

    //Reverse the buffer...
    reverse(buffer, buffer + i );
}

//****************************************************************************************

unsigned short computeChecksum(void * data, int length)
{
    unsigned short * buffer = (unsigned short *)data;
    unsigned int sum = 0;
    unsigned short result;

    for(sum = 0; length > 1; length -= 2)
    {
        sum += *buffer++;
    }

    if (length == 1)
    {
        sum += *(unsigned char *)buffer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;

    return result;
}


//****************************************************************************************

static void callBack(u_char * user, const struct pcap_pkthdr * pkthdr, const u_char * capPacket)
{
    auto context = reinterpret_cast<CaptureContext*>(user);

    const int ethHeaderLen = 14;

    context->result = false;

    struct ip * ipHeader = (struct ip *)(capPacket + ethHeaderLen); //Skip Ethernet header...

    if(ipHeader->ip_p == IPPROTO_ICMP)
    {
        char sourceStr[INET_ADDRSTRLEN];
        char destStr[INET_ADDRSTRLEN];
        char target[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &(ipHeader->ip_src.s_addr), sourceStr, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst.s_addr), destStr, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(context->destination), target, INET_ADDRSTRLEN);

        //Uncomment line below for debugging purposes:
        //cout << "Captured packet from: " << sourceStr << " to " << destStr << endl;

        if (strcmp(sourceStr, target) == 0)
        {
            int ipHeaderLen = ipHeader->ip_hl * 4;

            struct icmphdr * icmpHeader = (struct icmphdr *)(capPacket + ethHeaderLen + ipHeaderLen);

            if ( ( icmpHeader->type ) == ( ICMP_ECHOREPLY) )
            {
                cout << "Received ICMP ECHO Reply packet from " << sourceStr << endl;
                context->result = true;
                pcap_breakloop(context->captureSession);
            }
            else
            {
                cout << "ICMP type " << static_cast<int>(icmpHeader->type) << " received, ignoring..." << endl;
            }
        }
        else
        {
            //cout << "Response from a different host. Skipping..." << endl;
            //cout << ".";
            cout << endl;
        }
    }
    else
    {
        cout << "Not an ICMP packet. Skipping..." << endl;
    }
}

//****************************************************************************************

bool pingSweep(char (&destination)[16], CaptureContext &context) {
    bool result = false;
    struct ip ipHdr;
    struct icmphdr msgHdr;
    unsigned char myPacket[sizeof(struct ethhdr) + sizeof(struct ip) + sizeof(struct icmphdr)];

    // Initialize the destination IP in the context struct
    inet_pton(AF_INET, destination, &context.destination);

    // Fill in the Ethernet header
    struct ethhdr ethHdr;
    memset(&ethHdr, 0, sizeof(struct ethhdr));
    memset(&ethHdr.h_dest, 0xff, ETH_ALEN); // Broadcast MAC address
    ethHdr.h_source[0] = 0x00; // Set your own MAC address
    ethHdr.h_source[1] = 0xD8;
    ethHdr.h_source[2] = 0x61;
    ethHdr.h_source[3] = 0xAB;
    ethHdr.h_source[4] = 0x11;
    ethHdr.h_source[5] = 0x03;
    ethHdr.h_proto = htons(ETH_P_IP); // Protocol type for IP

    // Fill in the IP header
    memset(&ipHdr, 0, sizeof(struct ip));
    ipHdr.ip_hl = 5; // Header length
    ipHdr.ip_v = 4; // IP version
    ipHdr.ip_tos = 0; // Type of service
    ipHdr.ip_len = htons(sizeof(struct ip) + sizeof(struct icmphdr)); // Total length
    ipHdr.ip_id = htons(54321); // Identification
    ipHdr.ip_off = 0; // Fragment Offset
    ipHdr.ip_ttl = 64; // Time to live
    ipHdr.ip_p = IPPROTO_ICMP; // Protocol (ICMP)
    ipHdr.ip_sum = 0; // Checksum
    inet_pton(AF_INET, "192.168.1.110", &ipHdr.ip_src); // Source IP
    inet_pton(AF_INET, destination, &ipHdr.ip_dst); // Destination IP
    ipHdr.ip_sum = computeChecksum((unsigned short *)&ipHdr, sizeof(struct ip)); // Calculate checksum

    // Fill in the ICMP header
    memset(&msgHdr, 0, sizeof(struct icmphdr));
    msgHdr.type = ICMP_ECHO; // ICMP Echo request type
    msgHdr.code = 0; // Code
    msgHdr.checksum = 0; // Checksum
    msgHdr.un.echo.id = htons(1234); // Identifier
    msgHdr.un.echo.sequence = htons(1); // Sequence number
    msgHdr.checksum = computeChecksum((unsigned short *)&msgHdr, sizeof(struct icmphdr)); // Calculate checksum

    // Construct the packet by combining the headers
    memcpy(myPacket, &ethHdr, sizeof(struct ethhdr));
    memcpy(myPacket + sizeof(struct ethhdr), &ipHdr, sizeof(struct ip));
    memcpy(myPacket + sizeof(struct ethhdr) + sizeof(struct ip), &msgHdr, sizeof(struct icmphdr));

    // Send the packet using pcap_inject
    cout << "\n***Pinging " << destination << "..." << endl;
    if (pcap_inject(context.sendSession, myPacket, sizeof(myPacket)) == -1) {
        cout << "Error sending the packet: " << pcap_geterr(context.sendSession) << endl;
        return false;
    }

    //cout << "\n***Searching for a response..." << endl;

    // Use pcap_dispatch for a specified number of packets
    if (pcap_dispatch(context.captureSession, 10, callBack, reinterpret_cast<u_char *>(&context)) == -1) {
        cout << "Error in pcap_dispatch(): " << pcap_geterr(context.captureSession) << endl;
        return false;
    }

    // Check the result after capturing packets
    if (context.result)
    {
        cout << "Response received from " << destination << endl;
        cout << "Host " << destination << " is active!" << endl;
        result = true;
    }
    else
    {
        cout << "No response." << endl;
        cout << "Host " << destination << " is inactive." << endl;
    }

    return result;
}
//****************************************************************************************

void getHosts(char (*hostList)[16], int &numHosts, CaptureContext &context)
{
    const char base[] = "192.168.1.";
    char destIP[16];
    int hostCount = 0;

    for (int i = 93; i < 96; i++)
    {
        strcpy(destIP, base);
        char suffix[4];
        intToCharArray(i, suffix);
        strcat(destIP, suffix);

        //cout << "***Pinging " << destIP << "...\n";

        context.result = false;

        // Start timing for response
        auto startTime = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() - startTime < std::chrono::milliseconds(2000))
        {
            // Call pingSweep with the correct context
            pingSweep(destIP, context);

            // Check if we got a response
            if (context.result)
            {
                //cout << "Host " << destIP << " is active.\n";
                if (hostCount < MAX_HOSTS)
                {
                    copyAddr(hostList, destIP, hostCount);
                    hostCount++;
                }
                else
                {
                    cout << "Error: hostList is full, unable to add more hosts." << endl;
                    break;
                }
                break;
            }
        }

        // if (!context.result) {
        //     cout << "Inactive host detected. Skipping...\n";
        // }
    }

    numHosts = hostCount;
}

//****************************************************************************************

void filterSpecialChars(const char * address, char * filtered)
{
    int index = 0;

    for ( int i = 0; address[i] != '\0'; i ++)
    {
        if(isdigit(address[i]) || address[i] == '.')
        {
            filtered[index] = address[i];
            index ++;
        }
    }
    filtered[index] = '\0';
}

//****************************************************************************************

bool isValidIPAddress(const char* address)
{
    int numDots = 0;
    int numDigits = 0;
    bool result = true;

    if(address == nullptr)
    {
        result = false;
    }

    while (*address)
    {
        if(*address == '.')
        {
            numDots ++;

            if ( (numDigits < 1) || (numDigits > 3) )
            {
                result = false;
            }

            numDigits = 0;
        }

        else if((*address >= '0') && (*address <= '9'))
        {
            numDigits ++;
        }
        else if(!isalnum(*address) || (!isprint(*address)))
        {
            result = false;
        }
        else
        {
            result = false; //Reject ALL special Unicode characters...
        }

        address++;
    }

    //Check if the IP address has 3 dots and is valid...
    //if (dots != 3 || num < 0 || num > 255)
    if((numDots != 3) || (numDigits < 1) || (numDigits > 3))
    {
        result = false;
    }

    return result;
}

//****************************************************************************************

bool inList(const char* address, char (*hostList)[16], int listSize)
{
    bool result = false;

    for (int i = 0; i < listSize; i ++)
    {
        if(strcmp(address, hostList[i]) == 0)
        {
            result = true; //Return true if the host is already in the list...
        }
    }

    return result;
}

//****************************************************************************************

void displayHostList(char (*hostList)[16], int numHosts)
{
    //cout << "\n\nPrinting list with " << numHosts << " hosts included." << endl;
    //cout << "*****************************************" << endl;
    cout << "Active Hosts List: " << endl;

    for (int i = 0; i < numHosts; i ++)
    {
        cout << i + 1 << ". " << hostList[i] << endl;
    }
    //cout << "*****************************************" << endl;
    cout << "----------------------------------" << endl;
    //cout << "\nDone." << endl;
}

//****************************************************************************************

void openNetworkInterface()
{
    pcap_t * session;

    char errors [PCAP_ERRBUF_SIZE];
    cout << "\n***Opening session..." << endl;

    session = pcap_open_live("enp34s0", BUFSIZ, 1, 1000, errors);

    if(session == NULL)
    {
        cout << "Error opening the NIC: " << errors << endl;
    }
}

//****************************************************************************************

void extractDeviceInfo(const u_char * packet, char (&source)[16], char(&destination)[16])
{
    //Extract device information from the packet...(IPs, MACs)

    //Assuming IPv4 packet structure...
    // struct ip *ip_header = (struct ip*) (packet + SIZE_ETHERNET); //Assuming Ethernet frame...
    struct ip *ip_header = (struct ip*) (packet + 14); //Assuming Ethernet frame...

    //Extract source and destination IP addresses...
    char sourceIP[INET_ADDRSTRLEN];
    char destinationIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), sourceIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), destinationIP, INET_ADDRSTRLEN);

    // //Print the extracted IP addresses...
    // cout << "Source IP: " << sourceIP << endl;
    // cout << "Destination IP: " << destinationIP << endl;

    //cout << "Copying..." << endl;
    //cout << "Before source: " << sourceIP << endl;
    strncpy(source, sourceIP, sizeof(source));
    strncpy(destination, destinationIP, sizeof(destination));
}

//****************************************************************************************

int main()
{
    bool result = false;
    char hostList[MAX_HOSTS][16]; //Assuming each IP addr is stored in a 16-character array.
    int numHosts = 0;
    char sendErrorMsg [PCAP_ERRBUF_SIZE];
    char capErrorMsg [PCAP_ERRBUF_SIZE];
    pcap_t * captureSession; /*= pcap_open_live("enp34s0", BUFSIZ, 1, 1000, errorMsg);*/
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
