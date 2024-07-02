//****************************************************************************************
//
//    Filename: networkScanner.cpp
//    Author:   Kyle McColgan
//    Date:     30 June 2024
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

    //Check protocol...
    if(ipHeader->ip_p == IPPROTO_ICMP)
    {
        //Compare the target's address to the response packet's header address info...

        char sourceStr [INET_ADDRSTRLEN];
        char destStr [INET_ADDRSTRLEN];
        char target[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &(ipHeader->ip_src.s_addr), sourceStr, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst.s_addr), destStr, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(context->destination), target, INET_ADDRSTRLEN);

        //cout << "\n***Response info for target: " << target << endl;
        cout << "Captured packet from: " << sourceStr << " to " << destStr << endl;

        if(strcmp(sourceStr, target) == 0)
        {
            int ipHeaderLen = ipHeader -> ip_hl * 4;

            struct icmphdr * icmpHeader = (struct icmphdr *)(capPacket + ethHeaderLen + ipHeaderLen); //Skip IP header...

            cout << "ICMP type: " << static_cast<int>(icmpHeader->type) << endl;

            if(icmpHeader->type ==ICMP_ECHOREPLY)
            {
                cout <<"Received ICMP ECHO Reply packet..." << endl;
                //cout << "Updating context->result...: " << context->result << endl;
                context->result = true;
                //cout << "Updated context->result...: " << context->result << endl;
            }
            else if (icmpHeader->type ==ICMP_DEST_UNREACH)
            {
                cout <<"Received ICMP DEST UNREACH packet..." << endl;
                //context->result = false;
            }
            else if (icmpHeader->type ==ICMP_TIME_EXCEEDED)
            {
                cout <<"Received ICMP TIME EXCEEDED packet..." << endl;
                //context->result = false;
            }
            else
            {
                cout << "Unknown response type. Skipping..." << endl;
                //context->result = false;
            }

            //context->result = true;
            //pcap_breakloop(context->captureSession);
            pcap_breakloop(reinterpret_cast<pcap_t *> (context->captureSession));
            //return;
        }
    }
    // else
    // {
    //     cout << "Not an ICMP packet. Skipping..." << endl;
    //     context->result = false;
    // }
}

//****************************************************************************************

bool pingSweep( char (&destination)[16], CaptureContext context)
{
    bool result = false;;
    struct ip ipHdr;
    struct icmphdr msgHdr;
    unsigned char myPacket[sizeof(struct ethhdr) + sizeof(struct ip) + sizeof(struct icmphdr)];
    const u_char * capPacket;

    //CaptureContext context{captureSession, result};
    inet_pton(AF_INET, destination, &context.destination); //This line is needed to fill in the context struct...

    //Fill in the headers for the echo request...

    //Fill in the Ethernet header...
    struct ethhdr ethHdr;
    memset(&ethHdr, 0, sizeof(struct ethhdr));

    //Set destination MAC address (example: broadcast address...)
    ethHdr.h_dest[0] = 0xff;
    ethHdr.h_dest[1] = 0xff;
    ethHdr.h_dest[2] = 0xff;
    ethHdr.h_dest[3] = 0xff;
    ethHdr.h_dest[4] = 0xff;
    ethHdr.h_dest[5] = 0xff;
    //
    // //Set source MAC address (example: your own MAC address...)
    // //Direct assignment...
    ethHdr.h_source[0] = 0x00;
    ethHdr.h_source[1] = 0xD8;
    ethHdr.h_source[2] = 0x61;
    ethHdr.h_source[3] = 0xAB;
    ethHdr.h_source[4] = 0x11;
    ethHdr.h_source[5] = 0x03;

    //Set the protocol type to IP...
    ethHdr.h_proto = htons(ETH_P_IP);

    //Fill in the IP header...
    // memset(&ipHdr, 0, sizeof(ipHdr));
    memset(&ipHdr, 0, sizeof(struct ip));
    ipHdr.ip_hl = 5; //Header length.
    ipHdr.ip_v = 4; //IP version.
    ipHdr.ip_tos = 0; //Type of service
    // ipHdr.ip_len = htons(sizeof(struct ip)) + sizeof(struct icmphdr); //Total length
    ipHdr.ip_len = htons(sizeof(struct ip) + sizeof(struct icmphdr)); //Total length
    ipHdr.ip_id = htons(54321); //Identification.
    ipHdr.ip_off = 0; //Fragment Offset.
    // ipHdr.ip_ttl = 255; //Time to live.
    ipHdr.ip_ttl = 64; //Time to live.
    ipHdr.ip_p = IPPROTO_ICMP; //Protocol (ICMP)
    ipHdr.ip_sum = 0; //Checksum (set to 0 before calculating.)
    // ipHdr.ip_src.s_addr = inet_addr("192.168.1.213");
    // ipHdr.ip_dst.s_addr = inet_addr("192.168.1.94");

    inet_pton(AF_INET, "192.168.1.213", &(ipHdr.ip_src)); //Source IP
    inet_pton(AF_INET, destination, &(ipHdr.ip_dst)); //Destination IP

    //Calculate the checksum for the IP header...
    // ipHdr.ip_sum = computeChecksum((unsigned short *)&ipHdr, sizeof(struct ip));
    ipHdr.ip_sum = computeChecksum((unsigned short *)&ipHdr, sizeof(ipHdr));

    //Fill in the ICMP header...
    memset(&msgHdr, 0, sizeof(struct icmphdr));
    msgHdr.type = ICMP_ECHO; //ICMP Echo request type.
    msgHdr.code = 0; //Code
    msgHdr.checksum = 0; //Checksum (set to 0 before calculating.)
    msgHdr.un.echo.id = htons(1234); //Identifier.
    msgHdr.un.echo.sequence = htons(1); //Sequence number.

    //Calculate the checksum for the ICMP header...
    // msgHdr.checksum = computeChecksum((unsigned short *)&msgHdr, sizeof(struct icmphdr));
    msgHdr.checksum = computeChecksum((unsigned short *)&msgHdr, sizeof(struct icmphdr));

    //Construct the packet, by combining the headers into one super packet...
    //int packetLen = sizeof(struct ip) + sizeof(struct icmphdr);
    //memset(myPacket, 0, sizeof(myPacket));
    memcpy(myPacket, &ethHdr, sizeof(struct ethhdr));
    memcpy(myPacket + sizeof(struct ethhdr), &ipHdr, sizeof(struct ip));
    memcpy(myPacket + sizeof(struct ethhdr) + sizeof(struct ip), &msgHdr, sizeof(icmphdr));

    //send the packet using pcap_inject...
    cout << "\n***Pinging " << destination << "..." << endl;
    if(pcap_inject(context.sendSession, myPacket, sizeof(myPacket)) == -1)
    {
        cout << "Error sending the packet: " << pcap_geterr(context.sendSession) << endl;
        result = false;
    }

    cout << "\n***Searching..." << endl;
    if(pcap_loop(context.captureSession, 3, callBack, reinterpret_cast<u_char *>(&context)) == -1)
    {
        cout << "Error in pcap_loop(): " << pcap_geterr(context.captureSession) << endl;
        result = false;
    }
    else if(context.result == true)
    {
        cout << "Success!" << endl;
        result = true;
        cout << "Result: " << result << endl;
    }

    return result;
}

//****************************************************************************************

void getHosts(char (*hostList)[16], int & numHosts, CaptureContext context)
{
    const char base [] = "192.168.1."; //Correctly initalize the base IP array...
    char destIP[16]; //Enough to hold an IP address in the form xxx.xxx.xxx.xxx
    int hostCount = 0;
    bool result = false;

    //Should start at 1 and end at 254. The IP address range in a /24 subnet is from
    //x.x.x.0 to x.x.x.255.
    //x.x.x.0 is the network address and is not assignable to a host.
    //x.x.x.255 is trhe broadcast address and is also not assignable to a host.
    for (int i = 93; i < 96; i ++)
    {
        //Manually construct the IP address
        strcpy(destIP, base);
        char suffix [4]; //Sufficient for numbers 0-255
        intToCharArray(i, suffix); //Convert integer to string
        strcat(destIP, suffix);

        if(pingSweep(destIP, context))
        {
            if(hostCount < MAX_HOSTS)
            {

                copyAddr(hostList, destIP, hostCount);

                cout << "\nAfter copy: " << hostList[hostCount] << endl;

                hostCount ++;
            }
            else
            {

                cout << "Error: hostList is full, unable to add more hosts." << endl;
                break;
            }
        }
        else
        {
            cout << "Inactive host detected. Skipping..." << endl;
        }
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
    cout << "\n\nPrinting list with " << numHosts << " hosts included." << endl;
    cout << "*****************************************" << endl;

    for (int i = 0; i < numHosts; i ++)
    {
        cout << "Host " << i+1 << ": " << hostList[i] << endl;
    }
    cout << "*****************************************" << endl;
    cout << "\nDone." << endl;
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
    int timeout = 1000; //Timeout value in milliseconds.

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

    CaptureContext context{captureSession, result, .sendSession=sendSession};

    getHosts(hostList, numHosts, context);
    displayHostList(hostList, numHosts);

    pcap_freecode(&filter);

    pcap_close(context.captureSession);
    pcap_close(context.sendSession);

    return 0;
}

//****************************************************************************************

/*
g++ networkScanner.cpp -lpcap -o networkScanner
hostRecon> sudo ./networkScanner

Filter applied successfully!

***Pinging 192.168.1.93...

***Searching...
Captured packet from: 192.168.1.213 to 192.168.1.93
Captured packet from: 192.168.1.213 to 192.168.1.220
Captured packet from: 192.168.1.213 to 192.168.1.237
Inactive host detected. Skipping...

***Pinging 192.168.1.94...

***Searching...
Captured packet from: 192.168.1.213 to 192.168.49.1
Captured packet from: 192.168.1.213 to 192.168.1.94
Captured packet from: 192.168.1.94 to 192.168.1.213
ICMP type: 0
Received ICMP ECHO Reply packet...
Success!
Result: 1
Copying 12 chars to list at index: 0

hostList updated.

After copy: 192.168.1.94

***Pinging 192.168.1.95...

***Searching...
Captured packet from: 192.168.1.213 to 192.168.1.220
Captured packet from: 192.168.1.213 to 192.168.1.237
Captured packet from: 192.168.1.213 to 192.168.49.1
Inactive host detected. Skipping...


Printing list with 1 hosts included.
*****************************************
Host 1: 192.168.1.94
*****************************************

Done.

*/
