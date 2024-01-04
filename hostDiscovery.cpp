//****************************************************************************************
//
//Filename:    hostDiscovery.cpp
//Date:        3 January 2024
//Author:      Kyle McColgan
//Description: This program performs an ICMP Echo request using the libpcap library.
//
//****************************************************************************************

#include <iostream>
#include <pcap.h>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
using namespace std;

//****************************************************************************************

void printMenu()
{
    cout << "\n----------MENU----------" << endl;
    cout << "A....Inject an ICMP packet onto the network." << endl;
    cout << "Q....Quit and close any remaining open sessions." << endl;
    cout << "\nPlease input the letter of your selection from the menu: ";
}

//****************************************************************************************

uint16_t calculateChecksum( const void * data, size_t length)
{
    uint32_t sum = 0;
    const uint16_t * ptr = ( const uint16_t * ) data;

    while (length > 1)
    {
        sum += *ptr++;
        length -= 2;
    }

    if ( length > 0 )
    {
        sum += *((const uint8_t*)ptr);
    }

    while (sum >>16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return ~sum;
}

//****************************************************************************************

int injectICMPPacket()
{
    int returnFlag = 0;
    int numBytesWritten = 0;

    pcap_if_t * myDevice;
    char errorMsg[PCAP_ERRBUF_SIZE];

    //const void * packetData;
    int deviceFlag;
    //int numBytesWritten;

    pcap_t * sessionHandle; //return value from pcap_open_live
    //pcap_t * listenHandle; //For capturing response packets for example an ICMP Echo response.
    size_t packetLen;
    int numPackets;

    //pcap_lookupdev has been deprecated, use pcap_findalldevs instead.
    //device = pcap_lookupdev(errorMsg);
    cout << "Finding a valid interface for injection..." << endl;
    deviceFlag = pcap_findalldevs(&myDevice, errorMsg);

    if ( deviceFlag != 0 )
    {
        cout << "Could not find default device." << endl;
        returnFlag = -1;
    }
    else if ( deviceFlag == PCAP_ERROR)
    {
        cout << "Error reading the device list." << endl;
        returnFlag = -1;
    }

    cout << "Found device named: " << myDevice->name << endl;

    //open the device for injection....this must be run as root (sudo).
    cout << "Opening the device for injection..." << endl;
    sessionHandle = pcap_open_live (myDevice->name, PCAP_ERRBUF_SIZE, 1, 1000, errorMsg);

    if ( sessionHandle == NULL )
    {
        cout << "Could not open the device..." << errorMsg << endl;
        returnFlag = -1;
    }
    /*
    //Construct the ICMP packet...
    cout << "Building an ICMP Packet..." << endl;
    char packetData [64];
    memset (packetData, 0, sizeof(packetData));

    struct ip * ipHeader = (struct ip*) packetData;
    struct icmphdr * icmpHeader = (struct icmphdr *)(packetData + sizeof(struct ip));

    ipHeader->ip_hl = 5;
    ipHeader->ip_v = 4;
    ipHeader->ip_tos = 0;
    ipHeader->ip_len = sizeof(struct ip) + sizeof(struct icmphdr);
    ipHeader->ip_id = htons(1234);
    ipHeader->ip_off = 0;
    ipHeader->ip_ttl = 64;
    ipHeader->ip_p = IPPROTO_ICMP;
    ipHeader->ip_sum = 0;
    ipHeader->ip_src.s_addr = inet_addr("192.168.1.218");
    ipHeader->ip_dst.s_addr = inet_addr("192.168.1.94");

    icmpHeader->type = ICMP_ECHO;
    icmpHeader->code = 0;
    icmpHeader->checksum = 0;
    icmpHeader->un.echo.id = htons(1234);
    icmpHeader->un.echo.sequence = htons(1);

    unsigned short * buf = (unsigned short*) icmpHeader;
    int len = sizeof(struct icmphdr);
    unsigned int sum = 0;

    while (len >1 )
    {
        sum += *buf;
        buf++;
        len -= 2;

        if ( len == 1)
            sum += *(unsigned char*) buf;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    icmpHeader->checksum = ~sum;
    */

    //Build the packet for injection...

    struct iphdr ipPacket;
    struct icmphdr icmpPacket;

    ipPacket.saddr = inet_addr("192.168.1.218");
    ipPacket.daddr = inet_addr("192.168.1.94");
    ipPacket.protocol = IPPROTO_ICMP;
    ipPacket.tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr);

    icmpPacket.type = ICMP_ECHO;
    icmpPacket.code = 0;
    //Apparently pcap library handles the ICMP checksum calculation upon calling pcap_inject...
    //icmpPacket.checksum = 0;
    //icmpPacket.checksum = calculateChecksum(&icmpPacket, sizeof(struct icmphdr));

    char packet[sizeof(struct iphdr) + sizeof(struct icmphdr)];
    memcpy(packet, &ipPacket, sizeof(struct iphdr));
    memcpy(packet + sizeof(struct iphdr), &icmpPacket, sizeof(struct icmphdr));

    cout << "Injecting the ICMP Packet..." << endl;
    numBytesWritten = pcap_inject (sessionHandle, packet, sizeof(packet));

    if (numBytesWritten == -1)
    {
        cout << "Error injecting the ICMP packet..." << endl;
        returnFlag = -1;
    }

    cout << "Closing the session handle..." << endl;
    pcap_close(sessionHandle);
    return returnFlag;
}

//****************************************************************************************

char getUserChoice()
{
    char choice;
    do
    {
        cin >> choice;

        if ((choice != 'a' && choice != 'A') && (choice != 'q' && choice != 'Q'))
        {
            cout << "Error: Please enter a valid menu option." << endl;
        }
    }
    while ((choice != 'a' && choice != 'A') && (choice != 'q' && choice != 'Q'));

    return choice;
}

//****************************************************************************************

void processUserChoice(char choice)
{
    switch(choice)
    {
        case 'A':
            injectICMPPacket();
            break;
        case 'a':
            injectICMPPacket();
            break;
        case 'Q':
            break;
        case 'q':
            break;
        default:
            break;
    }
}

//****************************************************************************************

void packetHandler (u_char* userData, const struct pcap_pkthdr * pkthdr, const u_char * packet)
{

    //Determine protocol packet is using...
    struct ether_header * ethHeader = (struct ether_header*)packet;

    if (ntohs(ethHeader->ether_type) == ETHERTYPE_IP)
    {
        //IP Packet...
        struct ip* ipHeader = (struct ip*) (packet + sizeof(struct ether_header));

        //Check the IP protocol...
        if ( ipHeader->ip_p == IPPROTO_TCP)
        {
            //TCP Packet
            struct tcphdr * tcpHeader = (struct tcphdr*) (packet + sizeof(struct ether_header) + sizeof(struct ip));
            cout << "Protocol: TCP" << endl;
            //Extract the source ip from the packet...
            struct ip * ip_header = (struct ip *) (packet + 14);
            //Assuming Ethernet header length of 14 bytes.

            char sourceIP [INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip_header->ip_src), sourceIP, INET_ADDRSTRLEN);
            cout << "Source IP: " << sourceIP << endl;
        }
        else if ( ipHeader->ip_p == IPPROTO_UDP)
        {
            //UDP Packet
            struct udphdr * udpHeader = (struct udphdr*) (packet + sizeof(struct ether_header) + sizeof(struct ip));
            cout << "Protocol: UDP" << endl;
            //Extract the source ip from the packet...
            struct ip * ip_header = (struct ip *) (packet + 14);
            //Assuming Ethernet header length of 14 bytes.

            char sourceIP [INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip_header->ip_src), sourceIP, INET_ADDRSTRLEN);
            cout << "Source IP: " << sourceIP << endl;
        }
        else if ( ipHeader->ip_p == IPPROTO_ICMP)
        {
            //TCP Packet
            struct icmphdr * icmpHeader = (struct icmphdr*) (packet + sizeof(struct ether_header) + sizeof(struct ip));
            cout << "Protocol: ICMP" << endl;

            //Extract the source ip from the packet...
            struct ip * ip_header = (struct ip *) (packet + 14);
            //Assuming Ethernet header length of 14 bytes.

            char sourceIP [INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip_header->ip_src), sourceIP, INET_ADDRSTRLEN);
            cout << "Source IP: " << sourceIP << endl;
            cout << "ICMP Packet found! Stopping the loop..." << endl;
            pcap_breakloop((pcap_t*)userData);
        }
        else
        {
            cout << "Protocol: Unknown" << endl;
        }
    }
    else
    {
        cout << "Protocol: Unknown" << endl;
    }
}

//****************************************************************************************


void myCallback(u_char * useless, const struct pcap_pkthdr *pkthdr, const u_char* myPacket)
{
    cout << "Received a packet..." << endl;
    //cout << "Packet: " << myPacket << endl; This causes so many errors it ain't even funny.
}

//****************************************************************************************


int main()
{
    /*
    pcap_if_t * myDevice;
    char errorMsg[PCAP_ERRBUF_SIZE];

    const void * packetData;
    int deviceFlag;
    int numBytesWritten;

    pcap_t * sessionHandle; //return valuepcap_close(sessionHandle); from pcap_open_live
    pcap_t * listenHandle; //For capturing response packets for example an ICMP Echo response.
    size_t packetLen;
    int numPackets;

    //pcap_lookupdev has been deprecated, use pcap_findalldevs instead.
    //device = pcap_lookupdev(errorMsg);
    cout << "Finding a valid interface for injection..." << endl;
    deviceFlag = pcap_findalldevs(&myDevice, errorMsg);

    if ( deviceFlag != 0 )
    {
        cout << "Could not find default device." << endl;
    }
    else if ( deviceFlag == PCAP_ERROR)
    {
        cout << "Error reading the device list." << endl;
    }

    cout << "Found device named: " << myDevice->name << endl;

    //open the device for injection....this must be run as root (sudo).
    cout << "Opening the device for injection..." << endl;
    sessionHandle = pcap_open_live (myDevice->name, PCAP_ERRBUF_SIZE, 1, 1000, errorMsg);

    if ( sessionHandle == NULL )
    {
        cout << "Could not open the device..." << errorMsg << endl;
    }

    listenHandle = pcap_open_live (myDevice->name, PCAP_ERRBUF_SIZE, 1, 1000, errorMsg);

    if (listenHandle == NULL)
    {
        cout << "Error opening listening device session handle for response capture..." << endl;
        cout << "Closing the listening handle..." << endl;
        pcap_close(listenHandle);
    }
    //Here we will need to filter for ICMP packets to only get the response we want.
    struct bpf_program bpf;
    char filterExp[] = "icmp[0]==0"; //ICMP response type is 0.
    if (pcap_compile(listenHandle, &bpf, filterExp, 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        cout << "Error compiling the filter..." << endl;
        cout << "Closing the listening handle and exiting..." << endl;
        pcap_close(listenHandle);
        return 1;
    }

    if (pcap_setfilter(listenHandle, &bpf) == -1)
    {
        cout << "Error setting the filter..." << endl;
        cout << "Closing the listening handle and exiting..." << endl;
        pcap_close(listenHandle);
        return 1;
    }
    else
    {

        //numPackets = pcap_dispatch(sessionHandle, 1, packetHandler, NULL);

        //pcap_loop is an infinite loop currently...It is not seeing the injected ICMP packet currently...
        //Test "injecting" a packet on the above device name.
        //numPackets = pcap_dispatch(sessionHandle, 1, packetHandler, NULL);
        //pcap_inject returns num of bytes written or -1 on failure.

        cout << "Searching for the ICMP response..." << endl;
        if (pcap_loop(listenHandle, 0, packetHandler, (u_char*)listenHandle) == -1)
        {
            cout << "Error capturing packets..." << endl;
            cout << "Closing the listening handle and exiting..." << endl;
            pcap_close(listenHandle);
            return 1;
        }
    }

    */

    char input;
    do
    {
        printMenu();
        input = getUserChoice();
        processUserChoice(input);
    }
    while (input != 'q' && input != 'Q');

    //cout << "Closing the session handle..." << endl;
    cout << "Goodbye!" << endl;
    //pcap_close(listenHandle);
    //pcap_close(sessionHandle);
    return 0;
}
//****************************************************************************************
