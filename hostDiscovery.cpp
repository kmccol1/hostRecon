//****************************************************************************************
//
//    Filename:    hostDiscovery.cpp
//    Date:        3 January 2024
//    Author:      Kyle McColgan
//    Description: This program performs an ICMP Echo request using the libpcap library.
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
#include <sys/socket.h>
#include <unistd.h>
#include <sys/time.h>
using namespace std;

#define PACKET_SIZE 64
#define BUFFER_SIZE 1024

//****************************************************************************************

void printMenu()
{
    cout << "\n----------MENU----------" << endl;
    cout << "A....Inject an ICMP packet onto the network using pcap." << endl;
    cout << "R....Inject an ICMP packet onto the network using a raw socket." << endl;
    cout << "Q....Quit and close any remaining open sessions." << endl;
    cout << "\nPlease input the letter of your selection from the menu: ";
}

//****************************************************************************************

int sendRawPacket(int mySocketFlag)
{
    //Must be root SUID(0) for raw socket opening and sending.
    int successFlag = 1;

    //Create the ICMP Packet
    char packet [PACKET_SIZE];

    memset(packet,0,PACKET_SIZE);

    struct icmphdr *icmp_header = (struct icmphdr*) (packet);
    icmp_header->type = ICMP_ECHO;
    icmp_header->code = 0;
    icmp_header->checksum=0;
    icmp_header->un.echo.id=htons(4321);
    icmp_header->un.echo.sequence=0;

    //Set the destination IP address
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    //dest_addr.sin_port=0;
    //Use same port number as receiveRawPacket() below...
    dest_addr.sin_port=htons(1234);

    if (inet_pton(AF_INET, "192.168.1.94", &(dest_addr.sin_addr)) <= 0 )
    {
        cout << "inet_pton() failed..." << endl;
        successFlag = 0;
    }

    //Send the ICMP Packet
    if ( sendto(mySocketFlag, packet, PACKET_SIZE, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0)
    {
        cout << "Error: Socket sending failed..." << endl;
        successFlag = 0;
    }

    cout << "ICMP Packet sent successfully!" << endl;

    return successFlag;
}

//****************************************************************************************

int receiveRawPacket(int mySocketFlag)
{
    //Must be root SUID(0) for raw socket opening and sending.
    int successFlag = 1;
    //int mySocketFlag;

    struct sockaddr_in server_addr,client_addr;
    char buffer [BUFFER_SIZE];
    ssize_t numBytes;

    //Bind socket to addr and port
    server_addr.sin_family = AF_INET;
    //server_addr.sin_addr.s_addr= INADDR_ANY;
    //Bind correctly below....
    server_addr.sin_addr.s_addr= inet_addr("192.168.1.218");
    server_addr.sin_port =htons(1234);

    cout << "Binding socket..." << endl;

    if (bind(mySocketFlag, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        cout << "Error: Socket binding failed..." << endl;
        successFlag = 0;
    }
    else
    {
        cout << "Socket binded successfully!" << endl;
    }

    //Set the receive timeout here...need to loop send until a response is received???
    struct timeval timeout;
    timeout.tv_sec = 5; //5 second timeout...
    timeout.tv_usec = 0;

    if (setsockopt(mySocketFlag, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) < 0)
    {
        cout << "Setting socket options failed...." << endl;
    }

    //Receieve a single ICMP response
    socklen_t client_addr_len = sizeof(client_addr);
    successFlag = sendRawPacket(mySocketFlag);
    cout << "Getting the response..." << endl;
    numBytes = recvfrom(mySocketFlag, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &client_addr_len);
    cout << "Captured a response..." << endl;
    if(numBytes < 0)
    {
        cout << "Error: Socket recieving failed..." << endl;
        successFlag = 0;
    }

    //Extract the reply address
    char client_ip [INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
    int client_port = ntohs(client_addr.sin_port);

    //Process the received packet
    cout << "Received packet from: " << client_ip << " on port #" << client_port << endl;
    cout << "Packet contents: " << int(numBytes) << buffer << endl;



    return successFlag;
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

        if ((choice != 'a' && choice != 'A') && (choice != 'r' && choice != 'R') \
         && (choice != 'q' && choice != 'Q'))
        {
            cout << "Error: Please enter a valid menu option." << endl;
        }
    }
    while ((choice != 'a' && choice != 'A') && (choice != 'r' && choice != 'R') \
        && (choice != 'q' && choice != 'Q'));

    return choice;
}

//****************************************************************************************

void processUserChoice(int mySocketFlag, char choice)
{
    switch(choice)
    {
        case 'A':
            injectICMPPacket();
            break;
        case 'a':
            injectICMPPacket();
            break;
        case 'R':
            //if ( sendRawPacket(mySocketFlag) == 1)
            if ( receiveRawPacket(mySocketFlag) == 1)
                cout << "Successfully pinged!" << endl;
            else
                cout << "Error during ping..." << endl;
            break;
        case 'r':
            //if ( sendRawPacket(mySocketFlag) == 1)
            if ( receiveRawPacket(mySocketFlag) == 1)
                cout << "Successfully pinged!" << endl;
            else
                cout << "Error during ping..." << endl;
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
    char input;
    int mySocketFlag;

    mySocketFlag = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if ( mySocketFlag < 0 )
    {
        cout << "Error: Socket creation failed..." << endl;
        //successFlag = 0;
    }

    do
    {
        printMenu();
        input = getUserChoice();
        processUserChoice(mySocketFlag, input);
    }
    while (input != 'q' && input != 'Q');

    cout << "Goodbye!" << endl;

    //Close the socket
    close(mySocketFlag);

    return 0;
}
//****************************************************************************************

/*
----------MENU----------
A....Inject an ICMP packet onto the network using pcap.
R....Inject an ICMP packet onto the network using a raw socket.
Q....Quit and close any remaining open sessions.

Please input the letter of your selection from the menu: A
Finding a valid interface for injection...
Found device named: enp34s0
Opening the device for injection...
Injecting the ICMP Packet...
Closing the session handle...

----------MENU----------
A....Inject an ICMP packet onto the network using pcap.
R....Inject an ICMP packet onto the network using a raw socket.
Q....Quit and close any remaining open sessions.

Please input the letter of your selection from the menu: R
Binding socket...
Socket binded successfully!
ICMP Packet sent successfully!
Getting the response...
^X^C
*/



