//****************************************************************************************
//
//    Filename: networkScanner.cpp
//    Author:   Kyle McColgan
//    Date:     17 June 2024
//    Description: CLI based networking utility for preliminary network reconnaissance.
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
pcap_t * session;

//****************************************************************************************

//Ethernet header structure
struct CaptureContext
{
    pcap_t * captureSession;
    bool & result;
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

    struct ip * ipHeader = (struct ip *)(capPacket + 14); //Skip Ethernet header...

    if(ipHeader->ip_p == IPPROTO_ICMP)
    {
        struct icmphdr * icmpHeader = (struct icmphdr *)(capPacket + 14 + (ipHeader->ip_hl << 2)); //Skip IP header...

        cout << "ICMP type: " << static_cast<int>(icmpHeader->type) << endl;

        if(icmpHeader->type ==ICMP_ECHOREPLY)
        {
            cout <<"Received ICMP ECHO Reply packet..." << endl;
            context->result = true;
            pcap_breakloop(context->captureSession);
            //return;
        }
        else if (icmpHeader->type ==ICMP_DEST_UNREACH)
        {
            cout <<"Received ICMP DEST UNREACH packet..." << endl;
            context->result = false;
            pcap_breakloop(context->captureSession);
            //return;
        }
        else if (icmpHeader->type ==ICMP_TIME_EXCEEDED)
        {
            cout <<"Received ICMP TIME EXCEEDED packet..." << endl;
            context->result = false;
            pcap_breakloop(context->captureSession);
            //return;
        }
        else
        {
            cout << "Unknown response type. Skipping..." << endl;
            context->result = false;
            pcap_breakloop(context->captureSession);
            //return;
        }
    }
    else
    {
        // context->result = false;
        // pcap_breakloop(context->captureSession);
        // return;
        cout << "Not an ICMP packet. Skipping..." << endl;
    }
}

//****************************************************************************************

bool pingSweep( char (&destination)[16], pcap_t * sendSession, pcap_t * captureSession)
{
    bool result = false;
    struct ip ipHdr;
    struct icmphdr msgHdr;
    unsigned char myPacket[sizeof(struct ip) + sizeof(struct icmphdr)];
    const u_char * capPacket;
    struct pcap_pkthdr header;
    // pcap_t * captureSession;
    // pcap_t * sendSession;
    bool responseCaptured = false;
    int timeout = 1000; //Timeout value in milliseconds.

    CaptureContext context{captureSession, result};

    //Open sendSession
    // char errorMsg [PCAP_ERRBUF_SIZE];
    // //cout << "\n***Opening session..." << endl;
    // sendSession = pcap_open_live("enp34s0", BUFSIZ, 1, 1000, errorMsg);
    //
    // if(sendSession == NULL)
    // {
    //     cout << "Error opening the NIC for injection: " << errorMsg << endl;
    // }
    //

    char errorMsg [PCAP_ERRBUF_SIZE];
    //cout << "\n***Opening session..." << endl;
    context.captureSession = pcap_open_live("enp34s0", BUFSIZ, 1, 1000, errorMsg);

    if(context.captureSession == NULL)
    {
        cout << "Error opening the NIC for capture: " << errorMsg << endl;
    }

    // //Set the filter for ICMP packets
    struct bpf_program filter;
    bpf_u_int32 net;
    char filterExp[] = "icmp";
    pcap_compile(context.captureSession, &filter, filterExp, 0, net);
    pcap_setfilter(context.captureSession, &filter);

    //Fill in the headers for the echo request...

    //Fill in the IP header...
    memset(&ipHdr, 0, sizeof(ipHdr));
    ipHdr.ip_hl = 5; //Header length.
    ipHdr.ip_v = 4; //IP version.
    ipHdr.ip_tos = 0; //Type of service
    ipHdr.ip_len = htons(sizeof(struct ip)) + sizeof(struct icmphdr); //Total length
    ipHdr.ip_id = htons(54321); //Identification.
    ipHdr.ip_off = 0; //Fragment Offset.
    ipHdr.ip_ttl = 255; //Time to live.
    ipHdr.ip_p = IPPROTO_ICMP; //Protocol (ICMP)
    ipHdr.ip_sum = 0; //Checksum (set to 0 before calculating.)
    ipHdr.ip_src.s_addr = inet_addr("192.168.1.213");
    ipHdr.ip_dst.s_addr = inet_addr(destination);

    //Calculate the checksum for the IP header...
    ipHdr.ip_sum = computeChecksum((unsigned short *)&ipHdr, sizeof(struct ip));

    //Fill in the ICMP header...
    memset(&msgHdr, 0, sizeof(msgHdr));
    msgHdr.type = ICMP_ECHO; //ICMP Echo request type.
    msgHdr.code = 0; //Code
    msgHdr.checksum = 0; //Checksum (set to 0 before calculating.)
    msgHdr.un.echo.id = htons(1234); //Identifier.
    msgHdr.un.echo.sequence = htons(1); //Sequence number.

    //Calculate the checksum for the ICMP header...
    msgHdr.checksum = computeChecksum((unsigned short *)&msgHdr, sizeof(struct icmphdr));

    //Combine headers into one packet...
    memcpy(myPacket, &ipHdr, sizeof(struct ip));
    memcpy(myPacket + sizeof(struct ip), &msgHdr, sizeof(struct icmphdr));

    //send the packet using pcap_inject...
    cout << "\n***Pinging " << destination << "..." << endl;
    if(pcap_inject(sendSession, &myPacket, sizeof(myPacket)) == -1)
    {
        cout << "Error sending the packet: " << pcap_geterr(sendSession) << endl;
        result = false;
    }

    //Set the timeout...
    //this_thread::sleep_for(chrono::seconds(1));
    if(pcap_set_timeout(context.captureSession, timeout) == -1)
    {
        cout << "Error setting the time out variable: " << pcap_geterr(context.captureSession) << endl;
    }

    // //Lambda..
    // pcap_handler callback = [&context](u_char * user, const struct pcap_pkthdr * pkthdr, const u_char * capPacket) -> void
    // {
    //     auto context = reinterpret_cast<CaptureContext*>(user);
    //
    //     struct ip * ipHeader = (struct ip *)(capPacket + 14); //Skip Ethernet header...
    //
    //     if(ipHeader->ip_p == IPPROTO_ICMP)
    //     {
    //         struct icmphdr * icmpHeader = (struct icmphdr *)(capPacket + 14 + (ipHeader->ip_hl << 2)); //Skip IP header...
    //
    //         cout << "ICMP type: " << static_cast<int>(icmpHeader->type) << endl;
    //
    //         if(icmpHeader->type ==ICMP_ECHOREPLY)
    //         {
    //             cout <<"Received ICMP ECHO Reply packet..." << endl;
    //             result = true;
    //             pcap_breakloop(context);
    //             //break;
    //             return;
    //         }
    //         else if (icmpHeader->type ==ICMP_DEST_UNREACH)
    //         {
    //             cout <<"Received ICMP DEST UNREACH packet..." << endl;
    //             result = false;
    //             pcap_breakloop(context);
    //             //break;
    //             return;
    //         }
    //         else if (icmpHeader->type ==ICMP_TIME_EXCEEDED)
    //         {
    //             cout <<"Received ICMP TIME EXCEEDED packet..." << endl;
    //             result = false;
    //             pcap_breakloop(context);
    //             //break;
    //             return;
    //         }
    //         else
    //         {
    //             cout << "Unknown response type. Skipping..." << endl;
    //             result = false;
    //             pcap_breakloop(context);
    //             //break;
    //             return;
    //         }
    //         // cout << "ICMP type: " << static_cast<int>(icmpHeader->type) << endl;
    //         result = false;
    //         pcap_breakloop(captureSession);
    //         return;
    //     }
    //     else
    //     {
    //         result = false;
    //         pcap_breakloop(captureSession);
    //         return;
    //     }
    // };

    if(pcap_loop(context.captureSession, 0, callBack, reinterpret_cast<u_char *>(&context)) == -1)
    {
        cout << "Error in pcap_loop(): " << pcap_geterr(context.captureSession) << endl;
        result = false;
    }

    //Capture the response packet using pcap_next()...

    // while(!responseCaptured)
    // {
        // if(pcap_inject(sendSession, &myPacket, sizeof(myPacket)) == -1)
        // {
        //     cout << "Error sending the packet: " << pcap_geterr(sendSession) << endl;
        //     result = false;
        // }
        //else
        //{
        // if(pcap_set_timeout(captureSession, timeout) == -1)
        // {
        //     cout << "Error setting the time out variable: " << pcap_geterr(captureSession) << endl;
        // }
        // capPacket = pcap_next(captureSession, &header);
        // //}
        //
        // if (capPacket == nullptr)
        // {
        //     cout << "No packet captured." << endl;
        //     continue;
        // }

        // struct ip * ipHeader = (struct ip *)(capPacket + 14); //Skip Ethernet header...
        // if(ipHeader->ip_p == IPPROTO_ICMP)
        // {
        //     struct icmphdr * icmpHeader = (struct icmphdr *)(capPacket + 14 + (ipHeader->ip_hl << 2)); //Skip IP header...
        //
        //     cout << "ICMP type: " << static_cast<int>(icmpHeader->type) << endl;
        //
        //     if(icmpHeader->type ==ICMP_ECHOREPLY)
        //     {
        //         cout <<"Received ICMP ECHO Reply packet..." << endl;
        //         responseCaptured = true;
        //         result = true;
        //         break;
        //     }
        //     else if (icmpHeader->type ==ICMP_DEST_UNREACH)
        //     {
        //         cout <<"Received ICMP DEST UNREACH packet..." << endl;
        //         responseCaptured = true;
        //         result = false;
        //         break;
        //     }
        //     else if (icmpHeader->type ==ICMP_TIME_EXCEEDED)
        //     {
        //         cout <<"Received ICMP TIME EXCEEDED packet..." << endl;
        //         responseCaptured = true;
        //         result = false;
        //         break;
        //     }
        //     else
        //     {
        //         cout << "Unknown response type. Skipping..." << endl;
        //         responseCaptured = true;
        //         result = false;
        //         break;
        //     }
        //     // cout << "ICMP type: " << static_cast<int>(icmpHeader->type) << endl;
        // }
    //}

    //else
    //{
        //Check if it's an ICMP Echo Reply (type 0)
        //struct ip * recvIPHdr = (struct ip *)(capPacket);
        //const struct icmphdr * recvICMPHdr = (struct icmphdr *)(capPacket + sizeof(struct icmphdr) + sizeof(struct iphdr));


        // const struct ethhdr * ethernetHeader;
        // const struct iphdr * ipHeader;
        // const struct icmphdr * icmpHeader;
        //
        // ethernetHeader = (ethhdr *)capPacket;
        // ipHeader = (iphdr *)(capPacket + sizeof(ethhdr));
        // icmpHeader = (icmphdr *)(capPacket + sizeof(ethhdr) + sizeof(iphdr));
        //
        // cout << "ICMP type: " << static_cast<int>(icmpHeader->type) << endl;

        // if(ipHeader->protocol == IPPROTO_ICMP && icmpHeader->type == 0)
        // {
        //     cout << "Received ICMP Echo Reply from: " << destination << endl;
        //     result = true;
        // }
        // // else if(recvICMPHdr -> type == ICMP_DEST_UNREACH)
        // // {
        // //     cout << "Received ICMP Dest Unreachable from: " << destination << endl;
        // // }
        // // else if(recvICMPHdr -> type == ICMP_TIME_EXCEEDED)
        // // {
        // //     cout << "Received ICMP Time Exceeded from: " << destination << endl;
        // // }
        // else if(ipHeader->protocol == IPPROTO_ICMP && icmpHeader->type == 8)
        // {
        //     cout << "\n***Received ICMP type 8!" << endl;
        // }
        // else
        // {
        //     cout << "Received ICMP type: " << (int)icmpHeader->type << endl;
        // }
    //}

    pcap_close(context.captureSession);
    // pcap_close(sendSession);
    return result;
}

//****************************************************************************************

void getHosts(char (*hostList)[16], int & numHosts, pcap_t * captureSession)
{
    const char base [] = "192.168.1."; //Correctly initalize the base IP array...
    char destIP[16]; //Enough to hold an IP address in the form xxx.xxx.xxx.xxx
    int hostCount = 0;

    //pcap_t * captureSession;
    pcap_t * sendSession;
    bool result = false;

    CaptureContext context{captureSession, result};

    char errorMsg [PCAP_ERRBUF_SIZE];
    //cout << "\n***Opening session..." << endl;
    sendSession = pcap_open_live("enp34s0", BUFSIZ, 1, 1000, errorMsg);

    if(sendSession == NULL)
    {
        cout << "Error opening the NIC for injection: " << errorMsg << endl;
    }

    //char errorMsg [PCAP_ERRBUF_SIZE];
    //cout << "\n***Opening session..." << endl;


    for (int i = 90; i <= 95; i ++)
    {
        //Manually construct the IP address
        strcpy(destIP, base);
        char suffix [4]; //Sufficient for numbers 0-255
        intToCharArray(i, suffix); //Convert integer to string
        //itoa(i, suffix);
        strcat(destIP, suffix);

        if(pingSweep(destIP, sendSession, context.captureSession))
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

    //pcap_close(context.captureSession);
    pcap_close(sendSession);
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
        // if(*address == '.')
        // {
        //     if( (num < 0 ) || (num > 255))
        //     {
        //         result = false;
        //     }
        //     num=0;
        //     dots ++;
        // }
        // else if(*address >= '0' && *address <= '9')
        // {
        //     num = num * 10 + (*address - '0');
        // }
        // else
        // {
        //     result = false; //Return false if a non-numeric character is found.
        // }

        if(*address == '.')
        {
            numDots ++;
            if ((numDigits < 1) || (numDigits > 3))
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
        //for (int i = 0; i < 16; ++ i)
        //{
        //if(hostList[i][0] != '\0')
        //{
        cout << "Host " << i+1 << ": " << hostList[i] << endl;
        //}
        //}
        //cout << endl;
        //cout << "Host " << i+1 << ": " << hostList[i] << endl;
    }
    cout << "\n*****************************************" << endl;
    cout << "\nDone." << endl;
}

//****************************************************************************************

void openNetworkInterface()
{
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

void capturePackets(char (*hostList)[16], int maxLength, int & numHosts)
{
    int totalPackets;
    struct pcap_pkthdr header;
    const u_char * packet;
    int numEntries = 0;
    char source[16];
    char destination[16];
    int hostListSize = sizeof(hostList) / sizeof(hostList[0]);
    int nextSlot = 0;
    char ipStr[INET_ADDRSTRLEN]; //Define a buffer to store the converted IP addr...
    char filteredIP[16];

    while ( (hostList[nextSlot][0] != '\0') && (numEntries < MAX_HOSTS))
    {
        //numHosts = nextSlot;
        nextSlot++;
    }

//     cout << "\n***Capturing packets..." << endl;
//

    //while (true)
    //while(totalPackets < numPackets)
    //while(hostListSize < totalHosts)
    // while(/*(hostList[numEntries][0] != '\0') && */ numEntries < MAX_HOSTS)
    // {
    //     cout << "\n*****************************************" << endl;
    //     packet = pcap_next(session, &header);
    //     if(packet == NULL)
    //     {
    //         continue;
    //     }
    //     totalPackets++;
    //     //cout << "\ntotal packets: " << totalPackets << endl;
    //
    //     extractDeviceInfo(packet, source, destination);
    //     cout << "\nCaptured source info: " << source
    //          << "..." << strlen(source) << " chars." << endl;
    //
    //     //Convert the source IP from ASCII to dotted-decimal format...
    //     // inet_ntop(AF_INET, source, ipStr, INET_ADDRSTRLEN);
    //     // cout << "Converted source info: " << source
    //     //      << "..." << strlen(ipStr) << " chars." << endl;
    //
    //     //Update the hostList char array...
    //
    //     //if((isValidIPAddress(ipStr)) && (nextSlot < MAX_HOSTS))
    //     if((numEntries < MAX_HOSTS) && (isValidIPAddress(source) == true) && (!inList(source, hostList, nextSlot)))
    //     //if((nextSlot < MAX_HOSTS))
    //     {
    //         // cout << "Updating list with: " << ipStr << endl;
    //         // filterSpecialChars(ipStr, filteredIP);
    //
    //         //cout << "\nBefore Copy: " << hostList[nextSlot] << endl; spec. chars...
    //         copyAddr(hostList, source, numEntries); //numHosts or nextSlot...???
    //         cout << "\nAfter copy: " << hostList[numEntries] << endl;
    //
    //         nextSlot++; //Increment the nextSlot for the next update...
    //         numHosts++;
    //         numEntries++;
    //     }
    //     else if(inList(source, hostList, nextSlot))
    //     {
    //         cout << "Duplicate entry found. Skipping..." << endl;
    //         continue;
    //     }
    //     else
    //     {
    //         //Handle the case when the hostList is full...
    //         cout << "Host list is full. Cannot add more hosts." << endl;
    //         //numHosts = nextSlot;
    //         //numHosts = hostListSize;
    //         //displayHostList(hostList, numHosts);
    //         break;
    //     }
    // }
}

//****************************************************************************************

int main()
{

    char hostList[MAX_HOSTS][16]; //Assuming each IP addr is stored in a 16-character array.
    int numHosts = 0;
    char errorMsg [PCAP_ERRBUF_SIZE];
    pcap_t * captureSession = pcap_open_live("enp34s0", BUFSIZ, 1, 1000, errorMsg);
    bool result = false;

    CaptureContext context{captureSession, result};



    getHosts(hostList, numHosts, context.captureSession);
    displayHostList(hostList, numHosts);



    return 0;
}

//****************************************************************************************

/*
g++ networkScanner.cpp -lpcap -o networkScanner
hostRecon> sudo ./networkScanner
*/
