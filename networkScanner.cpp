//****************************************************************************************
//
//    Filename: networkScanner.cpp
//    Author:   Kyle McColgan
//    Date:     4 June 2024
//
//****************************************************************************************

#include <iostream>
#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <cstring>
#include <arpa/inet.h>
#include <algorithm> //For std::reverse()
#include <cstdlib>
using namespace std;

//****************************************************************************************

const int MAX_HOSTS=10;
pcap_t * session;

//****************************************************************************************

// bool isActive(const char * address)
// {
//
// }

//****************************************************************************************

void copyAddr(char (*hostList)[16], const char * source, int index)
{
    int adrLen = strlen(source);
    cout << "Copying " << adrLen << " chars to list at index: " << index << endl;
    strncpy(hostList[index], source, adrLen);
    hostList[index][adrLen] = '\0';
    cout << "\nhostList updated." << endl;
    //cout << "Copied " << adrLen << "chars..." << endl;
    // if(strlen(source) == 16)
    // {
    //     hostList[index][15] = '\0';
    // }
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
    result + ~sum;

    return result;
}

//****************************************************************************************

bool pingSweep( char (&destination)[16])
{
    bool result = false;
    struct ip ipHdr;
    struct icmphdr msgHdr;
    unsigned char myPacket[sizeof(struct ip) + sizeof(struct icmphdr)];
    const u_char * capPacket;
    struct pcap_pkthdr header;

    //Fill in the headers for the echo request...

    //Fill in the IP header...
    ipHdr.ip_hl = 5; //Header length.
    ipHdr.ip_v = 4; //IP version.
    ipHdr.ip_tos = 0; //Type of service
    ipHdr.ip_len = sizeof(struct ip) + sizeof(struct icmphdr); //Total length
    ipHdr.ip_id = htons(54321); //Identification.
    ipHdr.ip_off = 0; //Fragment Offset.
    ipHdr.ip_ttl = 255; //Time to live.
    ipHdr.ip_p = IPPROTO_ICMP; //Protocol (ICMP)
    ipHdr.ip_sum = 0; //Checksum (set to 0 before calculating.)
    ipHdr.ip_src.s_addr = inet_addr("192.168.1.213");
    ipHdr.ip_dst.s_addr = inet_addr(destination);

    //Fill in the ICMP header...
    msgHdr.type = ICMP_ECHO; //ICMP Echo request type.
    msgHdr.code = 0; //Code
    msgHdr.checksum = 0; //Checksum (set to 0 before calculating.)
    msgHdr.un.echo.id = 0; //Identifier.
    msgHdr.un.echo.sequence = 0; //Sequence number.

    //Calculate the checksum for the ICMP header...
    msgHdr.checksum = computeChecksum(&msgHdr, sizeof(msgHdr));

    //Prepare the packet for sending...
    memcpy(myPacket, &ipHdr, sizeof(struct ip));
    memcpy(myPacket + sizeof(struct ip), &msgHdr, sizeof(struct icmphdr));

    //send the packet using pcap_inject...
    if(pcap_inject(session, &myPacket, sizeof(myPacket)) == -1)
    {
        cout << "Error sending packet: " << pcap_geterr(session) << endl;
        result = false;
    }
    else
    {
        cout << "Pinging " << destination << endl;

        capPacket = pcap_next(session, &header);
        struct icmphdr * icmp = (struct icmphdr *)(capPacket + sizeof(struct iphdr));

        if(icmp -> type == ICMP_ECHOREPLY)
        {
            result = true;
        }
    }

    return result;
}

//****************************************************************************************

void getHosts(char (*hostList)[16], int & numHosts)
{
    const char base [] = "192.168.1."; //Correctly initalize the base IP array...
    char destIP[16]; //Enough to hold an IP address in the form xxx.xxx.xxx.xxx
    int hostCount = 0;

    for (int i = 1; i <= 255; i ++)
    {
        //Manually construct the IP address
        strcpy(destIP, base);
        char suffix [4]; //Sufficient for numbers 0-255
        intToCharArray(i, suffix); //Convert integer to string
        //itoa(i, suffix);
        strcat(destIP, suffix);

        if(pingSweep(destIP))
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

    // source[sizeof(source)] = '\0';
    // destination[sizeof(destination)] = '\0';
    // for(int i = 0; i < 16; i++)
    // {
    //     source[i] = sourceIP[i];
    // }
    // source[15] = '\0'; //Add null terminator to ensure string termination...
    //
    // for(int i = 0; i < 16; i++)
    // {
    //     destination[i] = destinationIP[i];
    // }
    // destination[15] = '\0'; //Add null terminator to ensure string termination...
    //cout << "Copied source: " << source << endl;
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
//     while(1)
//     {
//
//     }
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

    openNetworkInterface();
    //capturePackets(hostList, MAX_HOSTS, numHosts);
    //Further processing and analysis...
    //displayHostList(hostList, numHosts);
    getHosts(hostList, numHosts);
    displayHostList(hostList, numHosts);
    pcap_close(session);
    return 0;
}

//****************************************************************************************

/*
g++ networkScanner.cpp -lpcap -o networkScanner
hostRecon> sudo ./networkScanner

***Opening session...
Pinging 192.168.1.1
Pinging 192.168.1.2
Pinging 192.168.1.3
Pinging 192.168.1.4
Pinging 192.168.1.5
Copying 11 chars to list at index: 0

hostList updated.

After copy: 192.168.1.5
Pinging 192.168.1.6
Pinging 192.168.1.7
Pinging 192.168.1.8
Pinging 192.168.1.9
Pinging 192.168.1.10
Pinging 192.168.1.11
Pinging 192.168.1.12
Pinging 192.168.1.13
Pinging 192.168.1.14
Pinging 192.168.1.15
Pinging 192.168.1.16
Pinging 192.168.1.17
Pinging 192.168.1.18
Pinging 192.168.1.19
Pinging 192.168.1.20
Pinging 192.168.1.21
Pinging 192.168.1.22
Pinging 192.168.1.23
Pinging 192.168.1.24
Pinging 192.168.1.25
Pinging 192.168.1.26
Pinging 192.168.1.27
Pinging 192.168.1.28
Pinging 192.168.1.29
Pinging 192.168.1.30
Pinging 192.168.1.31
Pinging 192.168.1.32
Pinging 192.168.1.33
Pinging 192.168.1.34
Pinging 192.168.1.35
Pinging 192.168.1.36
Pinging 192.168.1.37
Pinging 192.168.1.38
Pinging 192.168.1.39
Pinging 192.168.1.40
Pinging 192.168.1.41
Pinging 192.168.1.42
Pinging 192.168.1.43
Pinging 192.168.1.44
Pinging 192.168.1.45
Pinging 192.168.1.46
Pinging 192.168.1.47
Pinging 192.168.1.48
Pinging 192.168.1.49
Pinging 192.168.1.50
Pinging 192.168.1.51
Pinging 192.168.1.52
Pinging 192.168.1.53
Pinging 192.168.1.54
Pinging 192.168.1.55
Pinging 192.168.1.56
Pinging 192.168.1.57
Pinging 192.168.1.58
Pinging 192.168.1.59
Pinging 192.168.1.60
Pinging 192.168.1.61
Pinging 192.168.1.62
Pinging 192.168.1.63
Pinging 192.168.1.64
Pinging 192.168.1.65
Pinging 192.168.1.66
Pinging 192.168.1.67
Pinging 192.168.1.68
Pinging 192.168.1.69
Pinging 192.168.1.70
Pinging 192.168.1.71
Pinging 192.168.1.72
Pinging 192.168.1.73
Pinging 192.168.1.74
Pinging 192.168.1.75
Pinging 192.168.1.76
Pinging 192.168.1.77
Pinging 192.168.1.78
Pinging 192.168.1.79
Pinging 192.168.1.80
Pinging 192.168.1.81
Pinging 192.168.1.82
Pinging 192.168.1.83
Pinging 192.168.1.84
Pinging 192.168.1.85
Pinging 192.168.1.86
Pinging 192.168.1.87
Pinging 192.168.1.88
Pinging 192.168.1.89
Pinging 192.168.1.90
Pinging 192.168.1.91
Pinging 192.168.1.92
Pinging 192.168.1.93
Pinging 192.168.1.94
Pinging 192.168.1.95
Pinging 192.168.1.96
Pinging 192.168.1.97
Pinging 192.168.1.98
Pinging 192.168.1.99
Pinging 192.168.1.100
Pinging 192.168.1.101
Pinging 192.168.1.102
Pinging 192.168.1.103
Pinging 192.168.1.104
Pinging 192.168.1.105
Pinging 192.168.1.106
Pinging 192.168.1.107
Pinging 192.168.1.108
Pinging 192.168.1.109
Pinging 192.168.1.110
Pinging 192.168.1.111
Pinging 192.168.1.112
Pinging 192.168.1.113
Pinging 192.168.1.114
Pinging 192.168.1.115
Pinging 192.168.1.116
Pinging 192.168.1.117
Pinging 192.168.1.118
Pinging 192.168.1.119
Pinging 192.168.1.120
Pinging 192.168.1.121
Pinging 192.168.1.122
Pinging 192.168.1.123
Pinging 192.168.1.124
Pinging 192.168.1.125
Copying 13 chars to list at index: 1

hostList updated.

After copy: 192.168.1.125
Pinging 192.168.1.126
Pinging 192.168.1.127
Pinging 192.168.1.128
Pinging 192.168.1.129
Pinging 192.168.1.130
Pinging 192.168.1.131
Pinging 192.168.1.132
Pinging 192.168.1.133
Pinging 192.168.1.134
Pinging 192.168.1.135
Pinging 192.168.1.136
Pinging 192.168.1.137
Pinging 192.168.1.138
Pinging 192.168.1.139
Pinging 192.168.1.140
Pinging 192.168.1.141
Pinging 192.168.1.142
Copying 13 chars to list at index: 2

hostList updated.

After copy: 192.168.1.142
Pinging 192.168.1.143
Pinging 192.168.1.144
Pinging 192.168.1.145
Pinging 192.168.1.146
Pinging 192.168.1.147
Pinging 192.168.1.148
Pinging 192.168.1.149
Pinging 192.168.1.150
Pinging 192.168.1.151
Pinging 192.168.1.152
Pinging 192.168.1.153
Pinging 192.168.1.154
Pinging 192.168.1.155
Pinging 192.168.1.156
Pinging 192.168.1.157
Pinging 192.168.1.158
Pinging 192.168.1.159
Pinging 192.168.1.160
Pinging 192.168.1.161
Copying 13 chars to list at index: 3

hostList updated.

After copy: 192.168.1.161
Pinging 192.168.1.162
Pinging 192.168.1.163
Pinging 192.168.1.164
Pinging 192.168.1.165
Pinging 192.168.1.166
Pinging 192.168.1.167
Pinging 192.168.1.168
Pinging 192.168.1.169
Pinging 192.168.1.170
Pinging 192.168.1.171
Pinging 192.168.1.172
Pinging 192.168.1.173
Pinging 192.168.1.174
Pinging 192.168.1.175
Pinging 192.168.1.176
Pinging 192.168.1.177
Pinging 192.168.1.178
Pinging 192.168.1.179
Pinging 192.168.1.180
Pinging 192.168.1.181
Pinging 192.168.1.182
Pinging 192.168.1.183
Pinging 192.168.1.184
Pinging 192.168.1.185
Pinging 192.168.1.186
Pinging 192.168.1.187
Pinging 192.168.1.188
Pinging 192.168.1.189
Pinging 192.168.1.190
Pinging 192.168.1.191
Pinging 192.168.1.192
Pinging 192.168.1.193
Pinging 192.168.1.194
Pinging 192.168.1.195
Pinging 192.168.1.196
Pinging 192.168.1.197
Pinging 192.168.1.198
Pinging 192.168.1.199
Pinging 192.168.1.200
Pinging 192.168.1.201
Pinging 192.168.1.202
Pinging 192.168.1.203
Pinging 192.168.1.204
Pinging 192.168.1.205
Pinging 192.168.1.206
Pinging 192.168.1.207
Pinging 192.168.1.208
Pinging 192.168.1.209
Pinging 192.168.1.210
Pinging 192.168.1.211
Pinging 192.168.1.212
Pinging 192.168.1.213
Pinging 192.168.1.214
Pinging 192.168.1.215
Pinging 192.168.1.216
Pinging 192.168.1.217
Pinging 192.168.1.218
Copying 13 chars to list at index: 4

hostList updated.

After copy: 192.168.1.218
Pinging 192.168.1.219
Pinging 192.168.1.220
Pinging 192.168.1.221
Pinging 192.168.1.222
Pinging 192.168.1.223
Pinging 192.168.1.224
Pinging 192.168.1.225
Copying 13 chars to list at index: 5

hostList updated.

After copy: 192.168.1.225
Pinging 192.168.1.226
Pinging 192.168.1.227
Pinging 192.168.1.228
Pinging 192.168.1.229
Pinging 192.168.1.230
Pinging 192.168.1.231
Pinging 192.168.1.232
Pinging 192.168.1.233
Pinging 192.168.1.234
Pinging 192.168.1.235
Pinging 192.168.1.236
Pinging 192.168.1.237
Pinging 192.168.1.238
Pinging 192.168.1.239
Pinging 192.168.1.240
Pinging 192.168.1.241
Pinging 192.168.1.242
Pinging 192.168.1.243
Pinging 192.168.1.244
Pinging 192.168.1.245
Pinging 192.168.1.246
Pinging 192.168.1.247
Pinging 192.168.1.248
Pinging 192.168.1.249
Pinging 192.168.1.250
Pinging 192.168.1.251
Pinging 192.168.1.252
Pinging 192.168.1.253
Pinging 192.168.1.254
Pinging 192.168.1.255


Printing list with 6 hosts included.
*****************************************
Host 1: 192.168.1.5
Host 2: 192.168.1.125
Host 3: 192.168.1.142
Host 4: 192.168.1.161
Host 5: 192.168.1.218
Host 6: 192.168.1.225

*****************************************

Done.

*/
