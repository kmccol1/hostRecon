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
#include <cstring>
#include <arpa/inet.h>
using namespace std;

//****************************************************************************************

const int MAX_HOSTS=10;
pcap_t * session;

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

    cout << "\n***Capturing packets..." << endl;
    //while (true)
    //while(totalPackets < numPackets)
    //while(hostListSize < totalHosts)
    while(/*(hostList[numEntries][0] != '\0') && */ numEntries < MAX_HOSTS)
    {
        cout << "\n*****************************************" << endl;
        packet = pcap_next(session, &header);
        if(packet == NULL)
        {
            continue;
        }
        totalPackets++;
        //cout << "\ntotal packets: " << totalPackets << endl;

        extractDeviceInfo(packet, source, destination);
        cout << "\nCaptured source info: " << source
             << "..." << strlen(source) << " chars." << endl;

        //Convert the source IP from ASCII to dotted-decimal format...
        // inet_ntop(AF_INET, source, ipStr, INET_ADDRSTRLEN);
        // cout << "Converted source info: " << source
        //      << "..." << strlen(ipStr) << " chars." << endl;

        //Update the hostList char array...

        //if((isValidIPAddress(ipStr)) && (nextSlot < MAX_HOSTS))
        if((numEntries < MAX_HOSTS) && (isValidIPAddress(source) == true) && (!inList(source, hostList, nextSlot)))
        //if((nextSlot < MAX_HOSTS))
        {
            // cout << "Updating list with: " << ipStr << endl;
            // filterSpecialChars(ipStr, filteredIP);

            //cout << "\nBefore Copy: " << hostList[nextSlot] << endl; spec. chars...
            copyAddr(hostList, source, numEntries); //numHosts or nextSlot...???
            cout << "\nAfter copy: " << hostList[numEntries] << endl;

            nextSlot++; //Increment the nextSlot for the next update...
            numHosts++;
            numEntries++;
        }
        else if(inList(source, hostList, nextSlot))
        {
            cout << "Duplicate entry found. Skipping..." << endl;
            continue;
        }
        else
        {
            //Handle the case when the hostList is full...
            cout << "Host list is full. Cannot add more hosts." << endl;
            //numHosts = nextSlot;
            //numHosts = hostListSize;
            //displayHostList(hostList, numHosts);
            break;
        }
    }
}

//****************************************************************************************

int main()
{

    char hostList[MAX_HOSTS][16]; //Assuming each IP addr is stored in a 16-character array.
    int numHosts = 0;

    openNetworkInterface();
    capturePackets(hostList, MAX_HOSTS, numHosts);
    //Further processing and analysis...
    displayHostList(hostList, numHosts);
    pcap_close(session);
    return 0;
}

//****************************************************************************************

/*
g++ networkScanner.cpp -lpcap -o networkScanner
hostRecon> sudo ./networkScanner
[sudo] password for root:

***Opening session...

***Capturing packets...

*****************************************

Captured source info: 211.122.206.83...14 chars.
Copying 14 chars to list at index: 0

hostList updated.

After copy: 211.122.206.83

*****************************************

Captured source info: 142.32.34.241...13 chars.
Copying 13 chars to list at index: 1

hostList updated.

After copy: 142.32.34.241

*****************************************

Captured source info: 167.208.92.32...13 chars.
Copying 13 chars to list at index: 2

hostList updated.

After copy: 167.208.92.32

*****************************************

Captured source info: 64.2.12.27...10 chars.
Copying 10 chars to list at index: 3

hostList updated.

After copy: 64.2.12.27

*****************************************

Captured source info: 29.15.1.10...10 chars.
Copying 10 chars to list at index: 4

hostList updated.

After copy: 29.15.1.10


Printing list with 5 hosts included.
*****************************************
Host 1: 211.122.206.83
Host 2: 142.32.34.241
Host 3: 167.208.92.32
Host 4: 64.2.12.27
Host 5: 29.15.1.10

*****************************************

Done.

*/
