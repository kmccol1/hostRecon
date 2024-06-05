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
char hostList[MAX_HOSTS][16]; //Assuming each IP addr is stored in a 16-character array.

//****************************************************************************************

void displayHostList()
{
    cout << "Printing the host list..." << endl;

    for(int i = 0; i < MAX_HOSTS; i ++ )
    {
        cout << "Host " << i + 1 << ": ";
        for (int j = 0; j < 16; j++)
        {
            cout << hostList[i][j];
        }
        cout << endl;
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

    cout << "Copying..." << endl;
    cout << "Before source: " << sourceIP << endl;
    // strcpy(source, sourceIP);
    // strcpy(destination, destinationIP);
    //

    for(int i = 0; i < 16; i++)
    {
        source[i] = sourceIP[i];
    }
    source[15] = '\0'; //Add null terminator to ensure string termination...

    for(int i = 0; i < 16; i++)
    {
        destination[i] = destinationIP[i];
    }
    destination[15] = '\0'; //Add null terminator to ensure string termination...
    cout << "Copied source: " << source << endl;
}

//****************************************************************************************

void capturePackets()
{
    //Process the captured packet...
    int totalPackets = 0;
    struct pcap_pkthdr header;
    const u_char * packet;
    int totalHosts = 20;
    char source[16];
    char destination[16];
    int hostListSize = sizeof(hostList) / sizeof(hostList[0]);
    //string ipAddr;
    int nextSlot = 0;

    while (nextSlot < MAX_HOSTS && hostList[nextSlot][0] != '\0')
    {
        nextSlot++;
    }

    cout << "\n***Capturing..." << endl;
    //while (true)
    //while(totalPackets < numPackets)
    while(hostListSize < totalHosts)
    {
        packet = pcap_next(session, &header);
        if(packet == NULL)
        {
            continue;
        }
        totalPackets++;
        //cout << "\ntotal packets: " << totalPackets << endl;

        extractDeviceInfo(packet, source, destination);
        cout << "Captured source info: " << source << endl;

        //string ipAddr(source);
        // char ipFormatted[16];
        // int ipParts[4];
        // sscanf(source, "%d.%d.%d.%d", &ipParts[0]);
        // sprintf(ipFormatted, "%d.%d.%d.%d", ipParts[0], ipParts[1], ipParts[2], ipParts[3]);

        //hostList.insert(ipAddr);
        //strcpy(hostList[nextIndex], source);

        //Define a buffer to store the converted IP addr...
        char ipStr[INET_ADDRSTRLEN];

        //Convert the source IP from ASCII to dotted-decimal format...
        inet_ntop(AF_INET, source, ipStr, INET_ADDRSTRLEN);

        //Update the hostList char array.

        if(nextSlot < MAX_HOSTS)
        {
            // for(int i = 0; i < 16 && source[i] != '\0'; i++)
            // {
            //     hostList[nextSlot][i] = source[i];
            // }
            // hostList[nextSlot][15] = '\0'; //Null-terminate the string...
            strcpy(hostList[nextSlot], ipStr);
            nextSlot++; //Increment the nextSlot for the next update...
        }
        else
        {
            //Handle the case when the hostList is full...
            cout << "Host list is full. Cannot add more hosts." << endl;
        }
    }
}

//****************************************************************************************

int main()
{
    openNetworkInterface();
    capturePackets();
    //Further processing and analysis...
    displayHostList();
    return 0;
}

//****************************************************************************************

/*
g++ networkScanner.cpp -lpcap -o networkScanner
sudo ./networkScanner
[sudo] password for root:

***Opening session...

***Capturing...
Copying...
Before source: 142.32.34.241
Copied source: 142.32.34.241
Captured source info: 142.32.34.241
Copying...
Before source: 34.241.192.168
Copied source: 34.241.192.168
Captured source info: 34.241.192.168
Copying...
Before source: 182.116.111.98
Copied source: 182.116.111.98
Captured source info: 182.116.111.98
Copying...
Before source: 192.168.1.208
Copied source: 192.168.1.208
Captured source info: 192.168.1.208
Copying...
Before source: 192.168.1.208
Copied source: 192.168.1.208
Captured source info: 192.168.1.208
Copying...
Before source: 192.168.1.254
Copied source: 192.168.1.254
Captured source info: 192.168.1.254
Copying...
Before source: 192.168.1.254
Copied source: 192.168.1.254
Captured source info: 192.168.1.254
Copying...
Before source: 167.208.92.32
Copied source: 167.208.92.32
Captured source info: 167.208.92.32
Copying...
Before source: 167.208.92.32
Copied source: 167.208.92.32
Captured source info: 167.208.92.32
Copying...
Before source: 167.208.92.32
Copied source: 167.208.92.32
Captured source info: 167.208.92.32
Copying...
Before source: 167.208.92.32
Copied source: 167.208.92.32
Captured source info: 167.208.92.32
Host list is full. Cannot add more hosts.
*/
