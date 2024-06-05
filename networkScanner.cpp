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
#include <regex>
using namespace std;

//****************************************************************************************

const int MAX_HOSTS=50;
pcap_t * session;

//****************************************************************************************

bool isValidIPAddress(const char* address)
{
    // regex pattern("^((25[0-5]|2[0-4][0-9][01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9][01]?[0-9][0-9]?)$");
    // return regex_match(address, pattern);
    int num = 0;
    int dots = 0;
    bool result = true;

    while (*address)
    {
        if(*address == '.')
        {
            if( (num < 0 ) || (num > 255))
            {
                result = false;
            }
            num=0;
            dots ++;
        }
        else if(*address >= '0' && *address <= '9')
        {
            num = num * 10 + (*address - '0');
        }
        else
        {
            result = false; //Return false if a non-numeric character is found.
        }
        address++;
    }

    //Check if the IP address has 3 dots and is valid...
    if (dots != 3 || num < 0 || num > 255)
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

void displayHostList(char (*hostList)[16], int maxLength)
{
    char filtered[16];
    int filteredIndex = 0;

    cout << "Printing the host list..." << endl;

    // for(int i = 0; i < MAX_HOSTS; i ++ )
    // {
    //     cout << "Host " << i + 1 << ": ";
    //     for (int j = 0; j < 16; j++)
    //     {
    //         cout << hostList[i][j];
    //     }
    //     cout << endl;
    // }
    for(int i = 0; i < maxLength; i ++ )
    {
        // filteredIndex = 0;
        // for(int j =0; j < 16; j ++ )
        // {
        //     if(isascii(hostList[i][j]))
        //     {
        //         filtered[filteredIndex] = hostList[i][j];
        //         filteredIndex ++;
        //     }
        // }
        // filtered[filteredIndex] = '\0'; //Add null terminator to ensure string termination...
        if (isValidIPAddress(hostList[i]))
        {
            cout << "Host " << i+1 << ": " << hostList[i] << endl;
        }

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
    strcpy(source, sourceIP);
    strcpy(destination, destinationIP);


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

void capturePackets(char (*hostList)[16], int maxLength)
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
    char ipStr[INET_ADDRSTRLEN]; //Define a buffer to store the converted IP addr...
    char cleaned[100];
    int cleanedIndex = 0;

    while (nextSlot < MAX_HOSTS && hostList[nextSlot][0] != '\0')
    {
        nextSlot++;
    }

    cout << "\n***Capturing..." << endl;
    //while (true)
    //while(totalPackets < numPackets)
    while(hostListSize < totalHosts)
    {
        cleanedIndex = 0;
        packet = pcap_next(session, &header);
        if(packet == NULL)
        {
            continue;
        }
        totalPackets++;
        //cout << "\ntotal packets: " << totalPackets << endl;

        extractDeviceInfo(packet, source, destination);
        //cout << "Captured source info: " << source << endl;

        //Convert the source IP from ASCII to dotted-decimal format...
        inet_ntop(AF_INET, source, ipStr, INET_ADDRSTRLEN);

        //Update the hostList char array...

        //if((isValidIPAddress(ipStr)) && (nextSlot < MAX_HOSTS))
        if(nextSlot < MAX_HOSTS && (!inList(ipStr, hostList, nextSlot)))
        {
            strcpy(hostList[nextSlot], ipStr);
            nextSlot++; //Increment the nextSlot for the next update...
        }
        else
        {
            //Handle the case when the hostList is full...
            cout << "Host list is full. Cannot add more hosts." << endl;
            break;
        }
    }
}

//****************************************************************************************

int main()
{
    char hostList[MAX_HOSTS][16]; //Assuming each IP addr is stored in a 16-character array.
    openNetworkInterface();
    capturePackets(hostList, MAX_HOSTS);
    //Further processing and analysis...
    displayHostList(hostList, MAX_HOSTS);
    return 0;
}

//****************************************************************************************

/*
g++ networkScanner.cpp -lpcap -o networkScanner
sudo ./networkScanner

***Opening session...

***Capturing...
Host list is full. Cannot add more hosts.
Printing the host list...
Host 3: 49.52.50.46
Host 4: 55.54.46.49
Host 5: 50.57.46.49

*****************************************

Done.

*/
