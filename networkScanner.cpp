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

void copyAddr(char (*hostList)[16], const char * source, int index)
{
    strncpy(hostList[index], source, 16);
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
    // regex pattern("^((25[0-5]|2[0-4][0-9][01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9][01]?[0-9][0-9]?)$");
    // return regex_match(address, pattern);
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

void displayHostList(char (*hostList)[16], int maxLength)
{
    cout << "Printing the host list..." << endl;

    // for(int i = 0; i < maxLength; i ++ )
    // {
    //     if(hostList[i][0] != '\0')
    //     {
    //         cout << "Host " << i+1 << ": " << hostList[i] << endl;
    //     }
    // }

    for (int i = 0; i < MAX_HOSTS; i ++)
    {
        cout << "Host " << i + 1 << ": ";
        for (int j = 0; j < 16; j ++)
        {
            if(hostList[i][j] != '\0')
            {
                cout << hostList[i][j];
            }
            else
            {
                break;
            }

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

    //cout << "Copying..." << endl;
    //cout << "Before source: " << sourceIP << endl;
    strncpy(source, sourceIP, sizeof(source) - 1);
    strncpy(destination, destinationIP, sizeof(destination) - 1);


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
    int totalPackets = 0;
    struct pcap_pkthdr header;
    const u_char * packet;
    int totalHosts = 20;
    char source[16];
    char destination[16];
    int hostListSize = sizeof(hostList) / sizeof(hostList[0]);
    int nextSlot = 0;
    char ipStr[INET_ADDRSTRLEN]; //Define a buffer to store the converted IP addr...
    char cleaned[100];
    int cleanedIndex = 0;
    int hostIndex = 0;
    int addressIndex = 0;
    int charIndex;
    int j = 0;
    char filteredIP[16];


    while ( (hostList[nextSlot][0] != '\0') && (nextSlot < MAX_HOSTS))
    {
        nextSlot++;
    }

    cout << "\n***Capturing packets..." << endl;
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
        if((nextSlot < MAX_HOSTS) && (isValidIPAddress(ipStr) == true) && (!inList(ipStr, hostList, nextSlot)))
        {
            cout << "Updating list with: " << ipStr << endl;


            //Poor man's str(n)cpy...
            // while(ipStr[addressIndex] != '\0' && nextSlot < MAX_HOSTS)
            // {
            //     charIndex = 0;
            //     while(ipStr[addressIndex] != '\0' && ipStr[addressIndex] != '.' && charIndex < 15)
            //     {
            //         hostList[nextSlot][charIndex] = ipStr[addressIndex];
            //         addressIndex ++;
            //         charIndex ++;
            //     }
            //     hostList[nextSlot][charIndex] = '\0'; //Null-terminate the string...
            //     //hostIndex ++;
            //     addressIndex ++;
            // }

            // charIndex = 0;
            // while(ipStr[charIndex] != '\0' && charIndex < 15)
            // {
            //     hostList[nextSlot][charIndex] = ipStr[charIndex];
            //     charIndex ++;
            // }
            // hostList[nextSlot][charIndex] = '\0'; //Null-terminate the string...

            // for(int i = 0, j=0; i < strlen(ipStr); i ++)
            // {
            //     if((ipStr[i] >= '0' && ipStr[i] <= '9') || ipStr[i] == '.')
            //     {
            //         hostList[nextSlot][j++] = ipStr[i];
            //     }
            //     else
            //     {
            //         cout << "Detected Unicode..." << endl;
            //     }
            // }
            // hostList[nextSlot][j] = '\0';

            // for(int i = 0; ipAddr[i] != '\0'; i ++)
            // {
            //     if(isdigit(ipAddr[i] || ipAddr[i] == '.')
            //     {
            //         hostList[nextSlot] = ipAddr[i];
            //     }
            // }

            // int ipStrIndex = 0;
            // int hostListIndex = 0;
            //
            // while(ipStr[ipStrIndex] != '\0' && hostListIndex < 15)
            // {
            //     if(isdigit(ipStr[ipStrIndex]) || ipStr[ipStrIndex] == '.')
            //     {
            //         hostList[nextSlot][hostListIndex] = ipStr[ipStrIndex];
            //         hostListIndex ++;
            //     }
            //     ipStrIndex ++;
            // }
            // int index = 0;
            // int ipIndex = 0;


            // while(filteredIP[ipIndex] != '\0' && nextSlot < MAX_HOSTS)
            // {
            //     char currentChar = filteredIP[ipIndex];
            //     if(isdigit(currentChar) || currentChar == '.')
            //     {
            //         hostList[nextSlot][0] = currentChar;
            //         hostList[nextSlot][1] = '\0'';
            //         index ++;
            //     }
            //     ipIndex ++;
            // }
            filterSpecialChars(ipStr, filteredIP);

            // for(int i = 0; i < MAX_HOSTS; i ++)
            // {
            //     snprintf(hostList[i])
            // }

            //strncpy(hostList[nextSlot], filteredIP, 16);
            //hostList[nextSlot][15] = '\0'; //Null-terminate the string...
            //strncpy(hostList[nextSlot], filteredIP, 16);
            cout << "Before Copy: " << hostList[nextSlot] << endl;
            copyAddr(hostList, filteredIP, nextSlot);
            cout << "After copy: " << hostList[nextSlot] << endl;
            //strcpy(hostList[nextSlot], ipStr);

            //strcpy(hostList[nextSlot], ipStr);
            //hostList[nextSlot][15] = '\0'; //Null-terminate the string...
            nextSlot++; //Increment the nextSlot for the next update...
            //cout << "Saved host entry: " << hostList[nextSlot] << endl;
            //cout << "Filtered: " << filteredIP << endl;
            //cout << "Copied/saved: ";// << hostList[nextSlot] << endl;
            // cout.write(hostList[nextSlot], 16);
            // cout << endl;


            // for(int i = 0; i < 16 && hostList[nextSlot][i] != '\0'; ++ i)
            // {
            //     cout << hostList[nextSlot][i];
            // }
            // cout << endl;

            hostListSize = sizeof(hostList) / sizeof(hostList[0]);
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
    //displayHostList(hostList, MAX_HOSTS);
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
