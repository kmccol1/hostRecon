//****************************************************************************************
//
//    Filename:    hostReconLib.cpp
//    Author:      Kyle McColgan
//    Date:        18 November 2024
//    Description: CLI based networking utility for local network host enumeration.
//
//****************************************************************************************

#include "hostReconLib.h"
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <cstring>
#include <arpa/inet.h>
#include <algorithm> //For std::reverse()
#include <cstdlib>
#include <chrono>
#include <netinet/in.h> //For struct definitions
#include <iostream>

using namespace std;

//****************************************************************************************

/**
 * @brief Copies a source IP address into a specific index of the host list.
 *
 * This function takes a source IP address string and copies it into a specified
 * index within the provided host list. The host list is expected to hold strings
 * of fixed size (16 bytes per entry) to store IPv4 addresses.
 *
 * @param hostList A 2D character array where each row represents an IPv4 address.
 *                 Each entry must be at least 16 bytes long to accommodate the
 *                 null-terminated string of the address.
 * @param source   A null-terminated C-string containing the source IP address to copy.
 * @param index    The index within hostList to which the source address will be copied.
 *
 * @pre  The `index` must be a valid index within `hostList`, and the `source` must
 *       be a valid null-terminated string representing an IPv4 address.
 * @post The `hostList` at the specified `index` will contain the copied IP address
 *       from the `source` parameter, ensuring null termination.
 */

void copyAddr(char (*hostList)[16], const char * source, int index)
{
    int adrLen = strlen(source);
    cout << "Copying " << adrLen << " chars to list at index: " << index << endl;
    strncpy(hostList[index], source, adrLen);
    hostList[index][adrLen] = '\0';
    cout << "\nhostList updated." << endl;
}

//****************************************************************************************

/**
 * @brief Converts an integer to a null-terminated character array.
 *
 * This function converts a given integer into its string representation and
 * stores it in the provided character buffer. The resulting string will be
 * null-terminated.
 *
 * @param num    The integer value to convert.
 * @param buffer A pointer to a character array where the resulting string
 *               representation of the integer will be stored. The buffer must
 *               be large enough to hold the resulting string, including the
 *               null-terminator.
 *
 * @pre  The `buffer` must be a valid pointer to a character array with enough
 *       space to store the string representation of `num` and the null-terminator.
 * @post The `buffer` will contain the null-terminated string representation
 *       of the input integer `num`.
 */

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

/**
 * @brief Computes the checksum of a given data buffer.
 *
 * This function calculates a 16-bit checksum for a block of data, typically
 * used for validating data integrity in networking protocols such as IP, TCP, or UDP.
 * The checksum is computed by summing 16-bit words and returning the one's complement
 * of the result.
 *
 * @param data   A pointer to the data buffer for which the checksum will be calculated.
 * @param length The length of the data buffer in bytes.
 *
 * @return The 16-bit computed checksum as an unsigned short.
 *
 * @pre  The `data` pointer must point to a valid memory location with at least `length` bytes.
 *       The `length` parameter must be non-negative.
 * @post The function returns the computed checksum based on the provided data buffer.
 */

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

/**
 * @brief Processes packets captured by `pcap_dispatch` during a network scan.
 *
 * This function is a callback invoked by `pcap_dispatch` for each captured packet.
 * It processes the packet's metadata and raw data, performing any necessary analysis
 * or validation. The callback is provided with a user-defined context for managing
 * state or passing additional data.
 *
 * @param user       A user-defined data pointer passed by `pcap_dispatch`. In this
 *                   implementation, it is a pointer to a `context` object that contains
 *                   relevant state information for the network scan.
 * @param pkthdr     A pointer to the packet header structure (`pcap_pkthdr`)
 *                   containing metadata about the captured packet, such as its
 *                   length, captured length, and timestamp.
 * @param capPacket  A pointer to the raw packet data captured by `pcap_dispatch`.
 *                   This includes the packet's payload and headers (e.g., Ethernet, IP, etc.).
 *
 * @pre  The `user`, `pkthdr`, and `capPacket` pointers must all be valid. The `user`
 *       parameter must point to a properly initialized `context` object. The `capPacket`
 *       buffer must contain at least `pkthdr->caplen` bytes.
 * @post The captured packet is processed as defined by the implementation. Any
 *       resulting data or state changes should be managed through the `context` object
 *       or other defined structures.
 *
 * @note This function is called repeatedly by `pcap_dispatch` until either the
 *       specified packet limit is reached or an error occurs.
 */

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

/**
 * @brief Sends an ICMP ping to a specified destination and captures responses.
 *
 * This function performs an ICMP ping sweep on the given destination IP address.
 * It sends a ping request and listens for responses, using the provided
 * `CaptureContext` to store relevant state and results. The function is
 * typically called in a loop to handle retries or multiple hosts.
 *
 * @param destination A reference to a character array (16 bytes) containing the
 *                    null-terminated destination IP address in dotted-decimal format.
 * @param context     A reference to a `CaptureContext` object that manages the
 *                    capture session, stores results, and maintains the scanning state.
 *
 * @return `true` if the ping request was sent successfully, otherwise `false`.
 *
 * @pre  The `destination` parameter must contain a valid null-terminated IPv4
 *       address. The `context` must be properly initialized and associated
 *       with an active `pcap_dispatch` session.
 * @post The `context.result` will be updated to reflect whether a response was
 *       received for the ping request.
 *
 * @note This function is typically called within a loop to handle multiple attempts
 *       or multiple destinations. In the calling function, the `context.result`
 *       should be checked to determine if the destination is active.
 *
 * @see `getHosts()` for an example of how this function is used in a scanning loop.
 */

bool pingSweep(char (&destination)[16], CaptureContext & context)
{
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

/**
 * @brief Scans for active hosts on the network and populates a host list.
 *
 * This function iterates through a series of potential hosts, sending ICMP ping requests
 * and listening for responses. Active hosts are added to the provided host list up to the
 * specified maximum limit. The function uses the provided `CaptureContext` to manage the
 * capture session and results during the scan.
 *
 * @param hostList   A pointer to a 2D character array where each row (16 bytes) stores
 *                   a null-terminated IPv4 address of an active host. The array should
 *                   have sufficient space for storing up to `numHosts` hosts.
 * @param numHosts   An integer reference representing the current number of hosts in the
 *                   list. This value is updated to reflect the total number of active
 *                   hosts detected.
 * @param context    A reference to a `CaptureContext` object that manages the capture
 *                   session, stores results, and maintains the scanning state.
 *
 * @pre  `hostList` must have sufficient capacity for storing the desired number of hosts
 *       (up to `MAX_HOSTS`). The `context` must be properly initialized with an active
 *       pcap session.
 * @post The `hostList` is updated with the IP addresses of active hosts detected during
 *       the scan, and `numHosts` is incremented accordingly.
 *
 * @note This function leverages `pingSweep` to send ICMP requests and evaluate responses.
 *       If the `hostList` becomes full, no additional hosts will be added, and an error
 *       message is printed.
 *
 * @see `pingSweep` for more details on the pinging mechanism.
 */

void getHosts(char (*hostList)[16], int &numHosts, CaptureContext & context)
{
    const char base[] = "192.168.1.";
    char destIP[16];
    int hostCount = 0;

    for (int i = 1; i < 255; i++)
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

/**
 * @brief Filters out special characters from an IP address or hostname string.
 *
 * This function processes the input string (`address`) and copies only alphanumeric
 * characters and periods (.) to the output string (`filtered`). It is primarily
 * used to sanitize user input or ensure compatibility with networking functions.
 *
 * @param address  A pointer to the null-terminated input string containing the
 *                 IP address or hostname to be filtered.
 * @param filtered A pointer to the null-terminated output string where the
 *                 sanitized result will be stored. The caller must ensure that
 *                 the buffer is large enough to hold the filtered output.
 *
 * @pre  `address` must point to a valid, null-terminated string. `filtered` must
 *       point to a buffer with sufficient capacity to store the sanitized output.
 * @post The `filtered` string contains a sanitized version of the `address`, with
 *       all special characters removed except for alphanumeric characters and periods.
 *
 * @note This function is typically used to clean input strings before further
 *       processing or validation. Characters not matching the allowed criteria
 *       are excluded from the output.
 */

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

/**
 * @brief Validates if a given string is a valid IPv4 address.
 *
 * This function checks whether the input string (`address`) conforms to the standard
 * IPv4 address format, consisting of four octets (each between 0 and 255) separated by periods.
 * It performs basic checks for the correct number of octets and ensures each octet is within the valid range.
 *
 * @param address A pointer to the null-terminated string representing the IP address to be validated.
 *
 * @return `true` if the `address` is a valid IPv4 address, otherwise `false`.
 *
 * @pre  `address` must point to a valid, null-terminated string.
 * @post The function returns `true` if the string is a valid IPv4 address, or `false` otherwise.
 *
 * @note This function performs a basic validation of the IPv4 format but does not
 *       handle edge cases like addresses with leading zeros or malformed segments.
 */

bool isValidIPAddress(const char* address)
{
    int numDots = 0;
    int numDigits = 0;
    int currentOctetValue = 0;
    bool result = true;

    if (address == nullptr)
    {
        return false;
    }

    while (*address)
    {
        if (*address == '.')
        {
            numDots++;

            // After the last digit of an octet, check the octet value
            if ( ( numDigits == 0 ) || ( numDigits > 3 ) || ( currentOctetValue > 255) )
            {
                result = false;
            }

            // Reset for next octet
            currentOctetValue = 0;
            numDigits = 0;
        }
        else if ( ( *(address) >= '0') && ( *(address) <= '9') )
        {
            currentOctetValue = currentOctetValue * 10 + (*address - '0');
            numDigits++;
        }
        else
        {
            result = false;
            break;
        }

        address++;
    }

    // Final validation for the last octet
    if ( (numDigits == 0) || (numDigits > 3) || (currentOctetValue > 255) )
    {
        result = false;
    }

    // IP should have exactly 3 dots
    if (numDots != 3)
    {
        result = false;
    }

    return result;
}
//****************************************************************************************

/**
 * @brief Checks if a given IP address is present in a list of hosts.
 *
 * This function iterates through a list of IP addresses (`hostList`) and checks if the
 * specified IP address (`address`) is present in the list. The comparison is done by
 * checking if the `address` matches any entry in the list of size `listSize`.
 *
 * @param address   A pointer to the null-terminated string representing the IP address to check.
 * @param hostList  A pointer to a 2D character array where each row (16 bytes) stores a null-terminated
 *                  IP address. The list contains up to `listSize` entries.
 * @param listSize  The size of the `hostList`, representing the number of IP addresses stored in the list.
 *
 * @return `true` if the `address` is found in the `hostList`, otherwise `false`.
 *
 * @pre  `address` must point to a valid, null-terminated string representing an IP address.
 *       `hostList` must be a valid pointer to an array of IP addresses, and `listSize` must
 *       be a non-negative integer representing the number of elements in the list.
 * @post The function returns `true` if the address is found in the list, or `false` if not.
 *
 * @note This function performs a direct comparison of the address string with each entry in the list.
 *       It assumes that all IP addresses in `hostList` are valid and formatted correctly.
 */

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

/**
 * @brief Displays the list of active hosts.
 *
 * This function iterates through the `hostList` and displays the IP addresses of all
 * active hosts stored in the list. It is typically used for debugging or presenting the
 * results of a network scan.
 *
 * @param hostList A pointer to a 2D character array where each row (16 bytes) stores a
 *                 null-terminated IP address. The list contains up to `numHosts` entries.
 * @param numHosts The number of active hosts in the `hostList` to be displayed.
 *
 * @pre  `hostList` must be a valid pointer to an array of IP addresses, and `numHosts`
 *       must be a non-negative integer representing the number of hosts to display.
 * @post The function prints each IP address in the list to the console.
 *
 * @note This function assumes that each entry in the `hostList` is a valid, null-terminated IP address.
 */

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

/**
 * @brief Opens the network interface for packet capture.
 *
 * This function attempts to open a network interface for packet capture using
 * `pcap_open_live`. It configures the capture session with a buffer size (`BUFSIZ`), enabling
 * promiscuous mode and setting a timeout of 1000ms. If the interface cannot be opened, an error message
 * is displayed.
 *
 * @pre The network interface must exist and be available for capture.
 * @post A packet capture session is opened if successful, or an error message is printed if failed.
 *
 * @note The interface "enp34s0" is hardcoded in this function. Modify the string if a different interface is needed.
 */

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

/**
 * @brief Extracts the source and destination IP addresses from a packet.
 *
 * This function extracts the source and destination IP addresses from an IPv4 packet.
 * The packet is assumed to be an Ethernet frame, and the IP header is parsed to retrieve
 * the source and destination IPs. These IPs are then copied into the provided `source` and
 * `destination` character arrays.
 *
 * @param packet A pointer to the raw packet data.
 * @param source A reference to a character array where the source IP will be stored (in dotted decimal format).
 * @param destination A reference to a character array where the destination IP will be stored (in dotted decimal format).
 *
 * @pre The `packet` should be a valid pointer to a raw packet containing an IPv4 header.
 * @post The source and destination IP addresses are copied into the `source` and `destination` arrays.
 *
 * @note The function assumes the packet is an Ethernet frame containing an IPv4 header.
 */

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
