#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest/doctest.h"
#include <cstring>  // for strcmp
#include <iostream>
#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <algorithm> //For std::reverse()
#include <cstdlib>
#include <chrono>
#include <netinet/in.h> //For struct definitions
#include <string>

// Function prototypes ...
bool isValidIPAddress(const char* address);
void copyAddr(char (*hostList)[16], const char* source, int index);
unsigned short computeChecksum(void* data, int length);

const int MAX_HOSTS = 254;
//char testHostList[MAX_HOSTS][16] = {};

// Test case for IP Address Validation
TEST_CASE("IP Address Validation") {
    CHECK(isValidIPAddress("192.168.1.1") == true);
    CHECK(isValidIPAddress("255.255.255.255") == true);
    CHECK(isValidIPAddress("256.100.100.100") == false);
    CHECK(isValidIPAddress("192.168.1") == false);
    CHECK(isValidIPAddress("192.168.1.100.1") == false);
    CHECK(isValidIPAddress("abc.def.ghi.jkl") == false);
}

// Test case for Host List Management
TEST_CASE("Host List Management")
{
    //const int MAX_HOSTS = 254;
    char testHostList[254][16] = {}; // Local test host list
    int numHosts = 0;

    // Testing copyAddr
    copyAddr(testHostList, "192.168.1.10", 0);
    CHECK(strcmp(testHostList[0], "192.168.1.10") == 0);

    // Adding to the count of hosts
    numHosts++;

    // Test copying another address
    copyAddr(testHostList, "192.168.1.20", 1);
    CHECK(strcmp(testHostList[1], "192.168.1.20") == 0);
    numHosts++;

    // Check that the number of hosts is managed correctly
    CHECK(numHosts == 2);
}

// Test case for Checksum Calculation
TEST_CASE("Checksum Calculation") {
    struct icmphdr icmpHeader;
    icmpHeader.type = ICMP_ECHO;
    icmpHeader.code = 0;
    icmpHeader.checksum = 0; // Placeholder
    icmpHeader.un.echo.id = htons(1234);
    icmpHeader.un.echo.sequence = htons(1);

    unsigned short checksum = computeChecksum((void*)&icmpHeader, sizeof(struct icmphdr));
    CHECK(checksum != 0); // Checksum should not be zero

    // Verify that the checksum calculation is consistent (if you have expected checksum)
    // unsigned short expectedChecksum = /* Your expected checksum value */;
    // CHECK(checksum == expectedChecksum);
}
