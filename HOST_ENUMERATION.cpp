//****************************************************************************************************
//
//       Name:         Kyle McColgan
//       File name:    HOST_ENUMERATION.cpp
//       Date:         1 January 2023
//       Description: 
//               This program contains the main class which uses pcap API for local hosts.
//
//****************************************************************************************************

#include <iostream>
#include <pcap/pcap.h>
using namespace std;

//****************************************************************************************************

int main ( )
{
    char *dev;
	char errorMsg [PCAP_ERRBUF_SIZE];
	pcap_if_t * deviceList;

	if (pcap_findalldevs(&deviceList, errorMsg) == -1 )
	{
		fprintf(stderr, "Couldn't find default device: %s\n", errorMsg);
		return(2);
	}
	printf("Device: %s\n", dev);
	return(0);
}

//****************************************************************************************************
