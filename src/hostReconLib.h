//****************************************************************************************
//
//    Filename:    hostReconLib.h
//    Author:      Kyle McColgan
//    Date:        7 October 2024
//    Description: CLI based networking utility for local network host enumeration.
//
//****************************************************************************************

#ifndef HOST_RECON_LIB_H
#define HOST_RECON_LIB_H

#include <pcap/pcap.h>

//****************************************************************************************

const int MAX_HOSTS = 254; //Covers a typical /24 subnet, with 254 usable hosts.

//****************************************************************************************

struct CaptureContext
{
    pcap_t * captureSession;
    bool & result;
    struct in_addr destination;
    pcap_t * sendSession;
};

//****************************************************************************************

// Function declarations
bool isValidIPAddress(const char* ip);
unsigned short computeChecksum(void * data, int length);
void copyAddr(char (*hostList)[16], const char * source, int index);
void intToCharArray(int num, char * buffer);
static void callBack(u_char * user, const struct pcap_pkthdr * pkthdr, const u_char * capPacket);
bool pingSweep(char (&destination)[16], CaptureContext & context);
void getHosts(char (*hostList)[16], int &numHosts, CaptureContext & context);
void filterSpecialChars(const char * address, char * filtered);
bool inList(const char* address, char (*hostList)[16], int listSize);
void displayHostList(char (*hostList)[16], int numHosts);
void openNetworkInterface();
void extractDeviceInfo(const u_char * packet, char (&source)[16], char(&destination)[16]);

//****************************************************************************************


#endif  // HOST_RECON_LIB_H
