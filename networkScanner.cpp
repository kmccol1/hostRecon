#include <iostream>
#include <pcap/pcap.h>
using namespace std;

pcap_t * session;

void openNetworkInterface()
{
    char errors [PCAP_ERRBUF_SIZE];
    session = pcap_open_live("enp34s0", BUFSIZ, 1, 1000, errors);

    if(session == NULL)
    {
        cerr << "Error opening the NIC: " << errors << endl;
    }
}

void capturePackets()
{
    struct pcap_pkthdr header;
    const u_char * packet;

    //Capture a single packet
    packet = pcap_next(session, &header);
    //Process the captured packet...
}

void extractDeviceInfo(const u_char * packet)
{
    //Extract device information from the packet...(IPs, MACs)
}

int main()
{
    openNetworkInterface();
    capturePackets();
    //Further processing and analysis...
    return 0;
}
