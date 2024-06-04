#include <iostream>
#include <pcap/pcap.h>
#include <netinet/ip.h>
using namespace std;

pcap_t * session;

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

void extractDeviceInfo(const u_char * packet)
{
    //Extract device information from the packet...(IPs, MACs)

    //Assuming IPv4 packet structure...
    // struct ip *ip_header = (struct ip*) (packet + SIZE_ETHERNET); //Assuming Ethernet frame...
    struct ip *ip_header = (struct ip*) (packet + 14); //Assuming Ethernet frame...

    //Extract source and destination IP addresses...
    char source[INET_ADDRSTRLEN];
    char destination[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), source, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), destination, INET_ADDRSTRLEN);

    //Print the extracted IP addresses...
    cout << "Source IP: " << source << endl;
    cout << "Destination IP: " << destination << endl;

}

void capturePackets()
{
    struct pcap_pkthdr header;
    const u_char * packet;

    //Capture a single packet
    cout << "\n***Capturing..." << endl;
    while (true)
    {
        packet = pcap_next(session, &header);
        if(packet == NULL)
        {
            continue;
        }
    }

    //Process the captured packet...
    extractDeviceInfo(packet);
}



int main()
{
    openNetworkInterface();
    capturePackets();
    //Further processing and analysis...
    return 0;
}
