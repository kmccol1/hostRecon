#include <iostream>
#include <pcap/pcap.h>
using namespace std;

int main ( )
{
    cout << "Hello World!" << endl << endl << endl;
    

    char *dev;
	char errorMsg [PCAP_ERRBUF_SIZE];
	pcap_if_t * deviceList;

	//pcap_findalldevs(&deviceList, errorMsg);
	if (pcap_findalldevs(&deviceList, errorMsg) == -1 )
	{
		fprintf(stderr, "Couldn't find default device: %s\n", errorMsg);
		return(2);
	}
	printf("Device: %s\n", dev);
	return(0);


    




    return 0;
}