#include <stdio.h>
#include <pcap.h>
#include <signal.h>
#include "core/cb_pkg_buffer.h"

static pcap_t *handle;

void 
intCaptureHandler(int dummy)
{
	pcap_breakloop(handle) ;
}

void 
packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	printf("pk\n ");
}

int
main(int argc, char *argv[]) 
{
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];


	// Looking for a default device.
	dev = pcap_lookupdev(errbuf);

	if (dev == NULL)
	{
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	else
	{
		printf("Using device: %s\n", dev);
	}


	//Starting  the traffic capture, using a handle
	handle  = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL)
	{
			fprintf(stderr, "Couldn't open the device %s, are you Su\n", dev);
			return(2);
	}

	//Capture interruption
	signal(SIGINT, intCaptureHandler);
	

	//Capture loop
	pcap_loop(handle,0, packet_handler, NULL);

	pcap_close(handle);
	return(0);
}