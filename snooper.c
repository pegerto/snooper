#include <stdio.h>
#include <pcap.h>
#include <signal.h>

static int interruptCapture = 0;

void 
intCaptureHandler(int dummy)
{
	interruptCapture = 1;
}

int
main(int argc, char *argv[]) 
{
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;

	struct pcap_pkthdr	header;						/* Header provide by pcap*/
	const u_char *packet;							/* The actual package */

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
			fprintf(stderr, "Couldn't open the device %n, are you Su\n", dev);
			return(2);
	}

	//Capture interruption
	signal(SIGINT, intCaptureHandler);
	
	//Grab a package
	while(!interruptCapture){
		packet = pcap_next(handle, &header);
		if(packet == NULL)
		{
			fprintf(stderr, "No packet captured\n");
		}
		else
		{
			printf("We have a packet of [%d]\n", header.len);
		}
	}


	pcap_close(handle);
	return(0);
}