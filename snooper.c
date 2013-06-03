#include <stdio.h>
#include <pcap.h>

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

	//Grab a package
	packet = pcap_next(handle, &header);
	printf("We have a packet of [%d]\n", header.len);



	pcap_close(handle);
	return(0);
}