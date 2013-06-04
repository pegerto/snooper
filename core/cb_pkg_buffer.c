#include "cb_pkg_buffer.h"


cb_pkg_buffer *
cb_pkg_init(size_t capacity)
{
	//space for the cb_pkg buffer
	cb_pkg_buffer *cb_pkg = malloc ( sizeof(cb_pkg_buffer));
	if (cb_pkg == NULL)
	{
		fprintf(stderr, "Error: Memory allocation problem, init pkg buffer\n");
	}

	/*Allocate space to store the headers, 
	* (capacity * package headers in pcap */ 
	cb_pkg->header_buffer = malloc (capacity * sizeof(struct pcap_pkthdr));
	if (cb_pkg->header_buffer == NULL)
	{
		fprintf(stderr, "Error: Memory allocation problem for the package buffer\n" );
		exit(2);
	}
	cb_pkg->capacity = capacity;
	cb_pkg->count = 0;
	cb_pkg->h_head = cb_pkg->header_buffer;
	cb_pkg->h_tail = cb_pkg->header_buffer;

	printf("Buffer started\n");
	return cb_pkg;
}

void 
cb_pkg_push(cb_pkg_buffer *cb_pkg, const struct pcap_pkthdr *header, 
			const u_char *pkt_data)
{
	size_t sz = sizeof(struct pcap_pkthdr);
	
	//To increase header buffer
	size_t new_capacity;
	void *new_header_buffer;

	//Control the buffer structure
	if (cb_pkg == NULL)
	{
		fprintf(stderr, "Error: Package buffer is not started\n" );
		exit(2);
	}

	//Control header buffer space
	if (cb_pkg->count == cb_pkg->capacity)
	{
		//Increase header buffer size/2
		new_capacity = cb_pkg->capacity + ( cb_pkg-> capacity / 2);
		// allocate copy and remove
		new_header_buffer = malloc (new_capacity * sz);
		if (new_header_buffer == NULL)
		{
			fprintf(stderr, "Error: There is not more memory to enlarge pkg buffer\n" );
			exit(2);
		}
		memcpy(new_header_buffer, cb_pkg->header_buffer , cb_pkg->capacity * sz);
		
		//Update h_head and h_tail to the new buffer
		cb_pkg->h_head = new_header_buffer + (cb_pkg->h_head  - cb_pkg->header_buffer);
		cb_pkg->h_tail = new_header_buffer + (cb_pkg->h_tail - cb_pkg->header_buffer);

		//Release old buffer
		free(cb_pkg->header_buffer);

		//Update the inforamation
		cb_pkg->header_buffer = new_header_buffer;
		cb_pkg->capacity = new_capacity;

		printf("New header buffer capacity %d\n", new_capacity);

	}

	//Copy the header item to the buffer
	memcpy(cb_pkg->h_head, header,sz);

	//Update the pointers
	cb_pkg->h_head =  cb_pkg->h_head + sz;
	if (cb_pkg->h_head == (cb_pkg->header_buffer + (sz * cb_pkg->capacity)))
		cb_pkg->h_head = cb_pkg->header_buffer;

	cb_pkg->count++;
}