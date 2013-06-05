/*

    Copyright 2013 Pegerto Fernandez <pegerto@gmail.com>

    This file is part of Snooper

    Snooper is free software: you can redistribute it and/or modify it under the 
    terms of the GNU General Public License as published by the 
    Free Software Foundation, either version 3 of the License, or (at your option)
    any later version.
    
    Snooper is distributed in the hope that it will be useful, but 
    WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more 
    details.

    You should have received a copy of the GNU General Public License along 
    with Snooper. If not, see http://www.gnu.org/licenses/.
*/

#include "cb_pkg_buffer.h"


cb_pkg_buffer *
cb_pkg_init(size_t capacity)
{
	//Space for the cb_pkg buffer
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
		//Allocate copy and remove
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

		//Update  buffer and capacity
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

int  
cb_pkg_pull(cb_pkg_buffer *cb_pkg,  struct pcap_pkthdr *header,
			u_char *pkt_data)
{
	size_t sz = sizeof(struct pcap_pkthdr);

	//Control the buffer structure
	if (cb_pkg == NULL)
	{
		fprintf(stderr, "Error: Package buffer is not started\n" );
		exit(2);
	}

	//Do we have elements in the buffer
	if (cb_pkg->count == 0 )
		return 0;
	
	//Copy the item from the buffer
	memcpy(header, cb_pkg->h_tail , sz);

	//TODO: Decrease ring buffer size

	//In the last position goes to the the head
	cb_pkg->h_tail = cb_pkg->h_tail + sz; 
	if (cb_pkg->h_tail == (cb_pkg->capacity * sz + cb_pkg->header_buffer))
		cb_pkg->h_tail = cb_pkg->header_buffer;

	cb_pkg->count--;
	return 1;
}