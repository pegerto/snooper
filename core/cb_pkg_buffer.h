#include <stdlib.h>
#include <pcap.h>
#include <string.h>

/**
* Packet buffer definition for a circular buffer
*/
typedef struct cb_pkg_buffer{
	void *header_buffer;			/* Package header buffer */
	void *package_buffer;			/* Package buffer */
	size_t capacity;				/* Header capacity the 
									   packet capacity depends packet size */
	size_t count;					/* Number of packets */
	void *h_head;					/* Header head  */
	void *h_tail;					/* Header tail */
	void *p_head;					/* Package head */
	void *p_tail;					/* Package tail */
} cb_pkg_buffer;

/**
* Memory allocation for the circular buffer that store the captured
* packages. 
*/
cb_pkg_buffer *
cb_pkg_init(size_t capacity);

/**
* Push a new package in the buffer, input the pcap_header and 
* the package info
*/
void 
cb_pkg_push(cb_pkg_buffer *cb_pkg, const struct pcap_pkthdr *header, 
			const u_char *pkt_data);