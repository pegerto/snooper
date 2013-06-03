/**
* Packet buffer definition for a circular buffer
*/
typedef struct{
	char *buffer;
	int length;
	int start;
	int end;
} cb_pkg_buffer;