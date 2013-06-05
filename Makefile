#Snooper make
CC=gcc

CFLAGS=-c -Wall
CLIBS=-lpcap

all: snooper

debug: CC += -DDEBUG -g
debug: snooper

snooper: snooper.o 
	$(CC) $(CLIBS) snooper.o cb_pkg_buffer.o -o snooper

snooper.o: cb_pkg_buffer.o
	$(CC) $(CFLAGS) snooper.c 

cb_pkg_buffer.o:
	$(CC) $(CFLAGS) core/cb_pkg_buffer.c

clean: 
	rm -rf *o snooper
