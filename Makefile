#Snooper
CC=gcc

CFLAGS=-c -Wall
CLIBS=-lpcap

all: snooper

snooper: snooper.o
	$(CC) $(CLIBS) snooper.o -o snooper

snooper.o:
	$(CC) $(CFLAGS) snooper.c

clean: 
	rm -rf *o snooper
