# NetworksP1
CS3516 Networks Project 1

note for max and I:
	- we are going to pass a struct with all the program output info into pcap loop as a reference

To Run:
	- type "make" in terminal
	- type: ./wireview project2-dns.pcap | ./wire_analyze
		- you may switch out the pcap file
	
Info:

wireview.c:
	- our main function/program

wire_handlers.c:
	- all of our functions

wire_handlers.h:
	- header for those functions

wire_analyze.cpp
	- our parsing and statistic gathering program

