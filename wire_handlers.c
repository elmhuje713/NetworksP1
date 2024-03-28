#include <pcap.h>
// /usr/include/net
// /usr/include/netinet
// ntohs & ntohl (read values that span multiple bytes)
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "wire_handlers.h"
// only IPv4 header processing is required

// transport layer
void process_ethernet(const u_char *packet){
	return;
}
// network layer
void process_ip(const u_char *packet){ 
	return;
}
// network layer
void process_arp(const u_char *packet){ 
	return;
}
// transport layer
void process_udp(const u_char *packet){
	return;
}
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	return;
}
void callback(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	// print the start date and time of the packet capture

	// print duration of the packet capture in seconds with microsecond resolution

	// print the total number of packet

	// create 2 lists
		// 1 for unique senders + total number of packets associated
		// 1 for unique recipients + total number of packets associated
	// this should be at Ethernet and IP layers
		// Ethernet addresses in hex-colon notation
		// IP addresses in standard dotted decimal notation

	// create a list of machines participating in ARP
		// associated MAC addresses, any associated IP addresses

	// for udp, create 2 lists for the unique ports seen
		// 1 for source ports
		// 1 for destination ports

	// Report the average, minimum, and maximum packet sizes (packet size = everything beyond tcpdump header)

	return;
}

int compare_packets(struct pac* pacs, int num_packets, int response) {
	int maximum = 0;
	int minimum = pacs[0].length;
	int all_sizes = 0;

	for (int c = 0; c < num_packets; c++ ) {
		all_sizes += pacs[c].length;

        	if (pacs[c].length > maximum) {
			maximum = pacs[c].length;
        	}
		if (pacs[c].length < minimum) {
			minimum = pacs[c].length;
		}
	}
	if (response == 0) {			// return average 0
		return all_sizes / num_packets;
	}
	if (response == 1) { 			// return max 1
		return maximum;
	}
	if (response == 2) {			// return min 2
		return minimum;
	}
        return 0;
}
