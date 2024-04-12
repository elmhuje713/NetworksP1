#include <iostream>
#include <pcap.h>
#include "wire_handlers.h"
#include "wire_analyze.hpp"

void callback(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
wire_analyze analyze;

int main (int argc, char *argv[]) {
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <pcap>\n", argv[0]);
		return 1;
	}

	// wire_analyze analyze;
	struct prog_output output;
	const char *filename = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;

	handle = pcap_open_offline(argv[1], errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Error opening file: %s\n", errbuf);
		return 1;
	}
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "File does not contain Ethernet data\n");
		return 1;
	}
	if (pcap_loop(handle, -1, callback, (u_char*)&output) < 0) {
		fprintf(stderr, "Error reading packets: %s\n", pcap_geterr(handle));
		return 1;
	} 
	
	// These functions are described further in wire_analyze.cpp and handle printing and parsing of the final outputs
    analyze.printPackets();
	analyze.mapEth();
	analyze.mapIP();
	analyze.mapUDPports();
    analyze.listARP();
	pcap_close(handle);
	return 0;
}

/** callback
 * Passes a struct with all our program output info into pcap loop as a reference (user_data)
 * determines presence of IP, ARP, and passes the packet by reference to handler functions to be filled with the recorded data
 * finally: sends the packet to the wire_analyze object to be mapped and parsed for output
 *
 * @param user_data: the program output data (our packet info struct cast as a u_char*)
 * @param pkthdr: the pcap packet header
 * @param packet: the packet data
 */
void callback(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	static int count = 0;
	static int max_pkt_len = 0;
	static int min_pkt_len = 1000;
	static int total_pkt_len = 0;

	struct prog_output* our_output = (struct prog_output*)user_data;
	count++;
	our_output->packet_number = count;			// records the count in our program output struct
	our_output->packet_time_info = *pkthdr;		// records all packet header info (like time) in our struct

	u_int16_t type = handle_ethernet(user_data, pkthdr, packet);
	if (ntohs(type) == ETHERTYPE_IP) {			// if IP is detected, we record its data
			handle_IP(user_data,pkthdr,packet);	// our output data struct gets passed to each function
	} else if (ntohs(type) == ETHERTYPE_ARP) {	// if ARP is detected, we record that data
			handle_ARP(user_data,pkthdr, packet);
	}

	total_pkt_len += pkthdr->caplen;			// we start recording some statistics on packet lengths
	if (pkthdr->caplen > max_pkt_len) {
			max_pkt_len = pkthdr->caplen;
	}
	if (pkthdr->caplen < min_pkt_len) {
			min_pkt_len = pkthdr->caplen;
	}
	analyze.setPacket(*our_output); 			// Add Packet to our map after all data is added
	return;
}
