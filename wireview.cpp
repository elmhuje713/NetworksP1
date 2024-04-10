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
	} else {

	}
        analyze.testPrint();
        analyze.printPackets();
        // analyze.printTime(1);
        // analyze.printTime(2);
        // analyze.printTime(3);
        // analyze.printTime(4);
        // More ranges in arp-storm
        // analyze.printTime(200);
        // analyze.printTime(300);
        // analyze.printTime(622);
        // printf("aaah%d",analyze.packetInfo.at(4).packet_number);
	analyze.uniqueEths(1);
	analyze.uniqueEths(2);
	analyze.uniqueEths(3);
	analyze.uniqueEths(4);

	pcap_close(handle);
	return 0;
}

void callback(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
        static int count = 0;

        static int max_pkt_len = 0;
        static int min_pkt_len = 1000;
        static int total_pkt_len = 0;

        struct prog_output* our_output = (struct prog_output*)user_data;
        count++;
        printf("Callback ran: %d\n", count);
        our_output->packet_number = count;
        printf("count: %d\n", our_output->packet_number);
        our_output->packet_time_info = *pkthdr;

        u_int16_t type = handle_ethernet(user_data, pkthdr, packet);
        if (ntohs(type) == ETHERTYPE_IP) {
                handle_IP(user_data,pkthdr,packet);
        } else if (ntohs(type) == ETHERTYPE_ARP) {
                handle_ARP(user_data,pkthdr, packet);
        } else if (ntohs(type) == ETHERTYPE_REVARP) {
                printf("REV ARP");
        }

        total_pkt_len += pkthdr->caplen;
        if (pkthdr->caplen > max_pkt_len) {
                max_pkt_len = pkthdr->caplen;
        }
        if (pkthdr->caplen < min_pkt_len) {
                min_pkt_len = pkthdr->caplen;
        }
        printf("min packet length: %d\n", min_pkt_len);
        printf("max packet length: %d\n", max_pkt_len);
        printf("total length of packets: %d\n", total_pkt_len);
	analyze.setPacket(*our_output); // Add Packet to map
        printf("May output: %d\n ", our_output->packet_number);
        return;
}
