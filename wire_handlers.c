#include <pcap.h>
// /usr/include/net
// /usr/include/netinet
// ntohs & ntohl (read values that span multiple bytes)
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>

#include <netinet/ip.h>
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <string.h>

#include "wire_handlers.h"
// only IPv4 header processing is required

struct my_ip {
	u_int8_t 		ip_vhl;
	#define IP_V(ip) 	(((ip)->ip_vhl & 0xf0) >> 4)
	#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
	u_int8_t		ip_tos;
	u_int16_t		ip_len;
	u_int16_t		ip_id;
	u_int16_t		ip_off;
	#define IP_DF 0x4000
	#define IP_MF 0x2000
	#define IP_OFFMASK 0x1fff
	u_int8_t		ip_ttl;
	u_int8_t		ip_p;
	u_int16_t		ip_sum;	
	struct in_addr		ip_src, ip_dst;
};

// transport layer
void process_ethernet(const u_char *packet){
	struct ether_addr eth_addr;
	memcpy(&eth_addr, packet, 6);
	
	char *ascii_addr = ether_ntoa(&eth_addr);
	int result = ether_hostton((const char*)packet, &eth_addr);
	printf("Ethernet address: %s\n", ascii_addr);

	if (result == 0) {
		printf("Ethernet address for %s is %s\n", packet, ascii_addr);
	} else {
		printf("Failed to get Ethernet address for %s\n", packet);
	}

	return;
}

u_int16_t handle_ethernet(u_char *user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	struct ether_header *eptr; /* net/ethernet.h */
	eptr = (struct ether_header *) packet;
	fprintf(stdout, "ethernet header source %s", ether_ntoa((const struct ether_addr *)&eptr->ether_shost));
	fprintf(stdout," destination: %s ", ether_ntoa((const struct ether_addr *)&eptr->ether_dhost));

	if (ntohs (eptr->ether_type) == ETHERTYPE_IP) {
		fprintf(stdout,"(IP)");
	} else if (ntohs (eptr->ether_type) == ETHERTYPE_ARP) {
		fprintf(stdout,"(ARP)");
	} else if (ntohs (eptr->ether_type) == ETHERTYPE_REVARP){
		fprintf(stdout,"(RARP)");
	} else {
		fprintf(stdout, "(?)");
		exit(1);
	}
	fprintf(stdout, "\n");
	return eptr->ether_type;
}
// network layer
void process_ip(const u_char *packet){ 
	return;
}
u_char* handle_IP(u_char *user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	const struct my_ip* ip;
	int len;
	u_int length = pkthdr->len;
	u_int hlen, off, version;
	int i;
	ip = (struct my_ip*)(packet + sizeof(struct ether_header));
	length -= sizeof(struct ether_header);
	if (length < sizeof(struct my_ip)) {
		printf("truncated ip %d",length);
		return NULL;
	}
	len = ntohs(ip->ip_len);
	hlen = IP_HL(ip);
	version = IP_V(ip);
	if (version != 4) {
		fprintf(stdout,"Unknown version %d\n", version);
	}
	if (hlen < 5) {
		fprintf(stdout, "bad-hlen %d \n",hlen);
	}
	if (length < len) {
		printf("\ntruncated IP - %d bytes missing \n", len - length);
	}
	off = ntohs(ip->ip_off);
	if((off & 0x1fff) == 0) {
		fprintf(stdout,"%s ", inet_ntoa(ip->ip_src));
		fprintf(stdout, "%s %d %d %d %d\n", inet_ntoa(ip->ip_dst),hlen, version,len,off);
	}
	return NULL;
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
	static int count = 1;
	printf("Callback ran: %d\n", count);
	count++;
//	process_ethernet(packet);
	u_int16_t type = handle_ethernet(user_data, pkthdr, packet);
	if (type == ETHERTYPE_IP) {
		handle_IP(user_data,pkthdr,packet);
	} else if (type == ETHERTYPE_ARP) {
		
	} else if (type == ETHERTYPE_REVARP) {
	}
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
