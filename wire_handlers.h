#ifndef WIRE_HANDLERS_H
#define WIRE_HANDLERS_H

struct pac {
	int length;	// packet length
	int protocol;	// protocol (ARP...)
	// other values
};

void process_ethernet(const u_char *packet);
void process_ip(const u_char *packet);
void process_arp(const u_char *packet);
void process_udp(const u_char *packet);
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void callback(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
int compare_packets(struct pac* pacs, int num_packets, int response);

#endif /* WIRE_HANDLERS_H */
