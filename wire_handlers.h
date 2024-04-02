#ifndef WIRE_HANDLERS_H
#define WIRE_HANDLERS_H
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
struct pac {
	int length;	// packet length
	int protocol;	// protocol (ARP...)
	// other values
};

void process_ethernet(const u_char *packet);
void process_ip(const u_char *packet, int packet_len);
void process_arp(const u_char *packet);
void process_udp(const u_char *packet);
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void callback(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
int compare_packets(struct pac* pacs, int num_packets, int response);
void udp_print(const struct udphdr *udp_header);
void tcp_print(const struct tcphdr *tcp_header);
void ip_print(const struct ip *ip_header);
void handle_ARP(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
#endif /* WIRE_HANDLERS_H */
