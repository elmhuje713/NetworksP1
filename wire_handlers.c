#include "wire_handlers.h"

/** handle_ethernet
 * Handles the ethernet header
 *
 * @param user_data: the program output data (our packet info struct cast as a u_char*)
 * @param pkthdr: the pcap packet header
 * @param packet: the packet data
 * @return ether_type
 */
u_int16_t handle_ethernet(u_char *user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	struct prog_output* our_output = (struct prog_output*)user_data;
	struct ether_header *eptr; /* net/ethernet.h */
	eptr = (struct ether_header *) packet;
	our_output->eth_info = *eptr;
	if (!(ntohs(eptr->ether_type) == ETHERTYPE_IP || ntohs(eptr->ether_type) == ETHERTYPE_ARP || ntohs(eptr->ether_type) == ETHERTYPE_REVARP)) {
		exit(1);
	}
	return eptr->ether_type;
}

/** process_ip
 * Handles the IP header, namely TCP/UDP info.
 *
 * @param user_data: the program output data (our packet info struct cast as a u_char*)
 * @param pkthdr: the pcap packet header
 * @param packet: the packet data
 */
void process_ip(u_char *user_data, const u_char *packet, int packet_len) { 
	struct prog_output* our_output = (struct prog_output*)user_data;
	struct ether_header *eth_header = (struct ether_header *)packet;
	
	if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
		struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
		our_output->ip_info = *ip_header;
		if (ip_header->ip_p == IPPROTO_TCP) {
			struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
			our_output->tcp_info = *tcp_header;
		} else if (ip_header->ip_p == IPPROTO_UDP) {
			struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
			our_output->udp_info = *udp_header;
		}
	}
	return;
}

/** handle_IP
 * Handles the IP header.
 *
 * @param user_data: the program output data (our packet info struct cast as a u_char*)
 * @param pkthdr: the pcap packet header
 * @param packet: the packet data
 * @return NULL
 */
u_char* handle_IP(u_char *user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	const struct my_ip* ip;
	u_int length = pkthdr->len;
	u_int hlen, off, version;
	length -= sizeof(struct ether_header);
	if (length < sizeof(struct my_ip)) {
		return NULL;
	}
	process_ip(user_data, packet, length);
	return NULL;
}

/** handle_ARP
 * Handles the ARP header and machine info
 *
 * @param user_data: the program output data (our packet info struct cast as a u_char*)
 * @param pkthdr: the pcap packet header
 * @param packet: the packet data
 */
void handle_ARP(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	struct prog_output* our_output = (struct prog_output*)user_data;
	// Add ether_header length to get to arp_packet
	struct ether_arp* arp = (struct ether_arp *) (packet + sizeof(struct ether_header));
	our_output->arp_machine_info = *arp;
}