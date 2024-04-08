#include "wire_handlers.h"

u_int16_t handle_ethernet(u_char *user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	struct prog_output* our_output = (struct prog_output*)user_data;
	struct ether_header *eptr; /* net/ethernet.h */
	eptr = (struct ether_header *) packet;
	our_output->eth_info = *eptr;
	fprintf(stdout, CYN "ethernet header source %s" RESET, ether_ntoa((const struct ether_addr *)&eptr->ether_shost));
	fprintf(stdout, CYN " destination: %s " RESET, ether_ntoa((const struct ether_addr *)&eptr->ether_dhost));
	fprintf(stdout, "destination: %s ", ether_ntoa((const struct ether_addr *)&our_output->eth_info.ether_dhost));
	if (ntohs (eptr->ether_type) == ETHERTYPE_IP) {
		fprintf(stdout,MAG"(IP)"RESET);
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
void process_ip(u_char *user_data, const u_char *packet, int packet_len) { 
	struct prog_output* our_output = (struct prog_output*)user_data;
	struct ether_header *eth_header = (struct ether_header *)packet;
	
	if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
		struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
		our_output->ip_info = *ip_header;
		printf(MAG"IP Header:\n"RESET);
		ip_print(ip_header);
		if (ip_header->ip_p == IPPROTO_TCP) {
			struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
			our_output->tcp_info = *tcp_header;
			printf(GRN "TCP Header:\n" RESET);
			tcp_print(tcp_header);
		} else if (ip_header->ip_p == IPPROTO_UDP) {
			struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
			our_output->udp_info = *udp_header;
			printf(BLU "UDP Header:\n" RESET);
			udp_print(udp_header);
		}

	} else {
		printf("Not an IP packet.\n");
	}
	return;
}
void udp_print(const struct udphdr *udp_header) {
	printf(BLU"UDP Source Port: %u\n", ntohs(udp_header->source));
	printf("UDP Destination Port: %u\n", ntohs(udp_header->dest));
	printf("UDP Length: %u\n", ntohs(udp_header->len));
	printf("UDP Checksum: 0x%04x\n"RESET, ntohs(udp_header->check));
}
void tcp_print(const struct tcphdr *tcp_header) {
	printf(GRN"TCP Source Port: %u\n", ntohs(tcp_header->source));
	printf("TCP Destination Port: %u\n", ntohs(tcp_header->dest));
	printf("TCP Sequence Number: %u\n", ntohl(tcp_header->seq));
	printf("TCP Acknowledgement Number: %u\n", ntohl(tcp_header->ack_seq));
	printf("TCP Header Length: %u bytes\n", tcp_header->doff*4);
	printf("TCP Flags:");
	if (tcp_header->syn) printf("SYN");
	if (tcp_header->ack) printf("ACK");
	if (tcp_header->fin) printf("FIN");
	if (tcp_header->rst) printf("RST");
	if (tcp_header->psh) printf("PSH");
	if (tcp_header->urg) printf("URG");
	printf("\n"RESET);
}
void ip_print(const struct ip *ip_header) {
	printf(MAG"IP Version: %u\n", ip_header->ip_v);
	printf("IP Header Length: %u bytes\n", ip_header->ip_hl*4);
	printf("IP Total Length: %u bytes\n", ntohs(ip_header->ip_len));
	printf("IP Source Address: %s\n", inet_ntoa(ip_header->ip_src));
	printf("IP Destination Address: %s\n"RESET, inet_ntoa(ip_header->ip_dst));
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

	process_ip(user_data, packet, length);

	hlen = IP_HL(ip);
	version = IP_V(ip);
	if (version != 4) {
		fprintf(stdout,"Unknown version %d\n", version);
		return NULL;
	}
	if (hlen < 5) {
		fprintf(stdout, "bad-hlen %d \n",hlen);
	}
	if (length < len) {
		printf("\ntruncated IP - %d bytes missing \n", len - length);
	}
	off = ntohs(ip->ip_off);
	if((off & 0x1fff) == 0) {
		fprintf(stdout,"IP: ");
		fprintf(stdout,"%s ", inet_ntoa(ip->ip_src));
		fprintf(stdout, "%s %d %d %d %d\n", inet_ntoa(ip->ip_dst),hlen, version,len,off);
	}
	return NULL;
}
void handle_ARP(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	struct prog_output* our_output = (struct prog_output*)user_data;
	struct arphdr *arphdr; /* net/if_arp */
        arphdr = (struct arphdr *) packet;
	our_output->arp_machine_info = *arphdr;
        fprintf(stdout, YEL "ARP Hardware Type: %u\n", arphdr->ar_hrd);
        fprintf(stdout, "ARP Protocol Type: %u\n", arphdr->ar_pro);
	fprintf(stdout, "ARP Hardware Address Length: %u bytes\n", arphdr->ar_hln);
	fprintf(stdout, "ARP Protocol Address Length: %u bytes\n"RESET, arphdr->ar_pln);
	return;
}

void callback(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	static int count = 0;

	static int max_pkt_len = 0;
	static int min_pkt_len = 1000;
	static int total_pkt_len = 0;

    	struct prog_output* our_array = (struct prog_output*)user_data;
    
    	count++;
    	printf("Callback ran: %d\n", count);
    	if (our_array == NULL) {
        	fprintf(stderr, "Error: Invalid pointer\n");
        	return;
    	}
    
    	our_array = realloc(our_array, count * sizeof(struct prog_output));
    	if (our_array == NULL) {
        	fprintf(stderr, "Error reallocating memory\n");
        	exit(1);
    	}

	our_array[count - 1].packet_number = count;
	printf("count: %d\n", our_array[count - 1].packet_number);
	our_array[count - 1].packet_time_info = *pkthdr;

	u_int16_t type = handle_ethernet((u_char*)&our_array[count -1], pkthdr, packet);
	
	if (ntohs(type) == ETHERTYPE_IP) {
		handle_IP((u_char*)&our_array[count - 1],pkthdr,packet);
	} else if (ntohs(type) == ETHERTYPE_ARP) {
		handle_ARP((u_char*)&our_array[count - 1],pkthdr, packet);
	} else if (type == ETHERTYPE_REVARP) {
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

	return;
}
