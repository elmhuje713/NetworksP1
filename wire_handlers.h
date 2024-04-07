#ifndef WIRE_HANDLERS_H
#define WIRE_HANDLERS_H
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
struct prog_output {
	int start_time;
	int start_date;
	int cap_duration;	// in seconds with microsecond resolution
	int total_num_pkts;

//	struct ip_eth_info* senders[];
//	struct ip_eth_info* recipients[];

//	struct arp_machine* arp_machines[];

//	int udp_port_srcs[];
//	int udp_port_dests[];

	int max_pkt_len;
	int min_pkt_len;
	int av_pkt_len;
	
};

//struct arp_machine {
//	int ips[];
//	int macs[];
//};


struct my_ip {
        u_int8_t                ip_vhl;
        #define IP_V(ip)        (((ip)->ip_vhl & 0xf0) >> 4)
        #define IP_HL(ip)       ((ip)->ip_vhl & 0x0f)
        u_int8_t                ip_tos;
        u_int16_t               ip_len;
        u_int16_t               ip_id;
        u_int16_t               ip_off;
        #define IP_DF 0x4000
        #define IP_MF 0x2000
        #define IP_OFFMASK 0x1fff
        u_int8_t                ip_ttl;
        u_int8_t                ip_p;
        u_int16_t               ip_sum; 
        struct in_addr          ip_src, ip_dst;
};

void process_ip(const u_char *packet, int packet_len);
void callback(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
//int compare_packets(struct pac* pacs, int num_packets, int response);
void udp_print(const struct udphdr *udp_header);
void tcp_print(const struct tcphdr *tcp_header);
void ip_print(const struct ip *ip_header);
void handle_ARP(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
#endif /* WIRE_HANDLERS_H */
