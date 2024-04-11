#ifndef WIRE_HANDLERS_H
#define WIRE_HANDLERS_H

#include <netinet/ip.h>
#include <pcap.h>

#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>

#include <netinet/ip.h>
#include <netinet/in.h>

#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <net/if_arp.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <string.h>

#define BLU "\x1B[34m"
#define CYN "\x1B[36m"
#define GRN "\x1B[32m"
#define YEL "\x1B[33m"
#define WHT "\x1B[37m"
#define MAG "\x1B[35m"
#define RESET "\x1B[0m"

struct prog_output {
	int packet_number;

	struct pcap_pkthdr packet_time_info;	// this contains timeval from which we can access times in seconds with microsecond resolution

	struct ether_header eth_info;
	struct ip ip_info;

	struct ether_arp arp_machine_info;

	struct udphdr udp_info;
	struct tcphdr tcp_info;
};

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

#ifdef __cplusplus
extern "C" {
#endif

void udp_print(const struct udphdr *udp_header);
void tcp_print(const struct tcphdr *tcp_header);
void ip_print(const struct ip *ip_header);
void handle_ARP(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void process_ip(u_char *user_data, const u_char *packet, int packet_len);
u_int16_t handle_ethernet(u_char *user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet);
u_char* handle_IP(u_char *user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet);

#ifdef __cplusplus
}
#endif

#endif /* WIRE_HANDLERS_H */
