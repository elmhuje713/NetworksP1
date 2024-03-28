#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "wire_handlers.h"

void process_ethernet(const u_char *packet){
	return;
}
void process_ip(const u_char *packet){ 
	return;
}
void process_arp(const u_char *packet){ 
	return;
}
void process_udp(const u_char *packet){
	return;
}
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	return;
}
