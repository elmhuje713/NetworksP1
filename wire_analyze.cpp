#include <iostream>
#include <string>
#include <vector>
#include "wire_analyze.hpp"


wire_analyze::wire_analyze() {

}
/** setPacket
 * Grabs each packet during the execution of callback
 * maps the packet and its callback index
 *
 * @param: packet, the packet data
 */
void wire_analyze::setPacket(struct prog_output packet) {
	packetInfo.insert({packetNum++, packet});
}

/**
 * Prints all the packets in the pcap file
 * [packetNum] [MM:dd:yyyy hh:mm:ss.uS] [duration] [packetSize]
*/
void wire_analyze::printPackets() {
    time_t sec = packetInfo.at(1).packet_time_info.ts.tv_sec;
    suseconds_t usec = packetInfo.at(1).packet_time_info.ts.tv_usec;
    bpf_u_int32 minPacketSize = 0xffffffff;
    bpf_u_int32 maxPacketSize = 0;
    float avgPacketSize = 0;

    for (int i = 1; i <= packetInfo.size(); i++) {
        bpf_u_int32 packetSize = packetInfo.at(i).packet_time_info.len;
        time_t curr_sec = packetInfo.at(i).packet_time_info.ts.tv_sec;
        suseconds_t curr_usec = packetInfo.at(i).packet_time_info.ts.tv_usec;
        time_t elapsed_sec = curr_sec - sec;
        suseconds_t elapsed_usec = curr_usec - usec;
        // If usec is negative, add 1 sec of time to usec
        if (elapsed_usec < 0) {
            elapsed_sec--;
            elapsed_usec += 1000000;
        }
        // Set Min, Max, and Average packet sizes
        if (packetSize < minPacketSize) minPacketSize = packetSize;
        if (packetSize > maxPacketSize) maxPacketSize = packetSize;
        avgPacketSize += packetSize;

        printf("%d ", i); // Packet Num
        printTime(i); // Epoch Time
        printf(" %ld.%06ld", elapsed_sec, elapsed_usec); // Elapsed Time
        printf(" %d\n", packetSize); // Packet Size
    }
    avgPacketSize /= packetInfo.size();
    printf("Total of %ld packets found\n", packetInfo.size());
    printf("Statistics -> MIN: %d MAX: %d AVERAGE: %f\n", minPacketSize, maxPacketSize, avgPacketSize);

}
/** testPrint
 * Test function to make sure packets were correctly mapped
 */
void wire_analyze::testPrint() {
	std::map<int, struct prog_output>::iterator it = packetInfo.begin();
 
    // Iterate through the map and print the elements
    while (it != packetInfo.end()) {
        std::cout << "Key: " << it->first
             << ", Value: " << (it->second).packet_number << std::endl;
        ++it;
    }
}

/**
 * Prints the EPOCH time for a set packet
 * @param indx packetNum for what packet to print
 */
void wire_analyze::printTime(int indx) {
    __time_t timeEpoch = packetInfo.at(indx).packet_time_info.ts.tv_sec;
    __suseconds_t elapsed = packetInfo.at(indx).packet_time_info.ts.tv_usec;
    char stringEpoch [80];
    tm *tm_time = localtime(&timeEpoch);
    // MM:dd:yyyy hh:mm:ss -> %m:%d:%Y %H:%M:%S
    strftime(stringEpoch, 80, "%m:%d:%Y %H:%M:%S",tm_time);
    // (MM:dd:yyyy hh:mm:ss).uS
    printf("%s.%06ld", stringEpoch, elapsed);
}

/** listARP
 * Accesses and prints all ARP machine information contained within the packet_info struct map
 */
void wire_analyze::listARP() {
    // Write ARP machines to a list
    for (int i = 1; i <= packetInfo.size(); i++) {
        if (ntohs(packetInfo.at(i).eth_info.ether_type) == ETHERTYPE_ARP) {
            ARP_machines.push_front(packetInfo.at(i));
        }
    }
    printf("List of ARP Machines:\n");
    std::list<prog_output>::iterator it = ARP_machines.end();
    while (it != ARP_machines.begin()) {
        prog_output machine = *it;
        printARP(machine);
        --it;
    }
    prog_output machine = *it;
    if (ARP_machines.size()) printARP(machine);
    else printf("[NONE FOUND]\n");
}

/** printARP
 * Formats and prints the relevant ARP data
 *
 * @param machine: ARP machine input
 */
void wire_analyze::printARP(prog_output machine) {
    uint8_t* MAC_source = machine.arp_machine_info.arp_sha;
    uint8_t* MAC_destination = machine.arp_machine_info.arp_tha;
    uint8_t* IP_source = machine.arp_machine_info.arp_spa;
    uint8_t* IP_destination = machine.arp_machine_info.arp_tpa;
    printf("MAC Source: %s | ", ether_ntoa((const struct ether_addr *)MAC_source));
    printf("MAC Destination: %s\n", ether_ntoa((const struct ether_addr *)MAC_destination));
    printf("IP Source Address: %s | ", inet_ntoa(*(struct in_addr *)IP_source));
    printf("IP Destination Address: %s\n", inet_ntoa(*(const struct in_addr *)IP_destination));
    printf("ARP Hardware Type: %u\n", machine.arp_machine_info.ea_hdr.ar_hrd);
    printf("ARP Protocol Type: %u\n", machine.arp_machine_info.ea_hdr.ar_pro);
    printf("ARP Hardware Address Length: %u\n", machine.arp_machine_info.ea_hdr.ar_hln);
    printf("ARP Protocol Address Length: %u\n", machine.arp_machine_info.ea_hdr.ar_pln);
    printf("ARP Protocol: %d\n", ntohs(machine.arp_machine_info.ea_hdr.ar_op));
}
/** uniqueEths
 * Casts, formats and prints the src and dest eth addresses for a given packet
 *
 * @param indx: an index for the packet for testing purposes
 */
void wire_analyze::uniqueEths(int indx) {
    uint8_t* sender = packetInfo.at(indx).eth_info.ether_shost;
    uint8_t* receiver = packetInfo.at(indx).eth_info.ether_dhost;
    printf("eth source %s\n", ether_ntoa((const struct ether_addr *)sender));
    printf("ethernet header destination %s\n", ether_ntoa((const struct ether_addr *)receiver));
}
/** uniqueIPs
 * Casts, formats and prints the src and dest IP addresses for a given packet
 *
 * @param indx: an index for the packet for testing purposes
 */
void wire_analyze::uniqueIPs(int indx) {
    struct in_addr sender = packetInfo.at(indx).ip_info.ip_src;
    struct in_addr receiver = packetInfo.at(indx).ip_info.ip_dst;
    printf("ip source %s\n", inet_ntoa(sender));
    printf("ip dest   %s\n", inet_ntoa(receiver));
}
/** uniqueEths
 * Casts, formats and prints the src and dest udp ports for a given packet
 *
 * @param indx: an index for the packet for testing purposes
 */
void wire_analyze::uniqueUDPports(int indx) {
   uint16_t sender = packetInfo.at(indx).udp_info.source;
   uint16_t receiver = packetInfo.at(indx).udp_info.dest;
   printf("udp src port %u\n", ntohs(sender));
   printf("udp dest port %u\n", ntohs(receiver));
}
/** mapUDPports
 * Casts and maps the src and dest udp ports for all packets
 * this way, the map is able to count how many of the same UDP port
 * then, prints out the mapping data
 */
void wire_analyze::mapUDPports() {
   for (int i = 1; i <= packetInfo.size(); i++ ) {
        uint16_t senderKey = ntohs(packetInfo.at(i).udp_info.source);
	uint16_t receiverKey = ntohs(packetInfo.at(i).udp_info.dest);      
	if (udp_senderMap.find(senderKey) != udp_senderMap.end()) {
	    udp_senderMap[senderKey]++;
	} else {
	    udp_senderMap.insert({senderKey, 1});
	}
	if (udp_receiverMap.find(receiverKey) != udp_receiverMap.end()) {
	    udp_receiverMap[receiverKey]++;
	} else {
	    udp_receiverMap.insert({receiverKey, 1});
	}
   }	   
   std::map<uint16_t, int>::iterator it = udp_senderMap.begin();
   while (it != udp_senderMap.end()) {
	std::cout << "src udp port " << it->first << " in " << it->second << " packets" << std::endl;
	++it;
   }
   std::map<uint16_t, int>::iterator itr = udp_receiverMap.begin();
   while (itr != udp_receiverMap.end()) {
        std::cout << "dest udp port " << itr->first << " in " << itr->second << " packets" << std::endl;      
      	++itr;
   }
}
/** mapIP
 * casts and maps the src and dest IP addresses for all packets
 * this way, the map is able to count how many of the same IP address for src & dest
 * then, prints out the mapping data
 */
void wire_analyze::mapIP() {
   for (int i = 1; i <= packetInfo.size(); i++) {
	std::string senderKey = inet_ntoa(packetInfo.at(i).ip_info.ip_src);
	std::string receiverKey = inet_ntoa(packetInfo.at(i).ip_info.ip_dst);
        if(ip_senderMap.find(senderKey) != ip_senderMap.end()) {
	   ip_senderMap[senderKey]++;
	} else {
	   ip_senderMap.insert({senderKey, 1});
	}
	if(ip_receiverMap.find(receiverKey) != eth_receiverMap.end()) {
	   ip_receiverMap[receiverKey]++;
	} else {
	   ip_receiverMap.insert({receiverKey, 1});
	}
   }	
   std::map<std::string, int>::iterator it = ip_senderMap.begin();
   while (it != ip_senderMap.end()) {
      std::cout << "src ip addr " << it->first << " in " << it->second << " packets" << std::endl;
      ++it;
   }
   std::map<std::string, int>::iterator itr = ip_receiverMap.begin();
   while (itr != ip_receiverMap.end()) {
      std::cout << "dest ip addr " << itr->first << " in " << itr->second << " packets" << std::endl;
      ++itr;
   }	   
}
/** mapEth
 * Casts and maps the src and dest ethernet addresses for all packets
 * this way, the map is able to count how many of the same MAC address
 * then, prints out the mapping data
 */
void wire_analyze::mapEth() {
   for (int i = 1; i <= packetInfo.size(); i++) {
	std::string senderKey = ether_ntoa((const struct ether_addr*)packetInfo.at(i).eth_info.ether_shost);
	std::string receiverKey = ether_ntoa((const struct ether_addr*)packetInfo.at(i).eth_info.ether_dhost);
	if(eth_senderMap.find(senderKey) != eth_senderMap.end()) { 
	    eth_senderMap[senderKey]++;
	} else {
	    eth_senderMap.insert({senderKey, 1});
	}
	if(eth_receiverMap.find(receiverKey) != eth_receiverMap.end()) {
	    eth_receiverMap[receiverKey]++;
	} else {
	    eth_receiverMap.insert({receiverKey, 1});
	}
   }
   std::map<std::string, int>::iterator it = eth_senderMap.begin();
   while (it != eth_senderMap.end()) {
	std::cout << "src eth addr " << it->first << " in " << it->second << " packets" << std::endl;
	++it;
   }
   std::map<std::string, int>::iterator itr = eth_receiverMap.begin();
   while (itr != eth_receiverMap.end()) {
	std::cout << "dest eth addr " << itr->first << " in " << itr->second << " packets" << std::endl;
	++itr;
   }
}