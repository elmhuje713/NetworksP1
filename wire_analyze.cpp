#include <iostream>
#include <string>
#include <vector>
// create a list of machines participating in ARP
struct ARP_info {
	std::string MAC_address;	// their associated MAC address
	std::string IP_address;	//  their associated IP address
	// u_int16_t 
	// constructor
	ARP_info(std::string MAC_address, std::string IP_address) : MAC_address(MAC_address), IP_address(IP_address) {}
};

//struct packet_info {
	// start date and time of packet capture
	// duration of packet capture in seconds with microsecond resolution
	// total number of packets
	// 1 list for unique senders
	// total number of packets associated with unique senders
	// 1 list for  unique recipients
	// total number of packets associated with uniqeu recipients

	// list of machines participating in ARP
	// their associated MAC addresses
	// their associated IP addresses

	// 1 list of UDP unique source ports seen
	// 1 list of UDP unique destination ports seen

	// average packet size
	// minimum packet size
	// maximum packet size 

//	packet_info(int 
//};

int main() {
	std::string line;
	while(std::getline(std::cin, line)) {
		std::cout << "line" << std::endl;
		std::cout << line << std::endl;
	}
	return 0;
}
