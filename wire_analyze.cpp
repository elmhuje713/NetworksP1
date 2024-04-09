#include <iostream>
#include <string>
#include <vector>
// #include <map>
// #include "wire_handlers.h"
#include "wire_analyze.hpp"


wire_analyze::wire_analyze() {

}

void wire_analyze::setPacket(struct prog_output packet) {
	packetInfo.insert({packetNum++, packet});
}

void wire_analyze::printPackets() {
    time_t sec = packetInfo.at(1).packet_time_info.ts.tv_sec;
    suseconds_t usec = packetInfo.at(1).packet_time_info.ts.tv_usec;

    for (int i = 1; i <= packetInfo.size(); i++) {
        time_t curr_sec = packetInfo.at(i).packet_time_info.ts.tv_sec;
        suseconds_t curr_usec = packetInfo.at(i).packet_time_info.ts.tv_usec;
        time_t elapsed_sec = curr_sec - sec;
        suseconds_t elapsed_usec = curr_usec - usec;
        // If usec is negative, add 1 sec of time to usec
        if (elapsed_usec <0) {
            elapsed_sec--;
            elapsed_usec += 1000000;
        }
        printf("%d ", i);
        printTime(i);
        printf(" %ld.%06ld", elapsed_sec, elapsed_usec);
        printf(" %d\n", packetInfo.at(i).packet_time_info.len);
    }
}

void wire_analyze::testPrint() {
	std::map<int, struct prog_output>::iterator it = packetInfo.begin();
 
    // Iterate through the map and print the elements
    while (it != packetInfo.end()) {
        std::cout << "Key: " << it->first
             << ", Value: " << (it->second).packet_number << std::endl;
        ++it;
    }
}

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
/**
void wire_analyze::setEth(struct prog_output packet) {
	ethInfo.insert({packet.eth_info});
}

void wire_analyze::uniqueEths() {
	std::map<struct eth_header, int>::iterator c = ethInfo.begin();

	while (c != ethInfo.end()) {
		std::cout << "Sender: " << c->ether_shost << std::endl;
		std::cout << "Recipient: " << c->ether_dhost << std::endl;
		++c;
	}
}
*/
// int main() {

// 	std::map<int, struct prog_output> packetInfo;

// 	struct prog_output a;
// 	a.packet_number = 1;
// 	struct prog_output b;
// 	b.packet_number = 100;

// 	packetInfo[8] = a;
// 	packetInfo[42] = b;

// 	// Get an iterator pointing to the first element in the
//     // map
    // std::map<int, struct prog_output>::iterator it = packetInfo.begin();
 
    // // Iterate through the map and print the elements
    // while (it != packetInfo.end()) {
    //     std::cout << "Key: " << it->first
    //          << ", Value: " << (it->second).packet_number << std::endl;
    //     ++it;
    // }

// 	/*
// 	std::string line;
// 	while(std::getline(std::cin, line)) {
// 		std::cout << "line" << std::endl;
// 		std::cout << line << std::endl;
// 	}
// 	*/
// 	return 0;
// }
