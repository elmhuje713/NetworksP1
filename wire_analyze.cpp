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

void wire_analyze::testPrint() {
	std::map<int, struct prog_output>::iterator it = packetInfo.begin();
 
    // Iterate through the map and print the elements
    while (it != packetInfo.end()) {
        std::cout << "Key: " << it->first
             << ", Value: " << (it->second).packet_number << std::endl;
        ++it;
    }
}
 

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