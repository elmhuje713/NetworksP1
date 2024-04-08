#include <iostream>
#include <pcap.h>
#include "wire_handlers.h"
#include "wire_analyze.hpp"

int main (int argc, char *argv[]) {
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <pcap>\n", argv[0]);
		return 1;
	}

	wire_analyze analyze;
	struct prog_output* outputs[4];
	const char *filename = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;

	handle = pcap_open_offline(argv[1], errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Error opening file: %s\n", errbuf);
		return 1;
	}
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "File does not contain Ethernet data\n");
		return 1;
	}
	//if (pcap_loop(handle, -1, callback, (u_char*)&my_output) < 0) {
	if (pcap_loop(handle, -1, callback, (u_char*)outputs) < 0) {
		fprintf(stderr, "Error reading packets: %s\n", pcap_geterr(handle));
		return 1;
	} else {
		//analyze.setPacket(my_output);
		//int length_array = sizeof(outputs) / sizeof(struct prog_output);
		int length_array = 4;
		for (int i = 0; i < length_array; i++) {
			
//			analyze.setPacket(*outputs[i]);
//			analyze.testPrint();
			printf("May output: %d\n ", outputs[0]->packet_number);
		}
	}
	for (int i = 0; i < 4; i++) {
    		free(outputs[i]);
	}

	pcap_close(handle);

	return 0;
}
