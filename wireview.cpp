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
	//struct prog_output my_output;
//	struct prog_output* outputs = (struct prog_output*) malloc(1 * sizeof(struct prog_output*)); 
//	struct prog_output* outputs[1];
	struct prog_output** outputs = (struct prog_output**)malloc(ARRAY_SIZE * sizeof(struct prog_output*));
	for (int i = 0; i < ARRAY_SIZE; i++) {
    		outputs[i] = (struct prog_output*)malloc(sizeof(struct prog_output));y
	}

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
			
			analyze.setPacket(*outputs[i]);
			analyze.testPrint();
		//printf("My output: %d\n ", my_output.packet_number);
			printf("May output: %d\n ", outputs[i]->packet_number);
		}
	}
	for (int i = 0; i < 4; i++) {
    		free(outputs[i]);
	}

	pcap_close(handle);

	return 0;
}
