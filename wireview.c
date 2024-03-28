#include <stdio.h>
#include <pcap.h>
#include "wire_handlers.h"

int main (int argc, char *argv[]) {
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <pcap>\n", argv[0]);
		return 1;
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
	if (pcap_loop(handle, -1, callback, NULL) < 0) {
		fprintf(stderr, "Error reading packets: %s\n", pcap_geterr(handle));
		return 1;
	}

	pcap_close(handle);

	return 0;
}