#include <map>
#include "wire_handlers.h"
#include <cstring>
#include <list>
#include <arpa/inet.h>
class wire_analyze {

    private:

    int packetNum = 1;

    public:

    wire_analyze(void);
    std::map<int, struct prog_output> packetInfo;
    std::map<std::string, int> eth_senderMap;
    std::map<std::string, int> eth_receiverMap;
    std::map<std::string, int> ip_senderMap;
    std::map<std::string, int> ip_receiverMap;
    std::map<uint16_t, int> udp_senderMap;
    std::map<uint16_t, int> udp_receiverMap;
    std::list<struct prog_output> ARP_machines;
    void setPacket(struct prog_output);
    void testPrint();
    void printTime(int);
    void printPackets(void);
    void uniqueEths(int);
    void mapEth();
    void uniqueIPs(int);
    void mapIP();
    void uniqueUDPports(int);
    void mapUDPports();
    void printARP(void);
};
