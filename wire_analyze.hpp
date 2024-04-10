#include <map>
#include "wire_handlers.h"
#include <cstring>
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
    void setPacket(struct prog_output);
    void testPrint();
    void printTime(int);
    void printPackets(void);
    void uniqueEths(int);
    void mapEth();
    void uniqueIPs(int);
    void mapIP();
};
