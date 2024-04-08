#include <map>
#include "wire_handlers.h"

class wire_analyze {

    private:

    int packetNum = 1;
   // int count = 0;

    public:

    wire_analyze(void);
    std::map<int, struct prog_output> packetInfo;
    //std::map<struct ether_header, int> ethInfo;
    void setPacket(struct prog_output);
    void testPrint();
    void printTime(int);
//    void setEth(struct prog_output packet);
  //  void uniqueEths();

};
