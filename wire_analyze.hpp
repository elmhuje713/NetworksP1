#include <map>
#include "wire_handlers.h"

class wire_analyze {

    private:

    int packetNum = 1;

    public:

    wire_analyze(void);
    std::map<int, struct prog_output> packetInfo;
    void setPacket(struct prog_output);
    void testPrint();
    void printTime(int);

};