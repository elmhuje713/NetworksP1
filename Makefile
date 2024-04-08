all: wireview

wire_analyze: wire_analyze.cpp 
	g++ -o wire_analyze wire_analyze.cpp

wireview: wireview.o wire_handlers.o wire_analyze.o
	g++ -g -o wireview wireview.o wire_handlers.o wire_analyze.o -lpcap

wireview.o: wireview.cpp wire_handlers.h wire_analyze.hpp
	g++ -g -c wireview.cpp

wire_handlers.o: wire_handlers.c wire_handlers.h
	gcc -c wire_handlers.c

wire_analyze.o: wire_analyze.cpp wire_analyze.hpp
	g++ -c wire_analyze.cpp

clean:
	rm -f wireview wire_analyze *.o
