all: wireview

wireview: wireview.o wire_handlers.o
	gcc -o  wireview wireview.o wire_handlers.o -lpcap

wireview.o: wireview.c wire_handlers.h
	gcc -c  wireview.c

wire_handlers.o: wire_handlers.c wire_handlers.h
	gcc -c wire_handlers.c

clean:
	rm -f wireview wireview.o wire_handlers.o
