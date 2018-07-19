all : packet_capture

packet_capture: packet_capture.o
	g++ -g -o packet_capture packet_capture.o -lpcap
	rm -rf *.o

packet_capture.o:
	g++ -g -c -o packet_capture.o packet_capture.cpp

clean:
	rm -f packet_capture
	rm -f *.o

