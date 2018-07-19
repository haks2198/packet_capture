#include <pcap.h>
#include <stdio.h>
#include <unistd.h>

#define ETHERNET	0
#define PROTOCOL	1

#define TCP	1
#define UDP	2
#define ICMP	3
#define IGMP	4
#define EGP	5
#define OSPF	6

#define IPV4	1
#define IPV6	2
#define ARP	3

#define UNKNOWN 9

void usage() {
  printf("syntax: packet_capture <interface>\n");
  printf("sample: packet_capture wlan0\n");
  printf("sample: packet_capture eth0\n");
}
void printAddr(const u_char* packet){
	long dstMacOffset = 0x00;	//Destination MAC Offset : 0
	long srcMacOffset = 0x06;	//Source MAC Offset : 6
	long srcIpOffset = 0x1a;	//Source IP Offset ; 26
	long dstIpOffset = 0x1e;	//Destination IP Offset : 30
	int ipSize = 4;
	int macSize = 6;

	printf("Source Address\t\t: ");
	for(int i=0 ; i<ipSize ; i++){
		printf("%d", packet[srcIpOffset+i]);
		if(i != ipSize-1) printf(".");
		else printf(" / ");
	}
	for(int i=0 ; i<macSize ; i++){
		printf("%02x", packet[srcMacOffset+i]);
		if(i != macSize-1) printf(":");
		else printf("\n");
	}

	printf("Destination Address\t: ");
	for(int i=0 ; i<ipSize ; i++){
		printf("%d", packet[dstIpOffset+i]);
		if(i != ipSize-1) printf(".");
		else printf(" / ");
	}
	for(int i=0 ; i<macSize ; i++){
		printf("%02x", packet[dstMacOffset+i]);
		if(i != macSize-1) printf(":");
		else printf("\n");
	}
}

void getEthType(int *flag, const u_char* packet){
	long ethernetTypeOffset = 0x0c;	// Ethernet Type Offset : 12
	
	if(packet[ethernetTypeOffset] == 0x08 && packet[ethernetTypeOffset+1] == 0x00){
		flag[ETHERNET] = IPV4;
	}else if(packet[ethernetTypeOffset] == 0x08 && packet[ethernetTypeOffset+1] == 0x06){
		flag[ETHERNET] = ARP;
	}else if(packet[ethernetTypeOffset] == 0x86 && packet[ethernetTypeOffset+1] == 0xDD){
		flag[ETHERNET] = IPV6;
	}else{
		flag[ETHERNET] = UNKNOWN;
	}
}

void printPort(const u_char* packet){
	long srcPortOffset = 0x22;	//Source Port Offset : 34
	long dstPortOffset = 0x24;	//Destination Port Offset : 36

	printf("Source Port\t\t: %d\n", packet[srcPortOffset]*256 + packet[srcPortOffset+1]);
	printf("Destination Port\t: %d\n", packet[dstPortOffset]*256 + packet[dstPortOffset+1]);
}

void getProType(int *flag, const u_char* packet){
	long protocolTypeOffset = 0x17;	// Protocol Type Offset : 23

	if(packet[protocolTypeOffset] == 0x01) flag[PROTOCOL] = ICMP; 
	else if(packet[protocolTypeOffset] == 0x02) flag[PROTOCOL] = IGMP;
	else if(packet[protocolTypeOffset] == 0x06) flag[PROTOCOL] = TCP;
	else if(packet[protocolTypeOffset] == 0x08) flag[PROTOCOL] = EGP;
	else if(packet[protocolTypeOffset] == 0x11) flag[PROTOCOL] = UDP;
	else if(packet[protocolTypeOffset] == 0x59) flag[PROTOCOL] = OSPF;
	else flag[PROTOCOL] = UNKNOWN;
}

void printData(int *flag, const u_char* packet, int cap_size){
	long ethHeaderSize = 0xe;	// Ethernet Header Size : 14
	long ipv4HeaderSize = 0x14;	// IPv4 Header Size : 20
	long ipv6HeaderSize = 0x28;	// IPv6 Header Size : 40
	long tcpHeaderSize = 0x20;	// TCP Header Size : 32
	long udpHeaderSize = 0x8;	// UDP Header Size : 8
	long dataOffset = ethHeaderSize;
	
	// Caculation Data Offset
	if(flag[ETHERNET] == IPV4){
		dataOffset += ipv4HeaderSize;
		if(flag[PROTOCOL] == TCP){
			dataOffset += tcpHeaderSize;
		}else if(flag[PROTOCOL] == UDP){
			dataOffset += udpHeaderSize;
		}
	}else if(flag[ETHERNET] == IPV6){
		dataOffset += ipv6HeaderSize;
		if(flag[PROTOCOL] == TCP){
			dataOffset += tcpHeaderSize;
		}else if(flag[PROTOCOL] == UDP){
			dataOffset += udpHeaderSize;
		}
	}

	// Data Print
	printf("Data : ");
	for(int i=0 ; i<cap_size-dataOffset ; i++){
		if(i%16 == 0) printf("\n");
		printf("%02x ", packet[dataOffset+i]);
	}
	printf("\n");
}

void printTypeInfo(int *flag){
	printf("Ethernet Type\t\t: ");
	if(flag[ETHERNET] == IPV4) printf("IPv4");
	else if(flag[ETHERNET] == IPV6) printf("IPv6");
	else if(flag[ETHERNET] == ARP) printf("ARP");
	else if(flag[ETHERNET] == UNKNOWN) printf("Unknown");
	printf("\n");

	printf("Protocol Type\t\t: ");
	if(flag[PROTOCOL] == ICMP) printf("ICMP");
	else if(flag[PROTOCOL] == IGMP) printf("IGMP");
	else if(flag[PROTOCOL] == TCP) printf("TCP");
	else if(flag[PROTOCOL] == EGP) printf("EGP");
	else if(flag[PROTOCOL] == UDP) printf("UDP");
	else if(flag[PROTOCOL] == OSPF) printf("OSPF");
	printf("\n");

}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    	struct pcap_pkthdr *pkt_header;
    	const u_char* packet;
    	int res = pcap_next_ex(handle, &pkt_header, &packet);
	int cap_size = pkt_header->caplen;
	int flag[2] = {0, 0};	//index 1 : Ethernet Type, index 2 : Protocol Type
    	if (res == 0) continue;
    	if (res == -1 || res == -2) break;
	
	printf("=================================================\n");
	printf("%u bytes captured\n", cap_size);
	
	getEthType(flag, packet);
	getProType(flag, packet);
	printTypeInfo(flag);
	printAddr(packet);
	printPort(packet);
	printData(flag, packet, cap_size);
	sleep(1);
  }

  pcap_close(handle);
  return 0;
}
