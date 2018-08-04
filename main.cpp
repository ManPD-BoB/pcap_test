#include <pcap.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#define ETHERTYPE_IP 0x0800

// Define Header
typedef struct TCP_Header
{
	u_short src_port;
	u_short dst_port;
	u_int seq_num;
	u_int ack_num;
	u_char reserved : 4;
	u_char h_length : 4;
	u_char flag;
	u_short window;
	u_short checksum;
	u_short urgent;
}TCP_Header;

typedef struct IP_Header
{
	u_char h_length : 4;
	u_char version : 4;
	u_char service;
	u_short t_length;
	u_short ident;
	u_short flag;
	u_char ttl;
	u_char protocol;
	u_short checksum;
	u_char src_addr[4];
	u_char dst_addr[4];
}IP_Header;

typedef struct Ethernet
{
	u_char dst_mac[6];
	u_char src_mac[6];
	short type;
}Ethernet;

void usage() {
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
	// nedd 2 argv
	if (argc != 2) {
		usage();
		return -1;
	}

	// Info Creator
	char track[] = "컨설팅";
	char name[] = "김만수";
	printf("[bob7][%s]pcap_test[%s]\n", track, name);

	// Network Device
	char* dev = argv[1];

	Ethernet *eth;
	IP_Header *iph;
	TCP_Header *tcph;

	// Error ?
	char errbuf[PCAP_ERRBUF_SIZE];

	// Find Packet session, no session -> return false
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	// True code
	while (true) {
		struct pcap_pkthdr* header;							// pcap header
		const u_char* packet;								// real packet
		int res = pcap_next_ex(handle, &header, &packet);	// receive packet
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
		
		eth = (struct Ethernet*)packet;

		printf("========================================================\n");
		printf("Ethernet Header\n");
		printf("\tSource MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", eth->src_mac[0], eth->src_mac[1], eth->src_mac[2], eth->src_mac[3], eth->src_mac[4], eth->src_mac[5]);
		printf("\tDestination MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", eth->dst_mac[0], eth->dst_mac[1], eth->dst_mac[2], eth->dst_mac[3], eth->dst_mac[4], eth->dst_mac[5]);

		// Ethernet Header -> IP -> TCP -> HTTP
		if (ntohs(eth->type) == ETHERTYPE_IP)
		{	
			// IP Header
			// packet 구조체에서 +14만큼 이동한 부분부터 IP헤더의 부분
			iph = (IP_Header*)(packet + 14);
			u_char iph_length = iph->h_length;
			u_char iph_tlength = iph->t_length;
			
			printf("IP Header\n");
			printf("\tSource IP : %d.%d.%d.%d\n", iph->src_addr[0], iph->src_addr[1], iph->src_addr[2], iph->src_addr[3]);
			printf("\tDestination IP : %d.%d.%d.%d\n", iph->dst_addr[0], iph->dst_addr[1], iph->dst_addr[2], iph->dst_addr[3]);

			if (ntohs(iph->protocol == 0x06))
			{
				// TCP Header
				// packet 구조체에서 +14만큼 이동하고 +20만큼 이동한 부분부터 TCP 헤더부분
				// IP헤더의 HeaderLength값을 4배수하면 총 IP헤더의 크기가 나옴
				tcph = (TCP_Header*)(packet + 14 + (iph_length) * 4);
				u_char tcph_length = tcph->h_length;
				
				printf("TCP Header\n");
				printf("\tSource Port : %d\n", htons(tcph->src_port));
				printf("\tDestination Port : %d\n", htons(tcph->dst_port));

				// If, No packet data
				if (ntohs(iph_length) - (iph_length * 4) - (tcph_length * 4) <16)
				{
					for (int i = 14 + (iph_length * 4) + (tcph_length * 4); i<14 + ntohs(iph_tlength); i++)
					{
						if ((i - 14 - iph_length * 4 - tcph_length * 4) % 16 == 0)
						{
							printf("\n");
						}
						printf("%02x ", packet[i]);
					}
					printf("\n");
				}
				// Exist packet data
				else
				{
					int loc = 14 + (iph_length * 4) + (tcph_length * 4);

					for (int i = 0; i<16; i++)
						printf("%02x ", packet[loc + i]);
					printf("\n");
				}
			}
		}
		printf("%u bytes captured\n\n", header->caplen);
		printf("========================================================\n");
	}

	pcap_close(handle);
	return 0;
}
