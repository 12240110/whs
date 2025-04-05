#include <pcap.h>
#include <ctype.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "myheader.h"

void print_mac(u_char *mac) {
	printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	struct ethheader *eth = (struct ethheader *)packet;
	struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
	struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + (ip->iph_ihl * 4));

	printf("Ethernet Header:\n");
	printf("Source MAC: ");
	print_mac(eth->ether_shost);
	printf("\n");
	printf("Destination MAC: ");
	print_mac(eth->ether_dhost);
	printf("\n");
	printf("EtherType: 0x%04x\n", ntohs(eth->ether_type));

	printf("IP Header:\n");
	printf("Source IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->iph_sourceip));
	printf("Destination IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->iph_destip));

	printf("TCP Header:\n");
	printf("Source Port: %d\n", ntohs(tcp->tcp_sport));
	printf("Destination Port: %d\n", ntohs(tcp->tcp_dport));

	int payload_len = header->len - sizeof(struct ethheader) - (ip->iph_ihl * 4) - (tcp->tcp_offset * 4);
	if (payload_len > 0) {
		printf("Message:\n");
		for (int i = 0; i < payload_len; i++) {
			if (isprint(packet[sizeof(struct ethheader) + (ip->iph_ihl * 4) + (tcp->tcp_offset * 4) + i])) {
				printf("%c", packet[sizeof(struct ethheader) + (ip->iph_ihl * 4 ) + (tcp->tcp_offset * 4) + i]);
			} else {
				printf(".");
			}
		}
		printf("\n");
	}
}

int main() {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	const char *device = "ens33";
	const char *filter_exp = "tcp";
	
	handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Error opening device %s: %s\n", device, errbuf);
		return 1;
	}

	struct bpf_program filter;
	if (pcap_compile(handle, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
		fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
		pcap_close(handle);
		return 1;
	}
	if (pcap_setfilter(handle, &filter) == -1) {
		fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
		pcap_freecode(&filter);
		pcap_close(handle);
		return 1;
	}

	printf("Starting packet capture on device %s...\n", device);
	pcap_loop(handle, 10, packet_handler, NULL);

	pcap_freecode(&filter);
	pcap_close(handle);
	printf("Packet capture complete.\n");

	return 0;
}


