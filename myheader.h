#ifndef MYHEADER_H
#define MYHEADER_H

#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

struct ethheader {
	u_char ether_dhost[6];
	u_char ether_shost[6];
	u_short ether_type;
};

struct ipheader {
	unsigned char iph_ihl:4,
		      iph_ver:4;
	unsigned char iph_tos;
	unsigned short int iph_len;
	unsigned short int iph_ident;
	unsigned short int iph_flag:3,
		       iph_offset:13;
	unsigned char iph_ttl;
	unsigned char iph_protocol;
	unsigned short int iph_chksum;
	unsigned int iph_sourceip;
	unsigned int iph_destip;
};

struct tcpheader {
	unsigned short int tcp_sport;
	unsigned short int tcp_dport;
	unsigned int tcp_seq;
	unsigned int tcp_ack;
	unsigned char tcp_reserved:4,
		      tcp_offset:4;
	unsigned char tcp_flags;
	unsigned short int tcp_window;
	unsigned short int tcp_chksum;
	unsigned short int tcp_urgptr;
};

#endif
