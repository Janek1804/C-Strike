//C-Strike: a security research for flooding
//Copyright (C) 2025  Jan Kałucki
#include <time.h>
struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};
struct icmp_header{
    u_int8_t type;
    u_int8_t code;
    u_int16_t checksum;
};
struct dns_header{
    u_int16_t transaction_id;
    u_int16_t flags;
    u_int16_t num_questions;
    u_int16_t num_answers;
    u_int16_t num_auth_rr;
    u_int16_t num_add_rr;
};
struct dns_query{
    u_int8_t label_len;
    char* label;
    u_int8_t tld_len;
    char* tld;
    u_int16_t type;
    u_int16_t class;
};
int SYN_flood(char* target,char* src, unsigned short port,unsigned int msg_len, time_t duration);
int UDP_flood(char* target, char* src,unsigned short port,unsigned int msg_len, time_t duration);
int ICMP_flood(char* target, char* src,unsigned short port,unsigned int msg_len, time_t duration);
int HTTP_flood(char* target, char* src,unsigned short port, unsigned int msg_len, time_t duration);
int DNS_Amplification(char* target, char* src, unsigned short port, unsigned int msg_len, time_t duration);
int port_scan(char* target, unsigned short port_min, unsigned short port_max);
