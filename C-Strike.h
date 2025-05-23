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
int SYN_flood(char* target,unsigned short port,unsigned int msg_len, time_t duration);
int UDP_flood(char* target,unsigned short port,unsigned int msg_len, time_t duration);
int ICMP_flood(char* target,unsigned short port,unsigned int msg_len, time_t duration);
int HTTP_flood(char* target,unsigned short port, unsigned int msg_len, time_t duration);
