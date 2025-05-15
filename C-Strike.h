#include <cstdint>
int SYN_flood(char* target,uint8_t n_proc,uint16_t msg_len);
int UDP_flood(char* target,uint8_t n_proc,uint16_t msg_len);
int ICMP_flood(char* target,uint8_t n_proc,uint16_t msg_len);
int HTTP_flood(char* target,uint8_t n_proc, uint16_t msg_len);
