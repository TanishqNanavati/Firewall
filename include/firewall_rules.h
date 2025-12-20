#ifndef FIREWALL_RULES_H
#define FIREWALL_RULES_H

#include <stdint.h>
#include <stddef.h>   

#define MAX_RULES 100

typedef enum{
    ACCEPT,
    DROP
}action_t;

typedef struct{
    // network byte order
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    action_t action;
    int enabled;
    char description[64];
}firewall_rule_t;

typedef struct{
    // host byte order
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
}packet_info_t;

void init_rules(void);
int add_rule(uint32_t src_ip,uint32_t dst_ip,uint16_t src_port,uint16_t dst_port,uint8_t protocol,action_t action,const char* description);
action_t evaluate_packet(const packet_info_t *pkt);
void print_rules(void);
int parse_packet_info(const uint8_t *packet,size_t len,packet_info_t *info);

#endif