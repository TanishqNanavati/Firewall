#ifndef FIREWALL_RULES_H
#define FIREWALL_RULES_H
#include <stdint.h>
#include <stddef.h>

#define MAX_RULES 200
#define RULE_CONFIG_FILE "firewall_rules.conf"

typedef enum{
    ACCEPT,
    DROP,
    REJECT
}action_t;

// IP range with CIDR support
typedef struct {
    uint32_t network;   // address in host byte order
    uint32_t mask;
    uint8_t prefix;     // no. of network bits
}ip_range_t;

typedef struct{
    uint16_t start;     // port from (0 - 65535)
    uint16_t end;
}port_range_t;

typedef struct{
    int priority;
    int match_src_ip;
    ip_range_t src_ip_range;
    int match_dst_ip;
    ip_range_t dst_ip_range;
    int match_src_port;
    port_range_t src_port_range;
    int match_dst_port;
    port_range_t dst_port_range;
    int match_protocol;
    uint8_t protocol;
    action_t action;
    int enabled;
    char description[128];
    unsigned long hit_count;
}firewall_rule_t;

typedef struct{
    uint32_t src_ip;    // host byte order
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
}packet_info_t;

// Core functions
void init_rules(void);
int add_rule_v2(const firewall_rule_t *rule);
int add_rule(uint32_t src_ip,uint32_t dst_ip,uint16_t src_port,uint16_t dst_port,uint8_t protocol,action_t action,const char* description);
action_t evaluate_packet(const packet_info_t *pkt);
void print_rules(void);
int parse_packet_info(const uint8_t *packet,size_t len,packet_info_t *info);

// Rule management
int remove_rule(int rule_id);
int enable_rule(int rule_id);
int disable_rule(int rule_id);
void print_rule_statistics(void);

// Config file
int load_rules_from_file(const char *filename);
int reload_rules(void);
void save_rules_to_file(const char *filename);

// Helpers
int parse_cidr(const char*cidr_str,ip_range_t *range);
int parse_port_range(const char*port_str,port_range_t *range);
int ip_in_range(uint32_t ip,const ip_range_t *range);
int port_in_range(uint16_t port,const port_range_t *range);

#endif
