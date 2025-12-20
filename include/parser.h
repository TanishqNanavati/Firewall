#ifndef PARSER_H
#define PARSER_H
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Ethernet Header
struct EthHeader{
    uint8_t dest[6];
    uint8_t src[6];
    uint16_t ethertype;
}__attribute__((packed));

// ARP Header Format
struct ARPHeader{
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t oper;
    uint8_t sha[6];
    uint8_t spa[4];
    uint8_t tha[6];
    uint8_t tpa[4];
}__attribute__((packed));

// IPv4 header
struct IPv4Header{
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t saddr;
    uint32_t daddr;
}__attribute__((packed));

// TCP Header
struct TCPHeader{
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint16_t doff_res_flags;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
}__attribute__((packed));

// UDP Header
struct UDPHeader{
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t checksum;
}__attribute__((packed));

// ICMP Header
struct ICMPHeader{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t rest;
}__attribute__((packed));

// Protocol constants
#define PROTO_ICMP 1
#define PROTO_TCP 6
#define PROTO_UDP 17

// Ethertype constants
#define ETH_P_IP 0x0800
#define ETH_P_ARP 0x0806

// Print functions
void print_eth(const uint8_t* pkt, size_t size);
void print_arp(const uint8_t* pkt, size_t size);
void print_ip(const uint8_t* pkt, size_t size);
void print_tcp(const uint8_t* pkt, size_t size, size_t ip_header_len);
void print_udp(const uint8_t* pkt, size_t size, size_t ip_header_len);
void print_icmp(const uint8_t* pkt, size_t size, size_t ip_header_len);

typedef struct {
    int match_tcp;
    int match_udp;
    int match_icmp;
    int match_arp;
    int has_src_ip;
    uint32_t src_ip;
    int has_dst_ip;
    uint32_t dst_ip;
    int has_src_port;
    uint16_t src_port;
    int has_dst_port;
    uint16_t dst_port;
} SimpleFilter;

void parse_filter_expression(const char* expr, SimpleFilter* out);
int packet_matches_filter(const uint8_t* pkt, size_t size, const SimpleFilter* f);

#ifdef __cplusplus
}
#endif

#endif // PARSER_H