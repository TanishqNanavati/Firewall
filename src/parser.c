
#include "parser.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

void print_eth(const uint8_t* pkt, size_t size) {
    if (size < sizeof(struct EthHeader)) {
        printf("Packet too small for Ethernet header\n");
        return;
    }

    struct EthHeader* eth = (struct EthHeader*)pkt;
    
    printf("=== Ethernet Header ===\n");
    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->dest[0], eth->dest[1], eth->dest[2],
           eth->dest[3], eth->dest[4], eth->dest[5]);
    printf("Source MAC:      %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->src[0], eth->src[1], eth->src[2],
           eth->src[3], eth->src[4], eth->src[5]);
    printf("EtherType:       0x%04x", ntohs(eth->ethertype));
    
    uint16_t type = ntohs(eth->ethertype);
    if (type == ETH_P_IP) printf(" (IPv4)\n");
    else if (type == ETH_P_ARP) printf(" (ARP)\n");
    else printf(" (Other)\n");
}

void print_arp(const uint8_t* pkt, size_t size) {
    if (size < sizeof(struct EthHeader) + sizeof(struct ARPHeader)) {
        printf("Packet too small for ARP\n");
        return;
    }

    struct ARPHeader* arp = (struct ARPHeader*)(pkt + sizeof(struct EthHeader));
    
    printf("=== ARP Header ===\n");
    printf("Hardware Type: %u\n", ntohs(arp->htype));
    printf("Protocol Type: 0x%04x\n", ntohs(arp->ptype));
    printf("Operation: %u ", ntohs(arp->oper));
    
    if (ntohs(arp->oper) == 1) printf("(Request)\n");
    else if (ntohs(arp->oper) == 2) printf("(Reply)\n");
    else printf("(Unknown)\n");
    
    printf("Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           arp->sha[0], arp->sha[1], arp->sha[2],
           arp->sha[3], arp->sha[4], arp->sha[5]);
    printf("Sender IP:  %u.%u.%u.%u\n",
           arp->spa[0], arp->spa[1], arp->spa[2], arp->spa[3]);
    printf("Target MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           arp->tha[0], arp->tha[1], arp->tha[2],
           arp->tha[3], arp->tha[4], arp->tha[5]);
    printf("Target IP:  %u.%u.%u.%u\n",
           arp->tpa[0], arp->tpa[1], arp->tpa[2], arp->tpa[3]);
}

void print_ip(const uint8_t* pkt, size_t size) {
    if (size < sizeof(struct EthHeader) + sizeof(struct IPv4Header)) {
        printf("Packet too small for IP header\n");
        return;
    }

    struct IPv4Header* ip = (struct IPv4Header*)(pkt + sizeof(struct EthHeader));
    
    printf("=== IPv4 Header ===\n");
    printf("Version:      %u\n", (ip->ver_ihl >> 4) & 0x0F);
    printf("Header Len:   %u bytes\n", (ip->ver_ihl & 0x0F) * 4);
    printf("Total Length: %u\n", ntohs(ip->tot_len));
    printf("Protocol:     %u ", ip->protocol);
    
    if (ip->protocol == PROTO_TCP) printf("(TCP)\n");
    else if (ip->protocol == PROTO_UDP) printf("(UDP)\n");
    else if (ip->protocol == PROTO_ICMP) printf("(ICMP)\n");
    else printf("(Other)\n");
    
    printf("TTL:          %u\n", ip->ttl);
    
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    struct in_addr src = {.s_addr = ip->saddr};
    struct in_addr dst = {.s_addr = ip->daddr};
    inet_ntop(AF_INET, &src, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &dst, dst_ip, INET_ADDRSTRLEN);
    
    printf("Source IP:    %s\n", src_ip);
    printf("Dest IP:      %s\n", dst_ip);
}

void print_tcp(const uint8_t* pkt, size_t size, size_t ip_header_len) {
    size_t offset = sizeof(struct EthHeader) + ip_header_len;
    
    if (size < offset + sizeof(struct TCPHeader)) {
        printf("Packet too small for TCP header\n");
        return;
    }

    struct TCPHeader* tcp = (struct TCPHeader*)(pkt + offset);
    
    printf("=== TCP Header ===\n");
    printf("Source Port:      %u\n", ntohs(tcp->source));
    printf("Dest Port:        %u\n", ntohs(tcp->dest));
    printf("Sequence Number:  %u\n", ntohl(tcp->seq));
    printf("Ack Number:       %u\n", ntohl(tcp->ack_seq));
    
    uint16_t flags = ntohs(tcp->doff_res_flags);
    printf("Flags: ");
    if (flags & 0x020) printf("URG ");
    if (flags & 0x010) printf("ACK ");
    if (flags & 0x008) printf("PSH ");
    if (flags & 0x004) printf("RST ");
    if (flags & 0x002) printf("SYN ");
    if (flags & 0x001) printf("FIN ");
    printf("\n");
    
    printf("Window Size:      %u\n", ntohs(tcp->window));
}


void print_udp(const uint8_t* pkt, size_t size, size_t ip_header_len) {
    size_t offset = sizeof(struct EthHeader) + ip_header_len;
    
    if (size < offset + sizeof(struct UDPHeader)) {
        printf("Packet too small for UDP header\n");
        return;
    }

    struct UDPHeader* udp = (struct UDPHeader*)(pkt + offset);
    
    printf("=== UDP Header ===\n");
    printf("Source Port: %u\n", ntohs(udp->source));
    printf("Dest Port:   %u\n", ntohs(udp->dest));
    printf("Length:      %u\n", ntohs(udp->len));
    printf("Checksum:    0x%04x\n", ntohs(udp->checksum));
}

void print_icmp(const uint8_t* pkt, size_t size, size_t ip_header_len) {
    size_t offset = sizeof(struct EthHeader) + ip_header_len;
    
    if (size < offset + sizeof(struct ICMPHeader)) {
        printf("Packet too small for ICMP header\n");
        return;
    }

    struct ICMPHeader* icmp = (struct ICMPHeader*)(pkt + offset);
    
    printf("=== ICMP Header ===\n");
    printf("Type: %u ", icmp->type);
    
    if (icmp->type == 0) printf("(Echo Reply)\n");
    else if (icmp->type == 8) printf("(Echo Request)\n");
    else if (icmp->type == 3) printf("(Dest Unreachable)\n");
    else if (icmp->type == 11) printf("(Time Exceeded)\n");
    else printf("(Other)\n");
    
    printf("Code: %u\n", icmp->code);
    printf("Checksum: 0x%04x\n", ntohs(icmp->checksum));
}


void parse_filter_expression(const char* expr, SimpleFilter* out) {
    memset(out, 0, sizeof(SimpleFilter));
    
    if (!expr) return;
    
    // Simple string matching for basic filters
    if (strstr(expr, "tcp")) out->match_tcp = 1;
    if (strstr(expr, "udp")) out->match_udp = 1;
    if (strstr(expr, "icmp")) out->match_icmp = 1;
    if (strstr(expr, "arp")) out->match_arp = 1;

}


int packet_matches_filter(const uint8_t* pkt, size_t size, const SimpleFilter* f) {
    if (!f) return 1; // No filter = match all
    
    if (size < sizeof(struct EthHeader)) return 0;
    
    struct EthHeader* eth = (struct EthHeader*)pkt;
    uint16_t ethertype = ntohs(eth->ethertype);
    
    // Check ARP
    if (f->match_arp && ethertype == ETH_P_ARP) return 1;
    
    // For IP packets
    if (ethertype != ETH_P_IP) return 0;
    
    if (size < sizeof(struct EthHeader) + sizeof(struct IPv4Header)) return 0;
    
    struct IPv4Header* ip = (struct IPv4Header*)(pkt + sizeof(struct EthHeader));
    
    // Check protocol filters
    if (f->match_tcp && ip->protocol != PROTO_TCP) return 0;
    if (f->match_udp && ip->protocol != PROTO_UDP) return 0;
    if (f->match_icmp && ip->protocol != PROTO_ICMP) return 0;
    
    // Check IP addresses if specified
    if (f->has_src_ip && ntohl(ip->saddr) != f->src_ip) return 0;
    if (f->has_dst_ip && ntohl(ip->daddr) != f->dst_ip) return 0;
    
    // Check ports for TCP/UDP
    if (f->has_src_port || f->has_dst_port) {
        uint8_t ihl = ip->ver_ihl & 0x0F;
        size_t ip_hdr_len = ihl * 4;
        size_t offset = sizeof(struct EthHeader) + ip_hdr_len;
        
        if (ip->protocol == PROTO_TCP) {
            if (size < offset + sizeof(struct TCPHeader)) return 0;
            struct TCPHeader* tcp = (struct TCPHeader*)(pkt + offset);
            if (f->has_src_port && ntohs(tcp->source) != f->src_port) return 0;
            if (f->has_dst_port && ntohs(tcp->dest) != f->dst_port) return 0;
        } else if (ip->protocol == PROTO_UDP) {
            if (size < offset + sizeof(struct UDPHeader)) return 0;
            struct UDPHeader* udp = (struct UDPHeader*)(pkt + offset);
            if (f->has_src_port && ntohs(udp->source) != f->src_port) return 0;
            if (f->has_dst_port && ntohs(udp->dest) != f->dst_port) return 0;
        }
    }
    
    return 1; // All checks passed
}