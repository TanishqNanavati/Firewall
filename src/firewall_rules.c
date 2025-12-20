#include"firewall_rules.h"
#include"parser.h"
#include<stdio.h>
#include<string.h>
#include<arpa/inet.h>


static firewall_rule_t rules[MAX_RULES];
static int rule_cnt = 0;

void init_rules(void){
    memset(rules,0,sizeof(rules));
    rule_cnt = 0;

    // blocking incoming ssh from any source
    add_rule(0,0,0,htons(22),PROTO_TCP,DROP,"Block SSH");

    // allow http traffic
    add_rule(0,0,0,htons(80),PROTO_TCP,ACCEPT,"Allow HTTP");

    // allow https traffic
    add_rule(0,0,0,htons(443),PROTO_TCP,ACCEPT,"Allow HTTPS");

    // allow dns
    add_rule(0,0,0,htons(53),PROTO_UDP,ACCEPT,"Allow DNS");

    // allow icmp
    add_rule(0,0,0,0,PROTO_ICMP,ACCEPT,"Allow ICMP");
}

int add_rule(uint32_t src_ip,uint32_t dst_ip,uint16_t src_port,uint16_t dst_port,uint8_t protocol,action_t action,const char* description){
    if(rule_cnt >= MAX_RULES) return -1;

    rules[rule_cnt].src_ip = src_ip;
    rules[rule_cnt].dst_ip = dst_ip;
    rules[rule_cnt].src_port = src_port;
    rules[rule_cnt].dst_port = dst_port;
    rules[rule_cnt].protocol = protocol;
    rules[rule_cnt].action = action;
    rules[rule_cnt].enabled = 1;

    if(description){
        strncpy(rules[rule_cnt].description,description,63);
        rules[rule_cnt].description[63] = '\0';
    }

    rule_cnt++;
    return 0;
}

action_t evaluate_packet(const packet_info_t *pkt){
    // convert packet info into network byte order

    uint32_t pkt_src_ip = htonl(pkt->src_ip);
    uint32_t pkt_dst_ip = htonl(pkt->dst_ip);
    uint16_t pkt_src_port = htons(pkt->src_port);
    uint16_t pkt_dst_port = htons(pkt->dst_port);

    for(int i=0;i<rule_cnt;i++){
        if(!rules[i].enabled) continue;

        int match = 1;

        // match src ip
        if(rules[i].src_ip != 0 && rules[i].src_ip != pkt_src_ip) match = 0;

        // match dst ip
        if(rules[i].dst_ip != 0 && rules[i].dst_ip != pkt_dst_ip) match = 0;

        // match src port
        if(rules[i].src_port != 0 && rules[i].src_port != pkt_src_port) match = 0;

        // match dst port
        if(rules[i].dst_port != 0 && rules[i].dst_port != pkt_dst_port) match = 0;

        // match protocol
        if(rules[i].protocol != 0 && rules[i].protocol != pkt->protocol) match = 0;

        if(match) return rules[i].action;
    }

    return ACCEPT; // default
}


void print_rules(void){
    printf("\n  ============ Firewall Rules :  ============ \n");

    for(int i=0;i<rule_cnt;i++){
        printf("Rule %d : ",i);

        if(rules[i].src_ip == 0) printf("ANY");
        else{
            struct in_addr addr = {.s_addr = rules[i].src_ip};
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET,&addr,ip_str,INET6_ADDRSTRLEN);
            printf("%s",ip_str);
        }

        printf(":%u -> ",ntohs(rules[i].src_port));

        if(rules[i].dst_ip == 0) printf("ANY");
        else{
            struct in_addr addr = {.s_addr = rules[i].dst_ip};
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET,&addr,ip_str,INET_ADDRSTRLEN);
            printf("%s",ip_str);
        }

        printf(":%u ",ntohs(rules[i].dst_port));

        const char *proto = "ANY";

        if(rules[i].protocol == PROTO_TCP) proto = "TCP";
        else if(rules[i].protocol == PROTO_UDP) proto = "UDP";
        else if(rules[i].protocol == PROTO_ICMP) proto = "ICMP";

        printf("[%s] -> %s",proto,rules[i].action == ACCEPT ? "ACCEPT":"DROP");

        if(rules[i].description[0]) printf("(%s)",rules[i].description);
        printf("\n");


        printf("======================== \n\n");
    }
}

int parse_packet_info(const uint8_t *packet,size_t len,packet_info_t *info){

    if(len < sizeof(struct EthHeader)) return -1;

    memset(info,0,sizeof(packet_info_t));

    struct EthHeader*eth = (struct EthHeader*)packet;
    uint16_t ethertype = ntohs(eth->ethertype);

    if(ethertype != ETH_P_IP) return -1;

    if(len < sizeof(struct EthHeader) + sizeof(struct IPv4Header)) return -1;

    struct IPv4Header*ip = (struct IPv4Header*)(packet + sizeof(struct EthHeader));

    uint8_t version = (ip->ver_ihl >> 4) & 0x0F;
    if(version != 4) return -1;

    // Extract IP addresses (convert to host byte order)
    info->src_ip = ntohl(ip->saddr);
    info->dst_ip = ntohl(ip->daddr);
    info->protocol = ip->protocol;

    // Calculate IP header length
    uint8_t ihl = ip->ver_ihl & 0x0F;
    size_t ip_hdr_len = ihl * 4;

    size_t transport_offset = sizeof(struct EthHeader) + ip_hdr_len;

    if(len < transport_offset) return -1;

    // parse transport layer
    switch(info->protocol){
        case PROTO_TCP:{
            if(len < transport_offset + sizeof(struct TCPHeader)) return -1;

            struct TCPHeader *tcp = (struct TCPHeader*)(packet + transport_offset);
            info->src_port = ntohs(tcp->source);
            info->dst_port = ntohs(tcp->dest);
            break;
        }

        case PROTO_UDP:{
            if(len < transport_offset + sizeof(struct UDPHeader)) return -1;

            struct UDPHeader *udp = (struct UDPHeader*)(packet + transport_offset);
            info->src_port = ntohs(udp->source);
            info->dst_port = ntohs(udp->dest);
            break;
        }

        case PROTO_ICMP:{
            info->src_port = 0;
            info->dst_port = 0;
            break;
        }

        default:{
            info->src_port = 0;
            info->dst_port = 0;
            break;
        }
    }

    return 0;
}