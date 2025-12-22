#define _POSIX_C_SOURCE 200809L
#include "firewall_rules.h"
#include "parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <pthread.h>

static firewall_rule_t rules[MAX_RULES];
static int rule_count = 0;
static pthread_rwlock_t rules_lock = PTHREAD_RWLOCK_INITIALIZER;

static int compare_priority(const void *a,const void *b){
    const firewall_rule_t *rule_a = (const firewall_rule_t *)a;
    const firewall_rule_t *rule_b = (const firewall_rule_t *)b;
    return rule_a->priority - rule_b->priority;
}

void init_rules(void){
    pthread_rwlock_wrlock(&rules_lock);
    memset(rules,0,sizeof(rules));
    rule_count = 0;
    pthread_rwlock_unlock(&rules_lock);

    if(load_rules_from_file(RULE_CONFIG_FILE) < 0){
        printf("No config file, loading defaults...\n");
        
        add_rule(0,0,0,htons(22),PROTO_TCP,DROP,"Block SSH");
        add_rule(0,0,0,htons(80),PROTO_TCP,ACCEPT,"Allow HTTP");
        add_rule(0,0,0,htons(443),PROTO_TCP,ACCEPT,"Allow HTTPS");
        add_rule(0,0,0,htons(53),PROTO_UDP,ACCEPT,"Allow DNS");
        add_rule(0,0,0,0,PROTO_ICMP,ACCEPT,"Allow ICMP");
    }
}

int add_rule(uint32_t src_ip,uint32_t dst_ip,uint16_t src_port,
             uint16_t dst_port,uint8_t protocol,action_t action,
             const char* description) {
    
    firewall_rule_t rule;
    memset(&rule, 0, sizeof(rule));
    
    rule.priority = rule_count + 10;
    
    if(src_ip != 0) {
        rule.match_src_ip = 1;
        rule.src_ip_range.network = ntohl(src_ip);
        rule.src_ip_range.mask = 0xFFFFFFFF;
        rule.src_ip_range.prefix = 32;
    }
    
    if(dst_ip != 0) {
        rule.match_dst_ip = 1;
        rule.dst_ip_range.network = ntohl(dst_ip);
        rule.dst_ip_range.mask = 0xFFFFFFFF;
        rule.dst_ip_range.prefix = 32;
    }
    
    if(src_port != 0) {
        rule.match_src_port = 1;
        rule.src_port_range.start = ntohs(src_port);
        rule.src_port_range.end = ntohs(src_port);
    }
    
    if(dst_port != 0) {
        rule.match_dst_port = 1;
        rule.dst_port_range.start = ntohs(dst_port);
        rule.dst_port_range.end = ntohs(dst_port);
    }
    
    if(protocol != 0) {
        rule.match_protocol = 1;
        rule.protocol = protocol;
    }
    
    rule.action = action;
    rule.enabled = 1;
    
    if(description) {
        strncpy(rule.description, description, 127);
        rule.description[127] = '\0';
    }
    
    return add_rule_v2(&rule);
}

int add_rule_v2(const firewall_rule_t *rule){
    pthread_rwlock_wrlock(&rules_lock);

    if(rule_count >= MAX_RULES){
        pthread_rwlock_unlock(&rules_lock);
        return -1;
    }

    rules[rule_count] = *rule;
    rule_count++;

    qsort(rules,rule_count,sizeof(firewall_rule_t),compare_priority);

    pthread_rwlock_unlock(&rules_lock);
    return 0;
}

int ip_in_range(uint32_t ip,const ip_range_t *range){
    return (ip & range->mask) == (range->network & range->mask);
}

int port_in_range(uint16_t port,const port_range_t *range){
    return port >= range->start && port <= range->end;
}

action_t evaluate_packet(const packet_info_t *pkt){
    pthread_rwlock_rdlock(&rules_lock);
    
    for(int i=0; i<rule_count; i++){
        if(!rules[i].enabled) continue;

        int match = 1;

        if(rules[i].match_src_ip) {
            if(!ip_in_range(pkt->src_ip, &rules[i].src_ip_range)) {
                match = 0;
            }
        }

        if(rules[i].match_dst_ip) {
            if(!ip_in_range(pkt->dst_ip, &rules[i].dst_ip_range)) {
                match = 0;
            }
        }

        if(rules[i].match_src_port) {
            if(!port_in_range(pkt->src_port, &rules[i].src_port_range)) {
                match = 0;
            }
        }

        if(rules[i].match_dst_port) {
            if(!port_in_range(pkt->dst_port, &rules[i].dst_port_range)) {
                match = 0;
            }
        }

        if(rules[i].match_protocol) {
            if(rules[i].protocol != pkt->protocol) {
                match = 0;
            }
        }

        if(match) {
            rules[i].hit_count++;
            action_t result = rules[i].action;
            pthread_rwlock_unlock(&rules_lock);
            return result;
        }
    }
    
    pthread_rwlock_unlock(&rules_lock);
    return ACCEPT;
}

void print_rules(void){
    pthread_rwlock_rdlock(&rules_lock);
    
    printf("\n========== Firewall Rules (Priority Order) ==========\n");
    printf("%-4s %-6s %-20s %-20s %-12s %-12s %-8s %-8s %s\n",
           "ID", "Prior", "Src IP", "Dst IP", "Src Port", "Dst Port", 
           "Proto", "Action", "Description");
    printf("------------------------------------------------------------------------\n");

    for(int i=0; i<rule_count; i++){
        printf("%-4d %-6d ", i, rules[i].priority);

        if(rules[i].match_src_ip) {
            struct in_addr addr = {.s_addr = htonl(rules[i].src_ip_range.network)};
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
            printf("%-20s ", ip_str);
        } else {
            printf("%-20s ", "ANY");
        }

        if(rules[i].match_dst_ip) {
            struct in_addr addr = {.s_addr = htonl(rules[i].dst_ip_range.network)};
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
            printf("%-20s ", ip_str);
        } else {
            printf("%-20s ", "ANY");
        }

        if(rules[i].match_src_port) {
            if(rules[i].src_port_range.start == rules[i].src_port_range.end) {
                printf("%-12d ", rules[i].src_port_range.start);
            } else {
                char range[16];
                snprintf(range, 16, "%d-%d", rules[i].src_port_range.start, 
                        rules[i].src_port_range.end);
                printf("%-12s ", range);
            }
        } else {
            printf("%-12s ", "ANY");
        }

        if(rules[i].match_dst_port) {
            if(rules[i].dst_port_range.start == rules[i].dst_port_range.end) {
                printf("%-12d ", rules[i].dst_port_range.start);
            } else {
                char range[16];
                snprintf(range, 16, "%d-%d", rules[i].dst_port_range.start,
                        rules[i].dst_port_range.end);
                printf("%-12s ", range);
            }
        } else {
            printf("%-12s ", "ANY");
        }

        const char *proto = "ANY";
        if(rules[i].match_protocol) {
            if(rules[i].protocol == PROTO_TCP) proto = "TCP";
            else if(rules[i].protocol == PROTO_UDP) proto = "UDP";
            else if(rules[i].protocol == PROTO_ICMP) proto = "ICMP";
        }
        printf("%-8s ", proto);

        printf("%-8s ", rules[i].action == ACCEPT ? "ACCEPT" : "DROP");

        printf("%s", rules[i].description);
        if(!rules[i].enabled) printf(" [DISABLED]");
        
        printf("\n");
    }
    
    printf("========================================================\n\n");
    pthread_rwlock_unlock(&rules_lock);
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

    info->src_ip = ntohl(ip->saddr);
    info->dst_ip = ntohl(ip->daddr);
    info->protocol = ip->protocol;

    uint8_t ihl = ip->ver_ihl & 0x0F;
    size_t ip_hdr_len = ihl * 4;

    size_t transport_offset = sizeof(struct EthHeader) + ip_hdr_len;

    if(len < transport_offset) return -1;

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

void print_rule_statistics(void) {
    pthread_rwlock_rdlock(&rules_lock);
    
    printf("\n========== Rule Hit Statistics ==========\n");
    for(int i=0; i<rule_count; i++) {
        if(rules[i].hit_count > 0) {
            printf("Rule %d: %lu hits - %s\n", 
                   i, rules[i].hit_count, rules[i].description);
        }
    }
    printf("=========================================\n");
    
    pthread_rwlock_unlock(&rules_lock);
}

int remove_rule(int rule_id) {
    pthread_rwlock_wrlock(&rules_lock);
    
    if(rule_id < 0 || rule_id >= rule_count) {
        pthread_rwlock_unlock(&rules_lock);
        return -1;
    }
    
    for(int i = rule_id; i < rule_count - 1; i++) {
        rules[i] = rules[i + 1];
    }
    rule_count--;
    
    pthread_rwlock_unlock(&rules_lock);
    return 0;
}

int enable_rule(int rule_id) {
    pthread_rwlock_wrlock(&rules_lock);
    if(rule_id < 0 || rule_id >= rule_count) {
        pthread_rwlock_unlock(&rules_lock);
        return -1;
    }
    rules[rule_id].enabled = 1;
    pthread_rwlock_unlock(&rules_lock);
    return 0;
}

int disable_rule(int rule_id) {
    pthread_rwlock_wrlock(&rules_lock);
    if(rule_id < 0 || rule_id >= rule_count) {
        pthread_rwlock_unlock(&rules_lock);
        return -1;
    }
    rules[rule_id].enabled = 0;
    pthread_rwlock_unlock(&rules_lock);
    return 0;
}

int parse_cidr(const char *cidr_str, ip_range_t *range) {
    char ip_str[INET_ADDRSTRLEN];
    int prefix_len;
    
    if(sscanf(cidr_str, "%[^/]/%d", ip_str, &prefix_len) != 2) {
        return -1;
    }
    
    if(prefix_len < 0 || prefix_len > 32) return -1;
    
    struct in_addr addr;
    if(inet_pton(AF_INET, ip_str, &addr) != 1) return -1;
    
    range->network = ntohl(addr.s_addr);
    range->prefix = prefix_len;
    range->mask = prefix_len == 0 ? 0 : (~0U << (32 - prefix_len));
    
    return 0;
}

int parse_port_range(const char *port_str, port_range_t *range) {
    int start, end;
    
    if(sscanf(port_str, "%d-%d", &start, &end) == 2) {
        if(start < 0 || start > 65535 || end < 0 || end > 65535 || start > end) {
            return -1;
        }
        range->start = start;
        range->end = end;
    } else if(sscanf(port_str, "%d", &start) == 1) {
        if(start < 0 || start > 65535) return -1;
        range->start = start;
        range->end = start;
    } else {
        return -1;
    }
    
    return 0;
}

int load_rules_from_file(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if(!fp) return -1;
    
    pthread_rwlock_wrlock(&rules_lock);
    rule_count = 0;
    memset(rules, 0, sizeof(rules));
    
    char line[512];
    int line_num = 0;
    
    while(fgets(line, sizeof(line), fp)) {
        line_num++;
        
        if(line[0] == '#' || line[0] == '\n') continue;
        
        firewall_rule_t rule;
        memset(&rule, 0, sizeof(rule));
        rule.enabled = 1;
        
        char action_str[16], proto_str[16];
        char src_ip[64] = {0}, dst_ip[64] = {0};
        char src_port[32] = {0}, dst_port[32] = {0};
        
        int parsed = sscanf(line, "%d %15s %63s %31s %63s %31s %15s %127[^\n]",
                           &rule.priority, action_str, src_ip, src_port,
                           dst_ip, dst_port, proto_str, rule.description);
        
        if(parsed < 7) {
            fprintf(stderr, "Warning: Bad rule at line %d\n", line_num);
            continue;
        }
        
        if(strcmp(action_str, "ACCEPT") == 0) rule.action = ACCEPT;
        else if(strcmp(action_str, "DROP") == 0) rule.action = DROP;
        else if(strcmp(action_str, "REJECT") == 0) rule.action = REJECT;
        else continue;
        
        if(strcmp(src_ip, "ANY") != 0) {
            if(parse_cidr(src_ip, &rule.src_ip_range) == 0) {
                rule.match_src_ip = 1;
            }
        }
        
        if(strcmp(dst_ip, "ANY") != 0) {
            if(parse_cidr(dst_ip, &rule.dst_ip_range) == 0) {
                rule.match_dst_ip = 1;
            }
        }
        
        if(strcmp(src_port, "ANY") != 0) {
            if(parse_port_range(src_port, &rule.src_port_range) == 0) {
                rule.match_src_port = 1;
            }
        }
        
        if(strcmp(dst_port, "ANY") != 0) {
            if(parse_port_range(dst_port, &rule.dst_port_range) == 0) {
                rule.match_dst_port = 1;
            }
        }
        
        if(strcmp(proto_str, "TCP") == 0) {
            rule.protocol = PROTO_TCP;
            rule.match_protocol = 1;
        } else if(strcmp(proto_str, "UDP") == 0) {
            rule.protocol = PROTO_UDP;
            rule.match_protocol = 1;
        } else if(strcmp(proto_str, "ICMP") == 0) {
            rule.protocol = PROTO_ICMP;
            rule.match_protocol = 1;
        }
        
        if(rule_count < MAX_RULES) {
            rules[rule_count++] = rule;
        }
    }
    
    qsort(rules, rule_count, sizeof(firewall_rule_t), compare_priority);
    
    pthread_rwlock_unlock(&rules_lock);
    fclose(fp);
    
    printf("Loaded %d rules from %s\n", rule_count, filename);
    return 0;
}

int reload_rules(void) {
    printf("Reloading rules from %s...\n", RULE_CONFIG_FILE);
    return load_rules_from_file(RULE_CONFIG_FILE);
}

void save_rules_to_file(const char *filename) {
    FILE *fp = fopen(filename, "w");
    if(!fp) {
        fprintf(stderr, "Failed to open %s for writing\n", filename);
        return;
    }
    
    fprintf(fp, "# Firewall Rules Configuration\n");
    fprintf(fp, "# Format: priority action src_ip src_port dst_ip dst_port protocol description\n\n");
    
    pthread_rwlock_rdlock(&rules_lock);
    
    for(int i=0; i<rule_count; i++) {
        fprintf(fp, "%d ", rules[i].priority);
        
        if(rules[i].action == ACCEPT) fprintf(fp, "ACCEPT ");
        else if(rules[i].action == DROP) fprintf(fp, "DROP ");
        else if(rules[i].action == REJECT) fprintf(fp, "REJECT ");
        
        if(rules[i].match_src_ip) {
            struct in_addr addr = {.s_addr = htonl(rules[i].src_ip_range.network)};
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
            fprintf(fp, "%s/%d ", ip_str, rules[i].src_ip_range.prefix);
        } else {
            fprintf(fp, "ANY ");
        }
        
        if(rules[i].match_src_port) {
            if(rules[i].src_port_range.start == rules[i].src_port_range.end) {
                fprintf(fp, "%d ", rules[i].src_port_range.start);
            } else {
                fprintf(fp, "%d-%d ", rules[i].src_port_range.start, 
                        rules[i].src_port_range.end);
            }
        } else {
            fprintf(fp, "ANY ");
        }
        
        if(rules[i].match_dst_ip) {
            struct in_addr addr = {.s_addr = htonl(rules[i].dst_ip_range.network)};
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
            fprintf(fp, "%s/%d ", ip_str, rules[i].dst_ip_range.prefix);
        } else {
            fprintf(fp, "ANY ");
        }
        
        if(rules[i].match_dst_port) {
            if(rules[i].dst_port_range.start == rules[i].dst_port_range.end) {
                fprintf(fp, "%d ", rules[i].dst_port_range.start);
            } else {
                fprintf(fp, "%d-%d ", rules[i].dst_port_range.start,
                        rules[i].dst_port_range.end);
            }
        } else {
            fprintf(fp, "ANY ");
        }
        
        if(rules[i].match_protocol) {
            if(rules[i].protocol == PROTO_TCP) fprintf(fp, "TCP ");
            else if(rules[i].protocol == PROTO_UDP) fprintf(fp, "UDP ");
            else if(rules[i].protocol == PROTO_ICMP) fprintf(fp, "ICMP ");
        } else {
            fprintf(fp, "ANY ");
        }
        
        fprintf(fp, "%s\n", rules[i].description);
    }
    
    pthread_rwlock_unlock(&rules_lock);
    fclose(fp);
    
    printf("Saved %d rules to %s\n", rule_count, filename);
}