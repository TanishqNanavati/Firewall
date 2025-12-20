#include"logger.h"
#include"parser.h"
#include<stdio.h>
#include<time.h>
#include<arpa/inet.h>

static FILE *log_file = NULL;

void init_logger(const char *filename){
    log_file = fopen(filename,"a");
    if(!log_file) fprintf(stderr,"Failed to open log file : %s\n",filename);
}

void log_decision(const packet_info_t *pkt,action_t action){
    if(!log_file) return;

    time_t now = time(NULL);

    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));

    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    
    struct in_addr src_addr = {.s_addr = htonl(pkt->src_ip)};
    struct in_addr dst_addr = {.s_addr = htonl(pkt->dst_ip)};
    
    inet_ntop(AF_INET, &src_addr, src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &dst_addr, dst_ip_str, INET_ADDRSTRLEN);

    const char *proto = "UNKNOWN";
    if (pkt->protocol == PROTO_TCP) proto = "TCP";
    else if (pkt->protocol == PROTO_UDP) proto = "UDP";
    else if (pkt->protocol == PROTO_ICMP) proto = "ICMP";

    fprintf(log_file, "[%s] %s | %s:%u -> %s:%u [%s]\n",
            time_str,
            action == ACCEPT ? "ACCEPT" : "DROP",
            src_ip_str, pkt->src_port,
            dst_ip_str, pkt->dst_port,
            proto);
    
    fflush(log_file);
}

void close_logger(void) {
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}