
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "parser.h"
#include "firewall_rules.h"
#include "logger.h"

static volatile int keep_running = 1;
static int verbose_mode = 0;
static unsigned long packets_accepted = 0;
static unsigned long packets_dropped = 0;
static unsigned long packets_total = 0;

void signal_handler(int sig) {
    (void)sig;
    keep_running = 0;
    printf("\nShutting down...\n");
}

void print_statistics(void) {
    printf("\nStatistics:\n");
    printf("  Total:    %lu\n", packets_total);
    printf("  Accepted: %lu\n", packets_accepted);
    printf("  Dropped:  %lu\n", packets_dropped);
}

void packet_handler(uint8_t *user, const struct pcap_pkthdr *header,
                   const uint8_t *packet) {
    (void)user;
    
    packets_total++;
    
    packet_info_t pkt_info;
    
    if (parse_packet_info(packet, header->len, &pkt_info) < 0) {
        return;
    }

    action_t action = evaluate_packet(&pkt_info);
    
    if (action == ACCEPT) {
        packets_accepted++;
    } else {
        packets_dropped++;
    }
    
    printf("[%s] ", action == ACCEPT ? "ACCEPT" : "DROP  ");
    
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    struct in_addr src = {.s_addr = htonl(pkt_info.src_ip)};
    struct in_addr dst = {.s_addr = htonl(pkt_info.dst_ip)};
    inet_ntop(AF_INET, &src, src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &dst, dst_ip_str, INET_ADDRSTRLEN);
    
    const char *proto = "???";
    if (pkt_info.protocol == PROTO_TCP) proto = "TCP";
    else if (pkt_info.protocol == PROTO_UDP) proto = "UDP";
    else if (pkt_info.protocol == PROTO_ICMP) proto = "ICMP";
    
    printf("%s | %s:%u -> %s:%u\n",
           proto, src_ip_str, pkt_info.src_port,
           dst_ip_str, pkt_info.dst_port);
    
    if (verbose_mode && action == DROP) {
        printf("\n--- Dropped Packet Details ---\n");
        print_eth(packet, header->len);
        print_ip(packet, header->len);
        
        uint8_t ihl = ((struct IPv4Header*)(packet + sizeof(struct EthHeader)))->ver_ihl & 0x0F;
        size_t ip_hdr_len = ihl * 4;
        
        if (pkt_info.protocol == PROTO_TCP) {
            print_tcp(packet, header->len, ip_hdr_len);
        } else if (pkt_info.protocol == PROTO_UDP) {
            print_udp(packet, header->len, ip_hdr_len);
        } else if (pkt_info.protocol == PROTO_ICMP) {
            print_icmp(packet, header->len, ip_hdr_len);
        }
        printf("------------------------------\n\n");
    }
    
    log_decision(&pkt_info, action);
}

void print_usage(const char *prog_name) {
    printf("Usage: %s [options] [interface]\n", prog_name);
    printf("Options:\n");
    printf("  -v    Verbose mode\n");
    printf("  -h    Help\n");
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    char *dev = NULL;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0) {
            verbose_mode = 1;
        } else if (strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (argv[i][0] != '-') {
            dev = argv[i];
        }
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    if (dev == NULL) {
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Error: %s\n", errbuf);
            return 1;
        }
    }

    printf("Device: %s\n", dev);

    init_rules();
    init_logger("firewall.log");
    print_rules();

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error: %s\n", errbuf);
        fprintf(stderr, "Try: sudo %s\n", argv[0]);
        return 1;
    }

    struct bpf_program fp;
    char filter_exp[] = "ip";
    bpf_u_int32 net = 0;
    
    if (pcap_compile(handle, &fp, filter_exp, 0, net) != -1) {
        pcap_setfilter(handle, &fp);
        pcap_freecode(&fp);
    }

    printf("\nMonitoring traffic... (Ctrl+C to stop)\n\n");

    while (keep_running) {
        pcap_dispatch(handle, 10, packet_handler, NULL);
    }

    pcap_close(handle);
    close_logger();
    print_statistics();
    
    printf("\nLog: firewall.log\n");
    
    return 0;
}