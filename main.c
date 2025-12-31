#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/select.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <time.h>

#include "parser.h"
#include "firewall_rules.h"
#include "connection_tracker.h"
#include "logger.h"

/* ================= GLOBAL STATE ================= */
static volatile sig_atomic_t keep_running = 1;
static volatile sig_atomic_t reload_config = 0;
static volatile sig_atomic_t show_connections = 0;

static unsigned long total_packets    = 0;
static unsigned long accepted_packets = 0;
static unsigned long dropped_packets  = 0;

static time_t last_cleanup = 0;
#define CLEANUP_INTERVAL 60

/* ================= SIGNAL HANDLERS ================= */
static void handle_sigint(int sig) {
    (void)sig;
    keep_running = 0;
}

static void handle_sighup(int sig) {
    (void)sig;
    reload_config = 1;
}

static void handle_sigusr1(int sig) {
    (void)sig;
    show_connections = 1;
}

/* ================= PACKET CALLBACK ================= */
static void packet_handler(
    unsigned char *user,
    const struct pcap_pkthdr *header,
    const unsigned char *packet
) {
    (void)user;
    total_packets++;

    packet_info_t pkt;
    if (parse_packet_info(packet, header->caplen, &pkt) != 0) {
        return;
    }

    /* Track state */
    conn_state_t state = track_connection(&pkt, packet, header->caplen);

    /* Stateless rules */
    action_t action = evaluate_packet(&pkt);

    /* Stateful enforcement */
    if (state == CONN_STATE_INVALID) {
        action = DROP;
    }

    if (action == ACCEPT)
        accepted_packets++;
    else
        dropped_packets++;

    log_decision(&pkt, action);

    /* periodic cleanup */
    time_t now = time(NULL);
    if (now - last_cleanup >= CLEANUP_INTERVAL) {
        cleanup_expired_connection();
        last_cleanup = now;
    }
}

/* ================= STATS ================= */
static void print_statistics(void) {
    printf("\n========== Firewall Statistics ==========\n");
    printf("Total packets   : %lu\n", total_packets);
    printf("Accepted packets: %lu\n", accepted_packets);
    printf("Dropped packets : %lu\n", dropped_packets);
    printf("=========================================\n");
}

/* ================= MENU ================= */
static void print_menu(void) {
    printf("\n========== Firewall Menu ==========\n");
    printf("h - help\n");
    printf("r - reload rules\n");
    printf("p - print rules\n");
    printf("c - show connection table\n");
    printf("s - show packet statistics\n");
    printf("t - show connection statistics\n");
    printf("x - cleanup expired connections\n");
    printf("q - quit\n");
    printf("==================================\n> ");
    fflush(stdout);
}

/* ================= MAIN ================= */
int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const char *iface;

    if (argc < 2) {
        printf("Usage: %s <interface>\n", argv[0]);
        return 1;
    }
    iface = argv[1];

    /* signals */
    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);
    signal(SIGHUP, handle_sighup);
    signal(SIGUSR1, handle_sigusr1);

    /* init subsystems */
    init_connection_tracker();
    init_rules();
    init_logger("firewall.log");

    print_rules();

    handle = pcap_open_live(iface, BUFSIZ, 1, 100, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    pcap_setnonblock(handle, 1, errbuf);

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "ip", 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(handle, &fp);
        pcap_freecode(&fp);
    }

    printf("\nFirewall running on %s\n", iface);
    printf("SIGUSR1 to show connections (kill -USR1 %d)\n", getpid());
    printf("Press 'h' for menu\n\n");

    last_cleanup = time(NULL);

    fd_set readfds;
    struct timeval tv;

    while (keep_running) {

        if (reload_config) {
            printf("\nReloading rules...\n");
            reload_rules();
            print_rules();
            reload_config = 0;
        }

        if (show_connections) {
            print_connection_table();
            show_connections = 0;
        }

        pcap_dispatch(handle, 32, packet_handler, NULL);

        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        tv.tv_sec = 0;
        tv.tv_usec = 100000;

        if (select(STDIN_FILENO + 1, &readfds, NULL, NULL, &tv) > 0) {
            char cmd;
            if (read(STDIN_FILENO, &cmd, 1) > 0) {
                switch (cmd) {
                    case 'h': print_menu(); break;
                    case 'r': reload_rules(); print_rules(); break;
                    case 'p': print_rules(); break;
                    case 'c': print_connection_table(); break;
                    case 's': print_statistics(); break;
                    case 't': print_connection_statistics(); break;
                    case 'x': cleanup_expired_connection(); break;
                    case 'q': keep_running = 0; break;
                    case '\n': break;
                    default: printf("Unknown command\n"); break;
                }
            }
        }

        usleep(10000);
    }

    printf("\nShutting down firewall...\n");

    pcap_close(handle);
    close_logger();

    print_statistics();
    print_rule_statistics();
    print_connection_statistics();
    print_connection_table();

    cleanup();

    return 0;
}
