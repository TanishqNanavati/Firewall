
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pcap.h>
#include <arpa/inet.h>

#include "parser.h"
#include "firewall_rules.h"
#include "logger.h"

/* ================= GLOBAL STATE ================= */

static volatile sig_atomic_t keep_running = 1;
static volatile sig_atomic_t reload_config = 0;

static unsigned long total_packets   = 0;
static unsigned long accepted_packets = 0;
static unsigned long dropped_packets  = 0;

/* ================= SIGNAL HANDLERS ================= */

static void handle_sigint(int sig) {
    (void)sig;
    keep_running = 0;
}

static void handle_sighup(int sig) {
    (void)sig;
    reload_config = 1;
}

/* ================= PACKET CALLBACK ================= */

static void packet_handler(
    uint8_t *user,
    const struct pcap_pkthdr *header,
    const uint8_t *packet
) {
    (void)user;
    total_packets++;

    packet_info_t pkt;

    if (parse_packet_info(packet, header->caplen, &pkt) != 0) {
        return; // not an IPv4 packet or malformed
    }

    action_t action = evaluate_packet(&pkt);

    if (action == ACCEPT) {
        accepted_packets++;
    } else {
        dropped_packets++;
    }

    log_decision(&pkt, action);
}

/* ================= STATS ================= */

static void print_statistics(void) {
    printf("\n========== Firewall Statistics ==========\n");
    printf("Total packets   : %lu\n", total_packets);
    printf("Accepted packets: %lu\n", accepted_packets);
    printf("Dropped packets : %lu\n", dropped_packets);
    printf("=========================================\n");
}

/* ================= MAIN ================= */

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    char *interface = NULL;

    /* ---- Parse CLI ---- */
    if (argc > 1) {
        interface = argv[1];
    }

    /* ---- Signals ---- */
    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);
    signal(SIGHUP, handle_sighup);   // reload rules

    /* ---- Select interface if not provided ---- */
    if (!interface) {
        pcap_if_t *alldevs;
        if (pcap_findalldevs(&alldevs, errbuf) == -1 || !alldevs) {
            fprintf(stderr, "pcap_findalldevs failed: %s\n", errbuf);
            return 1;
        }
        interface = strdup(alldevs->name);
        pcap_freealldevs(alldevs);
    }

    printf("Using interface: %s\n", interface);

    /* ---- Init subsystems ---- */
    init_rules();
    init_logger("firewall.log");

    print_rules();

    /* ---- Open capture ---- */
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    /* ---- Filter only IPv4 ---- */
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "ip", 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(handle, &fp);
        pcap_freecode(&fp);
    }

    printf("Firewall running (Ctrl+C to stop, SIGHUP to reload rules)\n");

    /* ---- Main loop ---- */
    while (keep_running) {

        if (reload_config) {
            printf("\nReloading firewall rules...\n");
            reload_rules();
            print_rules();
            reload_config = 0;
        }

        pcap_dispatch(handle, 32, packet_handler, NULL);
    }

    /* ---- Cleanup ---- */
    pcap_close(handle);
    close_logger();

    print_statistics();
    print_rule_statistics();

    printf("Firewall stopped.\n");
    return 0;
}
