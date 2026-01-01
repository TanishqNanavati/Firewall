🛡️ Stateful Firewall in C (Userspace)

A userspace stateful firewall implemented in C using libpcap, supporting TCP connection tracking, rule-based filtering, interactive control, and logging.

This project demonstrates low-level networking, OS concepts, and data-structure design, including TCP finite-state machines and connection tables.

📌 Features
🔥 Packet Capture

Uses libpcap to capture live traffic from a network interface

Filters IPv4 traffic using BPF (ip)

Supports TCP, UDP, ICMP, and ARP parsing

🧠 Stateful Connection Tracking

Implements a TCP Finite State Machine (FSM):

SYN_SENT, SYN_RECEIVED, ESTABLISHED

FIN_WAIT, CLOSING, TIME_WAIT, CLOSED

Tracks connections using a 5-tuple:

(src_ip, dst_ip, src_port, dst_port, protocol)


Bidirectional matching (client ↔ server)

Per-connection statistics:

Packets & bytes (both directions)

Creation & last-seen timestamps

📋 Firewall Rule Engine

Rule-based packet filtering with priorities

Match conditions:

Source IP (CIDR)

Destination IP (CIDR)

Source / Destination port (single or range)

Protocol (TCP / UDP / ICMP)

Actions:

ACCEPT

DROP

REJECT (placeholder for future extension)

Rules loaded from config file:

firewall_rules.conf


Hit-count statistics per rule

🔄 Stateful Enforcement

Packets are:

Parsed

Passed through connection tracker

Evaluated by firewall rules

Invalid TCP states (e.g., data without handshake) are dropped

UDP/ICMP connections become ESTABLISHED after bidirectional traffic

⏱️ Connection Timeouts & Cleanup

Automatic expiration based on protocol and state:

Protocol	State	Timeout
TCP	ESTABLISHED	2 hours
TCP	SYN states	2 minutes
TCP	FIN / CLOSE	2 minutes
UDP	Any	3 minutes
ICMP	Any	30 seconds

Periodic cleanup prevents memory leaks

Statistics for expired connections maintained

🖥️ Interactive Control (Runtime)

Non-blocking interactive commands:

Key	Action
h	Show help menu
r	Reload firewall rules
p	Print firewall rules
c	Show active connection table
s	Show packet statistics
t	Show connection statistics
x	Cleanup expired connections
q	Quit firewall
📡 Signal Support
Signal	Effect
SIGINT	Graceful shutdown
SIGHUP	Reload firewall rules
SIGUSR1	Print connection table

Example:

kill -USR1 <pid>

📝 Logging

All decisions are logged to firewall.log

Log format:

[YYYY-MM-DD HH:MM:SS] ACTION | SRC_IP:SRC_PORT -> DST_IP:DST_PORT [PROTO]

🧱 Project Architecture
.
├── main.c                 # Main event loop & control
├── parser.c / parser.h    # Packet parsing (Ethernet/IP/TCP/UDP/ICMP)
├── firewall_rules.c/.h    # Rule engine & config parsing
├── connection_tracker.c/.h # Stateful conntrack + TCP FSM
├── logger.c / logger.h    # Firewall logging
├── firewall_rules.conf    # Rule configuration file
└── README.md

⚙️ Build Instructions
Requirements

Linux

GCC

libpcap

pthreads

Install dependencies:

sudo apt install libpcap-dev

Compile
gcc *.c -o firewall -lpcap -lpthread

▶️ Usage

Run with root privileges:

sudo ./firewall eth0


Replace eth0 with your network interface.

🧪 Example Rules (firewall_rules.conf)
10 DROP ANY ANY ANY 22 TCP Block SSH
20 ACCEPT ANY ANY ANY 80 TCP Allow HTTP
30 ACCEPT ANY ANY ANY 443 TCP Allow HTTPS
40 ACCEPT ANY ANY ANY 53 UDP Allow DNS
50 ACCEPT ANY ANY ANY ANY ICMP Allow ICMP

