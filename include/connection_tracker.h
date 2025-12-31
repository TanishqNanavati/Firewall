// implementing stateful firewall

#ifndef CONNECTION_TRACKER_H
#define CONNECTION_TRACKER_H

#include<stdint.h>
#include<time.h>
#include"parser.h"
#include"firewall_rules.h"

#define CONNECTION_TABLE_SIZE 65536
#define TCP_TIMEOUT_ESTABLISHED 7200      // 2 hrs
#define TCP_TIMEOUT_SYN_SENT 120          // 2 mins
#define TCP_TIMEOUT_FIN_WAIT 120          // 2 mins
#define TCP_TIMEOUT_CLOSED 10             // 10 secs
#define UDP_TIMEOUT 180                   // 3 mins
#define ICMP_TIMEOUT 30                   // 30 secs



// connection states

typedef enum{
    TCP_STATE_NONE = 0,
    TCP_STATE_SYN_SENT,
    TCP_STATE_SYN_RECEIVED,
    TCP_STATE_ESTABLISHED,
    TCP_STATE_FIN_WAIT_1,
    TCP_STATE_FIN_WAIT_2,
    TCP_STATE_CLOSE_WAIT,
    TCP_STATE_CLOSING,
    TCP_STATE_LAST_ACK,
    TCP_STATE_TIME_WAIT,
    TCP_STATE_CLOSED
}tcp_state_t;


// connection states for other protocols

typedef enum{
    CONN_STATE_NEW = 0,
    CONN_STATE_ESTABLISHED,
    CONN_STATE_RELATED,
    CONN_STATE_INVALID
}conn_state_t;


// uniquely identifying connection

typedef struct{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
}connection_key_t;

// tracking the connection

typedef struct connection_entry{
    connection_key_t key;

    // TCP
    tcp_state_t tcp_state;
    uint32_t seq_client;
    uint32_t seq_server;
    uint32_t ack_client;
    uint32_t ack_server;

    // connection state
    conn_state_t conn_state;

    // timestamps
    time_t created;
    time_t last_seen;

    // statistics
    uint64_t packets_client_to_server;
    uint64_t packets_server_to_client;
    uint64_t bytes_client_to_server;
    uint64_t bytes_server_to_client;

    // flags
    uint8_t direction;              // 0 = outbound , 1 = inbound
    uint8_t valid;                 // is it valid

    struct connection_entry * next; // chaining for hash collision
}connection_entry_t;


// connection table
typedef struct {
    connection_entry_t * table[CONNECTION_TABLE_SIZE];
    uint64_t total_connections;
    uint64_t active_connections;
    uint64_t expired_connections;
}connection_table_t;


// initializing to track the connection

void init_connection_tracker(void);


// cleanup connection tracker

void cleanup(void);

// cleanup expired connections

void cleanup_expired_connection(void);

// track a packet and update connection state

conn_state_t track_connection(const packet_info_t *pkt,const uint8_t *packet,size_t len);

// get connection state for display

const char* get_tcp_state(tcp_state_t state);
const char* get_conn_state(conn_state_t state);

// printing ...

void print_connection_table(void);
void print_connection_statistics(void);
void print_expired_connections(void);

// check if connection exists

connection_entry_t * find_connection(const packet_info_t *pkt);

#endif