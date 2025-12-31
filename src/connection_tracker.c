#define _POSIX_C_SOURCE 200809L
#include"connection_tracker.h"
#include"parser.h" 
#include"firewall_rules.h"
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<pthread.h>
#include<arpa/inet.h>

static connection_table_t conn_table;
static pthread_rwlock_t conn_lock = PTHREAD_RWLOCK_INITIALIZER;

// hash function for connection key
static uint32_t hash_connection(const connection_key_t *key){
    uint32_t hash = 2166136261u;          // Fowler-Noll-Vo hash number --> standard hash

    hash ^= key->src_ip;
    hash *= 16777619u;                   // Fowler-Noll-Vo hash number --> standard hash
    hash ^= key->dst_ip;
    hash *= 16777619u;
    hash ^= ((uint32_t)key->src_port << 16) | key->dst_port;     // combining src port and dst port
    hash *= 16777619u;
    hash ^= key->protocol;
    hash *= 16777619u;

    return hash % CONNECTION_TABLE_SIZE;
}

// creating connection key from packet info

static void create_connection_key(const packet_info_t *pkt,connection_key_t *key){
    key->src_ip = pkt->src_ip;
    key->dst_ip = pkt->dst_ip;
    key->src_port = pkt->src_port;
    key->dst_port = pkt->dst_port;
    key->protocol = pkt->protocol;
}

// comparing connection keys

static int keys_equal(const connection_key_t *key1,const connection_key_t *key2){
    return (key1->src_ip == key2->src_ip) && (key1->dst_ip == key2->dst_ip)
            && (key1->src_port == key2->src_port) && (key1->dst_port == key2->dst_port) &&
            (key1->protocol == key2->protocol);
}

// checking if keys are reversed (bidirectional lookup)

static int keys_reverse(const connection_key_t *key1,const connection_key_t *key2){
    return (key1->src_ip == key2->dst_ip) && (key1->dst_ip == key2->src_ip)
            && (key1->src_port == key2->dst_port) && (key1->dst_port == key2->src_port) 
            && (key1->protocol == key2->protocol);
}


// initialize connection tracker

void init_connection_tracker(void){
    pthread_rwlock_wrlock(&conn_lock);
    memset(&conn_table,0,sizeof(connection_table_t));
    pthread_rwlock_unlock(&conn_lock);
    printf("COnnection established successfully\n");
}

// freeing up the memory of connection table

void cleanup(void){
    pthread_rwlock_wrlock(&conn_lock);

    for(int i=0;i<CONNECTION_TABLE_SIZE;i++){
        connection_entry_t *entry = conn_table.table[i];
        while(entry){
            connection_entry_t *next = entry->next;
            free(entry);
            entry = next;
        }

        conn_table.table[i] = NULL;
    }

    pthread_rwlock_unlock(&conn_lock);
}

// finding which packet belong to which connection

connection_entry_t *find_connection(const packet_info_t *pkt){
    connection_key_t key;
    create_connection_key(pkt,&key);
    uint32_t hash = hash_connection(&key);

    pthread_rwlock_rdlock(&conn_lock);

    connection_entry_t *entry = conn_table.table[hash];
    while(entry){
        if(keys_equal(&entry->key,&key) || keys_reverse(&entry->key,&key)){
            pthread_rwlock_unlock(&conn_lock);
            return entry;
        }
        entry = entry->next;
    }

    pthread_rwlock_unlock(&conn_lock);
    return NULL;
}

static connection_entry_t* create_connection(const connection_key_t *key){
    connection_entry_t *entry = malloc(sizeof(connection_entry_t));
    if(!entry) return NULL;

    memset(entry,0,sizeof(connection_entry_t));
    entry->key = *key;
    entry->created = time(NULL);
    entry->last_seen = entry->created;
    entry->valid = 1;
    entry->conn_state = CONN_STATE_NEW;
    entry->tcp_state = TCP_STATE_NONE;

    uint32_t hash = hash_connection(key);

    pthread_rwlock_wrlock(&conn_lock);
    entry->next = conn_table.table[hash];
    conn_table.table[hash] = entry;
    conn_table.total_connections++;
    conn_table.active_connections++;
    pthread_rwlock_unlock(&conn_lock);

    return entry;
}


static void update_tcp_state(connection_entry_t *entry,const uint8_t *pkt,size_t len,int is_reverse){
    if(len < (sizeof(struct EthHeader) + sizeof(struct IPv4Header) + sizeof(struct TCPHeader))) return;

    struct IPv4Header *ip = (struct IPv4Header*)(pkt + sizeof(struct EthHeader));
    uint8_t ihl = ip->ver_ihl & 0x0F;       // length of header
    size_t ip_header_len = ihl*4;           // multiplying by scaling factor
    size_t tcp_offset = sizeof(struct EthHeader) + ip_header_len;

    struct TCPHeader *tcp = (struct TCPHeader*)(pkt + tcp_offset);
    uint16_t flags = ntohs(tcp->doff_res_flags);


    uint8_t syn = (flags & 0x002) ? 1: 0;
    uint8_t ack = (flags & 0x010) ? 1: 0;
    uint8_t fin = (flags & 0x001) ? 1: 0;
    uint8_t rst = (flags & 0x004) ? 1: 0;

    uint32_t seq = ntohl(tcp->seq);
    uint32_t ack_num = ntohl(tcp->ack_seq);

    if(rst){
        // rst = resetting the connection = immediate close
        entry->tcp_state = TCP_STATE_CLOSED;
        entry->conn_state = CONN_STATE_INVALID;
        return;
    }

    switch(entry->tcp_state){
        case TCP_STATE_NONE:
            if(syn && !ack){
                entry->tcp_state = TCP_STATE_SYN_SENT;
                entry->seq_client = seq;
                entry->conn_state  = CONN_STATE_NEW;
            }
            break;
        
        case TCP_STATE_SYN_SENT:
            if(syn && ack){
                entry->tcp_state = TCP_STATE_SYN_RECEIVED;
                entry->seq_server = seq;
                entry->ack_client = ack_num;
            }
            break;
        
        case TCP_STATE_SYN_RECEIVED:
            if(ack && !syn){
                entry->tcp_state = TCP_STATE_ESTABLISHED;
                entry->conn_state = CONN_STATE_ESTABLISHED;
            }
            break;
        

        case TCP_STATE_ESTABLISHED:
            if(fin){
                entry->tcp_state = TCP_STATE_FIN_WAIT_1;
            }
            break;

        case TCP_STATE_FIN_WAIT_1:
            if(ack){
                entry->tcp_state = TCP_STATE_FIN_WAIT_2;
            }
            if(fin){
                entry->tcp_state = TCP_STATE_CLOSING;
            }
            break;
        
        case TCP_STATE_FIN_WAIT_2:
            if(fin){
                entry->tcp_state = TCP_STATE_TIME_WAIT;
            }
            break;

        case TCP_STATE_CLOSING:
            if(ack){
                entry->tcp_state = TCP_STATE_TIME_WAIT;
            }
            break;

        case TCP_STATE_TIME_WAIT:
            // waiting for timeout
            break;

        case TCP_STATE_CLOSE_WAIT:
            if(fin){
                entry->tcp_state = TCP_STATE_LAST_ACK;
            }
            break;

        case TCP_STATE_LAST_ACK:
            if(ack){
                entry->tcp_state = TCP_STATE_CLOSED;
            }
            break;

        default:
            break;
    }


    if(!is_reverse){
        entry->seq_client = seq;
        entry->ack_client = ack_num;
    }else{
        entry->seq_server = seq;
        entry->ack_server = ack_num;
    }

}

conn_state_t track_connection(const packet_info_t *pkt,const uint8_t *packet,size_t len){
    connection_key_t key;

    create_connection_key(pkt,&key);

    connection_entry_t *entry = find_connection(pkt);
    int is_reverse = 0;

    if(!entry){
        // new connection
        entry = create_connection(&key);
        if(!entry) return CONN_STATE_INVALID;

        // for tcp , we start with syn
        if(pkt->protocol == PROTO_TCP){
            update_tcp_state(entry,packet,len,0);
            if(entry->tcp_state == TCP_STATE_NONE) entry->conn_state = CONN_STATE_INVALID;
        }else if(pkt->protocol == PROTO_ICMP || pkt->protocol == PROTO_UDP) entry->conn_state = CONN_STATE_NEW;
    }else{
        // existing connection
        pthread_rwlock_wrlock(&conn_lock);

        is_reverse = keys_reverse(&entry->key,&key);

        entry->last_seen = time(NULL);

        // checking if it is client->server or server->client
        if(!is_reverse){
            entry->packets_client_to_server++;
            entry->bytes_client_to_server += len;
        }else{
            entry->packets_server_to_client++;
            entry->bytes_server_to_client += len;
        }

        // updating tcp state if applicable
        if(pkt->protocol == PROTO_TCP) update_tcp_state(entry,packet,len,is_reverse);
        else{
            // UDP/ICMP (bidirectional)
            if(entry->packets_client_to_server > 0 && entry->packets_server_to_client > 0){
                entry->conn_state = CONN_STATE_ESTABLISHED;
            }
        }

        pthread_rwlock_unlock(&conn_lock);
    }

    return entry->conn_state;
}

// void cleanup_expired_connection(void){
//     time_t now = time(NULL);
//     int cleaned = 0;

//     pthread_rwlock_wrlock(&conn_lock);

//     for(int i=0;i<CONNECTION_TABLE_SIZE;i++){
//         connection_entry_t **entry_ptr = &conn_table.table[i];

//         while(*entry_ptr){
//             connection_entry_t *entry = *entry_ptr;
//             time_t age = now - entry->last_seen;
//             int shd_expire = 0;


//             if(entry->key.protocol == PROTO_TCP){
//                 switch(entry->tcp_state){
//                     case TCP_STATE_ESTABLISHED :
//                         shd_expire = (age > TCP_TIMEOUT_ESTABLISHED);
//                         break;
//                     case TCP_STATE_SYN_SENT:
//                     case TCP_STATE_SYN_RECEIVED:
//                         shd_expire = (age > TCP_TIMEOUT_SYN_SENT);
//                         break;
//                     case TCP_STATE_FIN_WAIT_1:
//                     case TCP_STATE_FIN_WAIT_2:
//                     case TCP_STATE_CLOSING:
//                     case TCP_STATE_LAST_ACK:
//                     case TCP_STATE_TIME_WAIT:
//                         shd_expire = (age > TCP_TIMEOUT_FIN_WAIT);
//                         break;
//                     case TCP_STATE_CLOSED:
//                         shd_expire = (age > TCP_TIMEOUT_CLOSED);
//                         break;
//                     default:
//                         shd_expire = (age > TCP_TIMEOUT_SYN_SENT);
//                         break;
//                 }
//             }

//             else if(entry->key.protocol == PROTO_UDP) shd_expire = (age > UDP_TIMEOUT);
//             else if(entry->key.protocol == PROTO_ICMP) shd_expire = (age > ICMP_TIMEOUT);

//             if(shd_expire){
//                 *entry_ptr = entry->next;
//                 free(entry);
//                 conn_table.active_connections--;
//                 conn_table.expired_connections++;
//                 cleaned++;
//             }else entry_ptr = &entry->next;
//         }
//     }

//     pthread_rwlock_unlock(&conn_lock);

//     if(cleaned > 0) printf("Clenaed up %d expired connections\n",cleaned);
// }

void cleanup_expired_connection(void) {
    time_t now = time(NULL);
    int cleaned = 0;

    pthread_rwlock_wrlock(&conn_lock);

    for (int i = 0; i < CONNECTION_TABLE_SIZE; i++) {
        connection_entry_t **entry_ptr = &conn_table.table[i];

        while (*entry_ptr) {
            connection_entry_t *entry = *entry_ptr;
            time_t age = now - entry->last_seen;
            int shd_expire = 0;

            if (entry->key.protocol == PROTO_TCP) {

                if (entry->tcp_state == TCP_STATE_ESTABLISHED) {
                    shd_expire = (age > TCP_TIMEOUT_ESTABLISHED);

                } else if (entry->tcp_state == TCP_STATE_SYN_SENT ||
                           entry->tcp_state == TCP_STATE_SYN_RECEIVED) {
                    shd_expire = (age > TCP_TIMEOUT_SYN_SENT);

                } else {
                    /* All closing, closed, and unknown TCP states */
                    shd_expire = (age > TCP_TIMEOUT_FIN_WAIT);
                }

            } else if (entry->key.protocol == PROTO_UDP) {
                shd_expire = (age > UDP_TIMEOUT);

            } else if (entry->key.protocol == PROTO_ICMP) {
                shd_expire = (age > ICMP_TIMEOUT);
            }

            if (shd_expire) {
                *entry_ptr = entry->next;
                free(entry);

                conn_table.active_connections--;
                conn_table.expired_connections++;
                cleaned++;
            } else {
                entry_ptr = &entry->next;
            }
        }
    }

    pthread_rwlock_unlock(&conn_lock);

    if (cleaned > 0)
        printf("Cleaned up %d expired connections\n", cleaned);
}


const char* get_tcp_state(tcp_state_t state) {
    switch(state) {
        case TCP_STATE_NONE: return "NONE";
        case TCP_STATE_SYN_SENT: return "SYN_SENT";
        case TCP_STATE_SYN_RECEIVED: return "SYN_RECV";
        case TCP_STATE_ESTABLISHED: return "ESTABLISHED";
        case TCP_STATE_FIN_WAIT_1: return "FIN_WAIT1";
        case TCP_STATE_FIN_WAIT_2: return "FIN_WAIT2";
        case TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
        case TCP_STATE_CLOSING: return "CLOSING";
        case TCP_STATE_LAST_ACK: return "LAST_ACK";
        case TCP_STATE_TIME_WAIT: return "TIME_WAIT";
        case TCP_STATE_CLOSED: return "CLOSED";
        default: return "UNKNOWN";
    }
}

const char* get_conn_state(conn_state_t state) {
    switch(state) {
        case CONN_STATE_NEW: return "NEW";
        case CONN_STATE_ESTABLISHED: return "ESTABLISHED";
        case CONN_STATE_RELATED: return "RELATED";
        case CONN_STATE_INVALID: return "INVALID";
        default: return "UNKNOWN";
    }
}

void print_connection_table(void) {
    pthread_rwlock_rdlock(&conn_lock);
    
    printf("\n========== Active Connections ==========\n");
    printf("%-15s %-6s %-15s %-6s %-8s %-12s %-12s\n",
           "Src IP", "Port", "Dst IP", "Port", "Proto", "State", "TCP State");
    printf("-------------------------------------------------------------------------\n");
    
    int shown = 0;
    for(int i = 0; i < CONNECTION_TABLE_SIZE && shown < 50; i++) {
        connection_entry_t *entry = conn_table.table[i];
        while(entry && shown < 50) {
            if(entry->valid) {
                struct in_addr src = {.s_addr = htonl(entry->key.src_ip)};
                struct in_addr dst = {.s_addr = htonl(entry->key.dst_ip)};
                char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &src, src_ip, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &dst, dst_ip, INET_ADDRSTRLEN);
                
                const char *proto = "OTHER";
                if(entry->key.protocol == PROTO_TCP) proto = "TCP";
                else if(entry->key.protocol == PROTO_UDP) proto = "UDP";
                else if(entry->key.protocol == PROTO_ICMP) proto = "ICMP";
                
                printf("%-15s %-6u %-15s %-6u %-8s %-12s %-12s\n",
                       src_ip, entry->key.src_port,
                       dst_ip, entry->key.dst_port,
                       proto,
                       get_conn_state(entry->conn_state),
                       entry->key.protocol == PROTO_TCP ? 
                           get_tcp_state(entry->tcp_state) : "N/A");
                shown++;
            }
            entry = entry->next;
        }
    }
    
    if(conn_table.active_connections > 50) {
        printf("... and %lu more connections\n", 
               conn_table.active_connections - shown);
    }
    
    printf("========================================\n\n");
    pthread_rwlock_unlock(&conn_lock);
}

void print_connection_statistics(void) {
    pthread_rwlock_rdlock(&conn_lock);
    
    printf("\n========== Connection Statistics ==========\n");
    printf("Total connections:   %lu\n", conn_table.total_connections);
    printf("Active connections:  %lu\n", conn_table.active_connections);
    printf("Expired connections: %lu\n", conn_table.expired_connections);
    printf("===========================================\n\n");
    
    pthread_rwlock_unlock(&conn_lock);
}