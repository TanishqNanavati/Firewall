#ifndef LOGGER_H
#define LOGGER_H

#include"firewall_rules.h"

void init_logger(const char* filename);
void log_decision(const packet_info_t *pkt,action_t action);
void close_logger(void);

#endif



// A firewall logger typically records:

// Timestamp

// Source IP

// Destination IP

// Source port

// Destination port

// Protocol

// Action taken (ACCEPT / DROP)

// (Optionally) Rule ID or description