
/**
 * @file ping.h
 * @brief ICMP ping tool definitions.
 * @details
 * This module builds ICMP echo packets in user space for protocol-stack
 * verification and delay measurement. It uses local protocol headers to keep
 * the ping tool decoupled from stack-internal packet definitions.
 */
#ifndef PING_H
#define PING_H

#include <stdint.h>
#include <time.h>
#include "netapi.h"

// Default probe sizes and timing used by the command-line ping tool.
#define PING_BUFFER_SIZE            4096    // Extra payload carried with each probe.
#define PING_DEFAULT_ID             0x200   // Base identifier used to match echo replies.
#define PING_INTERVAL_MS            1000    // Default interval between probes (ms).
#define PING_DEFAULT_TMO            1000    // Default timeout for a single probe (ms).

#pragma pack(1)

/**
 * @brief Portable IPv4 header used by the ping reply parser.
 * @details
 * A local header definition avoids binding ping behavior to any specific
 * internal network-stack structure layout.
 */
typedef struct _ip_hdr_t {
	uint8_t shdr : 4;           // Header length in 32-bit words.
	uint8_t version : 4;        // IPv4 version.
	uint8_t tos;		        // Type of service.
	uint16_t total_len;		    // Total IPv4 packet length.
	uint16_t id;		        // Datagram identifier for fragmentation/reassembly.
	uint16_t frag;				// Fragment flags and offset.
	uint8_t ttl;                // Time-to-live decremented by each router hop.
	uint8_t protocol;	        // Upper-layer protocol.
	uint16_t hdr_checksum;      // IPv4 header checksum.
	uint8_t	src_ip[4];			// Source IPv4 address.
	uint8_t dest_ip[4];			// Destination IPv4 address.
}ip_hdr_t;

/**
 * @brief ICMP echo header used by request and reply packets.
 */
typedef struct _icmp_hdr_t {
	uint8_t type;           // ICMP type.
	uint8_t code;			// ICMP subtype.
	uint16_t checksum;	    // ICMP checksum.
	uint16_t id;            // Echo identifier.
	uint16_t seq;           // Echo sequence number.
}icmp_hdr_t;

/**
 * @brief Ping request payload (without IPv4 header).
 */
typedef struct _echo_req_t {
	icmp_hdr_t echo_hdr;
	clock_t time;               // Local send timestamp for RTT calculation.
	char buf[PING_BUFFER_SIZE];
}echo_req_t;

/**
 * @brief Ping reply payload (with IPv4 header).
 */
typedef struct _echo_reply_t {
	ip_hdr_t iphdr;
	icmp_hdr_t echo_hdr;
	clock_t time;               // Timestamp copied from request payload.
	char buf[PING_BUFFER_SIZE];
}echo_reply_t;
#pragma pack()

/**
 * @brief Runtime buffer set used by ping execution.
 */
typedef struct _ping_t {
	echo_req_t req;				// Outgoing request buffer.
	echo_reply_t reply;			// Incoming reply buffer.
}ping_t;

/**
 * @brief Run ping probes against a destination host.
 * @param[in,out] ping Runtime ping context.
 * @param[in] dest Destination IPv4/domain string.
 * @param[in] count Probe count. Negative values usually indicate continuous mode.
 * @param[in] size Payload size to send in each probe.
 * @param[in] interval Probe interval in milliseconds.
 */
void ping_run(ping_t * ping, const char * dest, int count, int size, int interval);

#endif // PING_H
