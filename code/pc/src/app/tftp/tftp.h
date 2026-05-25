/**
 * @file tftp.h
 * @brief TFTP protocol constants, packet layouts, and shared helpers.
 * @details
 * This header centralizes wire-level definitions used by both client and
 * server paths, which keeps transfer behavior consistent across platforms.
 */
#ifndef TFTP_H
#define TFTP_H

#include "netapi.h"

#define TFTP_DEF_PORT               69      // Well-known TFTP server port.
#define TFTP_DEF_BLKSIZE            512     // RFC default transfer block size.
#define TFTP_BLKSIZE_MAX            8192    // Upper bound accepted for block option.
#define TFTP_TMO_SEC                5       // Receive timeout before retransmission.
#define TFTP_MAX_RETRY              6       // Max timeout retries before abort.

/**
 * @brief TFTP opcode values.
 */
typedef enum _tftp_op_t {
    TFTP_PKT_RRQ = 1,                               // Read request.
    TFTP_PKT_WRQ,                                   // Write request.
    TFTP_PKT_DATA,                                  // Data packet.
    TFTP_PKT_ACK,                                   // Acknowledge packet.
    TFTP_PKT_ERROR,                                 // Error packet.
    TFTP_PKT_OACK,                                  // Option acknowledgement.

    TFTP_PKT_REQ = (TFTP_PKT_WRQ << 8) | TFTP_PKT_RRQ,  // RRQ or WRQ group mask.
}tftp_op_t;

/**
 * @brief TFTP error codes exchanged in ERROR packets.
 */
typedef enum _tftp_err_t {
    TFTP_ERR_OK = 0,                // No error.
    TFTP_ERR_NO_FILE = 1,           // File not found.
    TFTP_ERR_ACC_VIO,               // Access violation.
    TFTP_ERR_DISK_FULL,             // Disk full or allocation exceeded.
    TFTP_ERR_OP,                    // Illegal TFTP operation.
    TFTP_ERR_UNKNOWN_TID,           // Unknown transfer ID.
    TFTP_ERR_FILE_EXIST,            // File already exists.

    TFTP_ERR_USER_NOT_EXIT,         // Unsupported transfer mode.
    TFTP_ERR_OPTION,                // Option negotiation failure.
    TFTP_ERR_UNKNOWN,               // Unsupported operation.

    NET_TFTP_ERR_END,
}tftp_err_t;

/**
 * @brief Packed TFTP packet view for RX/TX buffers.
 * @details
 * A single union layout keeps parsing/serialization explicit and avoids
 * dynamic allocations in constrained environments.
 */
#pragma pack(1)
typedef struct _tftp_packet_t {
    uint16_t opcode;                // Packet opcode.

    union {
        struct {
            uint8_t args[1];        // RRQ/WRQ payload: filename/mode/options.
        }req;

        struct {
            uint16_t block;         // DATA block number.
            uint8_t data[TFTP_BLKSIZE_MAX];
        }data;

        struct {
            uint16_t block;         // ACK block number.
            char option[1];         // Optional ACK extension payload.
        }ack;

        struct {
            char option[1];         // OACK key/value payload.
        }oack;

        struct {
            uint16_t code;          // TFTP error code.
            char msg[1];            // Human-readable error message.
        }err;
    };
}tftp_pkt_t;
#pragma pack()

#define TFTP_PACKET_MIN_SIZE   4   // Minimum bytes for opcode + argument header.

/**
 * @brief Shared transfer context.
 * @details
 * Maintains transport state, negotiated options, retry bookkeeping, and
 * reusable packet buffers for both upload/download flows.
 */
typedef struct _tftp_t {
    int socket;                     // Local UDP socket.
    tftp_err_t error;               // Last transfer-layer error.
    int block_size;                 // Negotiated block size.
    int file_size;                  // Negotiated or known file size.
    uint16_t curr_blk;              // Current transfer block index.

    // Server may switch to a new UDP port after the initial request.
    struct x_sockaddr remote;       // Current peer endpoint.

    uint8_t tmo_retry;              // Current timeout retry count.
    uint8_t tmo_sec;                // Timeout window in seconds.

    int tx_size;                    // Serialized TX packet length.
    tftp_pkt_t rx_packet;           // Reusable RX packet buffer.
    tftp_pkt_t tx_packet;           // Reusable TX packet buffer.
}tftp_t;

/**
 * @brief Parsed high-level transfer request.
 */
#define TFTP_NAME_SIZE          32

typedef struct _tftp_req_t {
    tftp_t tftp;                    // Transfer context.
    tftp_op_t op;                   // Request operation (RRQ/WRQ).
    struct x_sockaddr_in remote;    // Initial remote endpoint.
    int option;                     // Non-zero when options are enabled.
    int blksize;                    // Requested block size.
    int filesize;                   // Requested/known file size.
    char filename[TFTP_NAME_SIZE];  // Target file name.
}tftp_req_t;

/**
 * @brief Convert a TFTP error code to a human-readable string.
 */
const char* tftp_error_msg(tftp_err_t err);

/**
 * @brief Send RRQ/WRQ request packet.
 * @param[in,out] tftp Transfer context.
 * @param[in] is_read Non-zero for RRQ, zero for WRQ.
 * @param[in] filename Target file name.
 * @param[in] file_size Optional file size for option negotiation.
 * @return 0 on success, negative value on failure.
 */
int tftp_send_request(tftp_t * tftp, int is_read, const char* filename, uint32_t file_size);

/**
 * @brief Send ACK for a specific block.
 */
int tftp_send_ack(tftp_t * tftp, uint16_t block_num);

/**
 * @brief Send option acknowledgement (OACK response path).
 */
int tftp_send_oack(tftp_t * tftp);

/**
 * @brief Send DATA packet for a specific block.
 */
int tftp_send_data(tftp_t * tftp, uint16_t block_num, size_t size);

/**
 * @brief Send ERROR packet to peer.
 */
int tftp_send_error(tftp_t * tftp, uint16_t code);

/**
 * @brief Retransmit the last packet after timeout.
 */
int tftp_resend(tftp_t * tftp);

/**
 * @brief Wait for a packet of expected type/block.
 * @param[in,out] tftp Transfer context.
 * @param[in] op Expected opcode.
 * @param[in] block Expected block number.
 * @param[out] pkt_size Received packet size.
 */
int tftp_wait_packet(tftp_t * tftp, tftp_op_t op, uint16_t block, size_t * pkt_size);

/**
 * @brief Parse OACK option key/value pairs.
 */
int tftp_parse_oack (tftp_t * tftp);

#endif // TFTP_H
