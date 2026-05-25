/**
 * @file tftp_client.h
 * @brief TFTP client command interfaces.
 * @details
 * This header groups interactive client entry points so CLI tooling can
 * trigger upload/download flows without coupling to internal transfer steps.
 */
#ifndef TFTP_CLIENT_H
#define TFTP_CLIENT_H

#include "tftp.h"

#define TFTP_CMD_BUF_SIZE           128     // Command-line input buffer size.

/**
 * @brief Start interactive TFTP client session.
 * @param[in] ip Server IPv4 address string.
 * @param[in] port Server port.
 * @return 0 on success, negative value on failure.
 */
int tftp_start (const char * ip, uint16_t port);

/**
 * @brief Download a file from server (RRQ flow).
 * @param[in] ip Server IPv4 address string.
 * @param[in] port Server port.
 * @param[in] block_size Requested block size (0 means default).
 * @param[in] filename Remote file path/name.
 * @return 0 on success, negative value on failure.
 */
int tftp_get(const char * ip, uint16_t port, int block_size, const char* filename);

/**
 * @brief Upload a file to server (WRQ flow).
 * @param[in] ip Server IPv4 address string.
 * @param[in] port Server port.
 * @param[in] block_size Requested block size (0 means default).
 * @param[in] filename Local file path/name.
 * @return 0 on success, negative value on failure.
 */
int tftp_put(const char* ip, uint16_t port, int block_size, const char* filename);

#endif // TFTP_CLIENT_H
