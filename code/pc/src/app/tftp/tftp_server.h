/**
 * @file tftp_server.h
 * @brief TFTP server startup interface.
 * @details
 * Exposes the server entry point used by integration tests and demos where
 * a minimal file transfer service is needed to validate UDP/TFTP behavior.
 */
#ifndef TFTP_SERVER_H
#define TFTP_SERVER_H

#include "tftp.h"

/**
 * @brief Start TFTP server.
 * @param[in] dir Root directory exposed by the server.
 * @param[in] port Listen port (typically 69 in test setups).
 * @return `NET_ERR_OK` on success, otherwise an error code.
 */
net_err_t tftpd_start (const char* dir, uint16_t port);

#endif // TFTP_SERVER_H
