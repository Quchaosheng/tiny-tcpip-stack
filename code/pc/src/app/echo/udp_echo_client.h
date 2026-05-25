/**
 * @file udp_echo_client.h
 * @brief UDP echo client startup interface.
 * @details
 * This header exposes a thin entry point so test tools can validate
 * end-to-end UDP send/receive behavior without depending on internal code.
 */
#ifndef UDP_ECHO_CLIENT_H
#define UDP_ECHO_CLIENT_H

/**
 * @brief Start the UDP echo client.
 * @param[in] ip Remote server IPv4 address string.
 * @param[in] port Remote server port.
 * @return 0 on success, negative value on failure.
 * @note Primarily used for stack verification and regression testing.
 */
int udp_echo_client_start(const char* ip, int port);

#endif // UDP_ECHO_CLIENT_H
