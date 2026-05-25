/**
 * @file udp_echo_server.h
 * @brief UDP 回显服务接口定义。
 * @details
 * 该模块用于验证无连接数据报路径，重点覆盖端口绑定、报文接收与原样回发，
 * 便于快速确认 UDP 子系统在当前平台下的可用性。
 */
#ifndef UDP_ECHO_SERVER_H
#define UDP_ECHO_SERVER_H

/**
 * @brief 启动 UDP 回显服务。
 * @param[in] port 监听端口。
 * @return 0 表示启动成功，负值表示启动失败。
 * @note UDP 无连接语义下，不保证远端可达与顺序一致性。
 */
int udp_echo_server_start (int port);

#endif // UDP_ECHO_SERVER_H
