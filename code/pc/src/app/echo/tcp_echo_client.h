/**
 * @file tcp_echo_client.h
 * @brief TCP 回显客户端接口定义。
 * @details
 * 该模块用于从客户端视角验证 TCP 建连、发送、接收和关闭流程，
 * 以较低成本覆盖协议栈关键通信路径。
 */
#ifndef TCP_ECHO_CLIENT_H
#define TCP_ECHO_CLIENT_H

/**
 * @brief 启动 TCP 回显客户端。
 * @param[in] ip 服务端 IPv4 地址字符串。
 * @param[in] port 服务端监听端口。
 * @return 0 表示启动成功，负值表示启动失败。
 * @note 调用方需保证目标地址可达，失败重试策略由上层测试流程控制。
 */
int tcp_echo_client_start(const char* ip, int port);

#endif // TECHO_H
