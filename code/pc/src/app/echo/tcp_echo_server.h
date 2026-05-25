/**
 * @file tcp_echo_server.h
 * @brief TCP 回显服务接口定义。
 * @details
 * 该模块提供最小化 TCP 服务端样例，用于验证协议栈连接建立、数据收发
 * 与 socket 接口链路是否工作正常，便于联调和回归测试。
 */
#ifndef TCP_ECHO_SERVER_H
#define TCP_ECHO_SERVER_H

/**
 * @brief 启动 TCP 回显服务。
 * @param[in] port 监听端口。
 * @return 0 表示启动成功，负值表示启动失败。
 * @note 该接口偏测试用途，生产场景应由上层统一托管生命周期。
 */
int tcp_echo_server_start(int port);

#endif // TECHO_H
