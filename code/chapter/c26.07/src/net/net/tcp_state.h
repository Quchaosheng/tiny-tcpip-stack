/**
 * @brief tcp状态处理
 * 1 为什么 TCP 要有状态处理模块？
 * 因为 TCP 是面向连接的协议，它的行为依赖当前连接所处的状态。
 * 不同状态下收到相同类型的报文，处理逻辑不同，所以通常会把 TCP 设计成一个状态机，每个状态对应独立的输入处理函数。
 * 2 TCP 状态机的核心职责是什么？
 * 核心职责是根据当前状态和收到的报文类型执行对应动作
 * 包括报文合法性检查、发送响应报文、更新序列号确认号窗口等连接控制信息，并在必要时完成状态迁移
 
 * tcp_state.h = 定义 TCP 各个状态下“收到报文以后怎么处理”
 */
#ifndef TCP_STATE_H
#define TCP_STATE_H

#include "tcp.h"

typedef net_err_t (*tcp_proc_t)(tcp_t *tcp, tcp_seg_t *seg);

net_err_t tcp_closed_in(tcp_t *tcp, tcp_seg_t *seg);
net_err_t tcp_syn_sent_in(tcp_t *tcp, tcp_seg_t *seg);
net_err_t tcp_established_in(tcp_t *tcp, tcp_seg_t *seg);
net_err_t tcp_close_wait_in (tcp_t * tcp, tcp_seg_t * seg);
net_err_t tcp_last_ack_in (tcp_t * tcp, tcp_seg_t * seg);
//主动关闭连接后，已经发送 FIN，等待 ACK 或对端 FIN  
/*可能收到：对 FIN 的 ACK -> 进入 FIN_WAIT_2
对端直接发 FIN（甚至 ACK+FIN）-> 可能进入 CLOSING 或 TIME_WAIT
异常报文*/
net_err_t tcp_fin_wait_1_in(tcp_t * tcp, tcp_seg_t * seg);
/*本端的 FIN 已被确认，连接进入半关闭，等待对端发 FIN。
FIN_WAIT_1 表示本端已发送 FIN 但尚未收到对该 FIN 的确认；
FIN_WAIT_2 表示对本端 FIN 的 ACK 已收到，现在只等待对端发送 FIN 完成关闭。*/
net_err_t tcp_fin_wait_2_in(tcp_t * tcp, tcp_seg_t * seg);
/*TIME_WAIT 主要有两个目的：第一，保证主动关闭方发送的最后一个 ACK 丢失时还能重发；
第二，等待网络中的旧报文自然过期，避免这些延迟报文影响后续使用相同四元组建立的新连接。*/
net_err_t tcp_closing_in (tcp_t * tcp, tcp_seg_t * seg);
net_err_t tcp_time_wait_in (tcp_t * tcp, tcp_seg_t * seg);
/*收到 SYN -> 创建新连接控制块 -> 回 SYN+ACK -> 进入 SYN_RCVD
LISTEN 状态收到 SYN 后会发生什么？
服务端在 LISTEN 状态收到 SYN 后，会为该连接创建或初始化连接控制块，记录对端信息，
发送 SYN+ACK，并将状态迁移到 SYN_RCVD，等待客户端最终 ACK。*/
net_err_t tcp_listen_in(tcp_t *tcp, tcp_seg_t *seg);
net_err_t tcp_syn_recvd_in(tcp_t *tcp, tcp_seg_t *seg);

const char * tcp_state_name (tcp_state_t state);
void tcp_set_state (tcp_t * tcp, tcp_state_t state);

#endif // TCP_STATE_H
