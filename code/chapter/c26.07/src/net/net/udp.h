#ifndef UDP_H
#define UDP_H

#include "sock.h"
#include "ipaddr.h"

typedef struct _udp_from_t {
    ipaddr_t from;  //发送方 IP 地址
    uint16_t port;  //发送方端口号
}udp_from_t;

/**
 * UDP数据包头
 */
#pragma pack(1)  //使用 1 字节对齐可以避免编译器插入额外填充字节，确保首部长度和字段偏移正确

typedef struct _udp_hdr_t {
    uint16_t src_port;          // 源端口
    uint16_t dest_port;		    // 目标端口
    uint16_t total_len;	        // 整个数据包的长度
    uint16_t checksum;		    // 整个数据包的校验和
    /*UDP 校验和通常不只是校验 UDP 头和数据，还会结合 伪首部 来计算，包括：1 源 IP 2目的IP 3协议号 4UDP 长度*/
}udp_hdr_t;

/**
 * UDP数据包
 */
typedef struct _udp_pkt_t {
    udp_hdr_t hdr;             // UDP头部
    uint8_t data[1];            // UDP数据区
}udp_pkt_t;

#pragma pack()

/**
 * UDP控制块
 */
typedef struct _udp_t {
    sock_t  base;                   // 基础控制块
    
    // 没有用定长消息队列，目的是减少开销。定长消息队列要求有缓存表
    // 再者还会创建多个信号量等结构，资源开锁大一些
    nlist_t recv_list;           	// 接收队列
    sock_wait_t rcv_wait;           // 接收等待结构
}udp_t;

net_err_t udp_init(void);
sock_t* udp_create(int family, int protocol);
net_err_t udp_in(pktbuf_t* buf, ipaddr_t* src_ip, ipaddr_t* dest_ip);
net_err_t udp_out(ipaddr_t* dest, uint16_t dport, ipaddr_t* src, uint16_t sport, pktbuf_t* buf);
//应用层通过 socket 发送 UDP 数据时的操作函数
net_err_t udp_sendto (struct _sock_t * sock, const void* buf, size_t len, int flags, const struct x_sockaddr* dest,
            x_socklen_t dest_len, ssize_t * result_len);
net_err_t udp_recvfrom(sock_t* sock, void* buf, size_t len, int flags,
        struct x_sockaddr* src, x_socklen_t* addr_len, ssize_t * result_len);
//UDP 不是无连接吗？为什么还有 connect()？
/*记录默认的目标地址和端口
以后发送时可以不用每次都传 dest
只接收来自这个目标的数据报（很多实现如此）
错误处理更方便*/
net_err_t udp_connect(sock_t* sock, const struct x_sockaddr* addr, x_socklen_t len);
#endif // UDP_H
/*2. UDP 首部有哪些字段？
UDP 首部固定 8 字节，包含源端口、目的端口、UDP 总长度和校验和四个字段，每个字段都是 16 位





*/