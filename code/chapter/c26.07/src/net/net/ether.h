/**
 * @brief 以太网协议支持，不包含ARP协议处理
 */
#ifndef ETHER_H
#define ETHER_H

#include "net_err.h"
#include "netif.h"

#define ETH_HWA_SIZE        6       // mac地址长度
#define ETH_MTU             1500    // 最大传输单元，数据区的大小
/*为什么 TCP 常见 MSS 是 1460？
因为以太网 MTU 是 1500 字节，减去 IP 头（20 字节）和 TCP 头（20 字节），剩下 1460 字节作为 TCP 数据部分。*/
#define ETH_DATA_MIN        46      // 最小发送的帧长，即头部+46 
/*：为什么以太网有最小帧长限制？
这是为了保证冲突检测机制（CSMA/CD）能够正常工作，帧必须足够长，发送端才能在发送过程中检测到冲突。*/

#pragma pack(1)

/**
 * @brief 以太网帧头
 */
typedef struct _ether_hdr_t {
    uint8_t dest[ETH_HWA_SIZE];         // 目标mac地址
    uint8_t src[ETH_HWA_SIZE];          // 源mac地址
 /*| 协议   | 值      |
| ---- | ------ |
| IPv4 | 0x0800 |
| ARP  | 0x0806 |
| IPv6 | 0x86DD |
以太网如何区分上层协议？
通过以太网头中的 EtherType 字段（protocol 字段），标识该帧承载的是 IPv4、ARP、IPv6 等协议。*/
    uint16_t protocol;                  // 协议/长度
}ether_hdr_t;

/**
 * @brief 以太网帧格式
 * 肯定至少要求有1个字节的数据
 */
typedef struct _ether_pkt_t {
    ether_hdr_t hdr;                    // 帧头
    uint8_t data[ETH_MTU];              // 数据区
}ether_pkt_t;

#pragma pack()

const uint8_t* ether_broadcast_addr(void);
//发送以太网帧
/*| 参数       | 含义      |
| -------- | ------- |
| netif    | 网卡      |
| protocol | 上层协议    |
| dest     | 目标 MAC  |
| buf      | 数据（IP包） |*/
net_err_t ether_raw_out(netif_t* netif, uint16_t protocol, const uint8_t* dest, pktbuf_t* buf);
net_err_t ether_init(void);
//处理网卡收到的以太网帧
/*以太网帧到达后如何处理？
先解析以太网头，检查目标 MAC 是否匹配，然后根据 EtherType 字段将数据交给对应的上层协议（如 IP 或 ARP）。*/
net_err_t ether_in(netif_t* netif, pktbuf_t* packet);

#endif // ETHER_H


/*1. 以太网帧结构是什么？
以太网帧由目标 MAC、源 MAC、协议类型和数据组成，其中头部 14 字节，数据部分为 46~1500 字节。
2. 什么是 MTU？
MTU 是链路层允许的最大数据载荷长度，以太网中为 1500 字节，超过需要在 IP 层分片。
3. 为什么以太网有最小帧长？
为了保证冲突检测机制正常工作，帧必须足够长，最小为 64 字节。
4.protocol 字段的作用？
用于标识上层协议类型，如 IPv4、ARP 等，从而实现链路层向上分发。*/
