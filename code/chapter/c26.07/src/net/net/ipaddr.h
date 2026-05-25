/*
 * @brief IP地址定义及接口函数
 ipaddr.h 是协议栈里对 IP 地址进行统一封装的基础模块，主要解决“地址如何表示、如何转换、如何比较、如何做网络相关判断”这些问题。
 */
#ifndef IPADDR_H
#define IPADDR_H

#include <stdint.h>
#include "net_err.h"

#define IPV4_ADDR_BROADCAST       0xFFFFFFFF  // 广播地址    它表示发给本地链路上所有主机，通常不会被路由转发
#define IPV4_ADDR_SIZE             4            // IPv4地址长度

/**
 * @brief IP地址
 */
typedef struct _ipaddr_t {
    enum {
        IPADDR_V4,
    }type;              // 地址类型     这样做可以到时候做扩展

    union {
        // 注意，IP地址总是按大端存放
        uint32_t q_addr;                        // 32位整体描述
        uint8_t a_addr[IPV4_ADDR_SIZE];        // 数组描述
    };
}ipaddr_t;

void ipaddr_set_any(ipaddr_t * ip);
//把字符串形式的 IP 地址转成内部 ipaddr_t
net_err_t ipaddr_from_str(ipaddr_t * dest, const char* str);
ipaddr_t * ipaddr_get_any(void);
void ipaddr_copy(ipaddr_t * dest, const ipaddr_t * src);
int ipaddr_is_equal(const ipaddr_t * ipaddr1, const ipaddr_t * ipaddr2);
void ipaddr_to_buf(const ipaddr_t* src, uint8_t* ip_buf);
//从 4 字节缓冲区读地址到内部结构  通常用于：从网络报文解析地址
void ipaddr_from_buf(ipaddr_t* dest, const uint8_t * ip_buf);
int ipaddr_is_local_broadcast(const ipaddr_t * ipaddr);
//判断一个地址是否是“某个网络的直接广播地址
/*问：如何判断一个 IPv4 地址是不是某个网段的广播地址？
可以结合子网掩码判断该地址的主机位是否全部为 1。若网络位合法且主机位全 1，则它是该子网的定向广播地址。*/
int ipaddr_is_direct_broadcast(const ipaddr_t * ipaddr, const ipaddr_t * netmask);
int ipaddr_is_any(const ipaddr_t* ip);
//根据 IP 地址和子网掩码，计算网络地址 本质公式就是：network = ip & netmask
ipaddr_t ipaddr_get_net(const ipaddr_t * ipaddr, const ipaddr_t * netmask);
//判断是否同网段，不是直接比较 IP 是否相等，而是比较两边与同一掩码按位与后的网络号是否相同。
/*(dest & netmask) == (src & netmask)是否相等才匹配*/
int ipaddr_is_match(const ipaddr_t* dest, const ipaddr_t* src, const ipaddr_t * netmask);
void ipaddr_set_all_1(ipaddr_t* ip);
int ipaddr_1_cnt(ipaddr_t* ip);

#endif // ipaddr_H
