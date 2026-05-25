/**
 * @file dns.h
 * @author lishutong(527676163@qq.com)
 * @brief DNS客户端协议实现
 * @version 0.1
 * @date 2022-11-30
 * 
 * @copyright Copyright (c) 2022
 * 
 */
#ifndef DNS_H
#define DNS_H

#include "nlist.h"
#include "net_cfg.h"
#include "udp.h"


// DNS包头标志位
#pragma pack(1)

/**
 * @brief DNS包头
 */
typedef struct _dns_hdr_t {
    uint16_t id;                // 事务ID
    union {
        uint16_t all;

#if NET_ENDIAN_LITTLE
        struct {
            uint16_t rcode : 4;         // 响应码
            uint16_t cd : 1;            // 禁用安全检查（1）
            uint16_t ad : 1;            // 信息已授权（1）
            uint16_t z : 1;             // 保底为0
            uint16_t ra : 1;            // 服务器是否支持递归查询(1)
            uint16_t rd : 1;            // 告诉服务器执行递归查询(1)，0 容许迭代查询
            uint16_t tc : 1;            // 可截断(1)，即UDP长超512字节时，可只返回512字节
            uint16_t aa : 1;            // 授权回答
            uint16_t opcode : 4;        // 操作码(缺省为0)
            uint16_t qr : 1;
        };
#else
        struct {
            uint16_t qr : 1;
            uint16_t opcode : 4;        // 操作码(缺省为0)
            uint16_t aa : 1;            // 授权回答
            uint16_t tc : 1;            // 可截断(1)，即UDP长超512字节时，可只返回512字节
            uint16_t rd : 1;            // 告诉服务器执行递归查询(1)，0 容许迭代查询
            uint16_t ra : 1;            // 服务器是否支持递归查询(1)
            uint16_t z : 1;             // 保底为0
            uint16_t ad : 1;            // 信息已授权（1）
            uint16_t cd : 1;            // 禁用安全检查（1）
            uint16_t rcode : 5;         // 响应码
        };
#endif
    }flags;
    uint16_t qdcount;           // 查询数/区域数
    uint16_t ancount;           // 回答/先决条件数
    uint16_t nscount;           // 授权纪录数/更新数
    uint16_t arcount;           // 额外信息数
}dns_hdr_t;

#define DNS_QUERY_CLASS_INET            1     // 查询类：1 - 表示互联网类

// DNS资源纪录类型
#define DNS_QUERY_TYPE_A                1       // IPv4地址纪录

/**
 * @brief 问题（查询）区域区段格式
 * 不含名称，因为名称是可变长的且位于开头
 */
typedef struct _dns_qfield_t {
    uint16_t type;              // 查询类型
    uint16_t class;             // 查询类
}dns_qfield_t;

#pragma pack()

/**
 * @brief DNS表
 * 该表存储DNS域名和IP映射之间的相关信息
 */
typedef struct _dns_entry_t {
    ipaddr_t ipaddr;        // 对应的IP地址
    char domain_name[DNS_DOMAIN_NAME_MAX];          //  域名最大长度
}dns_entry_t;

/**
 * @brief DNS查询消息
 */
typedef struct _dns_req_t {
    char domain_name[DNS_DOMAIN_NAME_MAX];           // 域名
    net_err_t err;

    ipaddr_t  ipaddr;                   // 查询的IP地址
    sys_sem_t wait_sem;               // 等待的信号
}dns_req_t;

void dns_init (void);
dns_req_t * dns_alloc_req (void);
void dns_free_req (dns_req_t * req);

net_err_t dns_req_in (func_msg_t * msg);

#endif // DNS_H
