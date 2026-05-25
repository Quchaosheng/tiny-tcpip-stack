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
