/**
 * @file dns.c
 * @author lishutong(527676163@qq.com)
 * @brief DNS客户端协议实现
 * @version 0.1
 * @date 2022-12-02
 * 
 * @copyright Copyright (c) 2022
 * 目前是针对每一个域名做一次查询，这样简单一些。虽然也可以一次查询多个，但是这样处理起来比较麻烦。
 */
#include "dns.h"
#include "dbg.h"
#include "mblock.h"

static nlist_t req_list;                                 // 请求列表
static mblock_t req_mblock;                       // 请求分配结构
static dns_req_t dns_req_list[DNS_REQ_SIZE];


/**
 * @brief 针对指定的entry表，发送查询报文
 */
static net_err_t dns_send_query (dns_req_t * req) {
    return NET_ERR_OK;
}


/**
 * @brief 在DNS缓存表中查找指定域名对应的表项
 * 查找出来的可能是匹配的项，也可能是最老的项
 */
dns_entry_t * dns_entry_find (const char * domain_name) {
    return (dns_entry_t *)0;
}

/**
 * @brief 申请一个查询请求结构
 */
dns_req_t * dns_alloc_req (void) {
    static dns_req_t req;
    return &req;
}

void dns_free_req (dns_req_t * req) {
}

/**
 * @brief 加入查询队列
 */
static void dns_req_add (dns_req_t * req) {

}

/**
 * @brief DNS查询请求消息的处理
 * 所有未被立即解析的域名请求，将被暂时插入到就绪列表中处理
 */
net_err_t dns_req_in(func_msg_t* msg) {
    dns_req_t * dns_req = (dns_req_t *)msg->param;

    // 必要的参数检查，地址要求不能超过整体的名称长度
    size_t name_len = plat_strlen(dns_req->domain_name);
    if (name_len >= DNS_DOMAIN_NAME_MAX) {
        dbg_error(DBG_DNS, "domain name too long: %d > %d", name_len, DNS_DOMAIN_NAME_MAX);
        return NET_ERR_PARAM;
    }

    // 检查是否是本机地址，直接返回，这样不用占用表项
    if (plat_strcmp(dns_req->domain_name, "localhost") == 0) {
        ipaddr_from_str(&dns_req->ipaddr, "127.0.0.1");
        dns_req->err = NET_ERR_OK;
        return dns_req->err;
    }

    // 已经是IP地址，直接处理
    ipaddr_t ipaddr;
    if (ipaddr_from_str(&ipaddr, dns_req->domain_name) == NET_ERR_OK) {
        ipaddr_copy(&dns_req->ipaddr, &ipaddr);
        dns_req->err = NET_ERR_OK;
        return dns_req->err;
    }

    // 如果已经存在，找到后复制后直接返回
    dns_entry_t * entry = dns_entry_find(dns_req->domain_name);
    if (entry) {
        // 找到已解析的项，直接返回
        ipaddr_copy(&dns_req->ipaddr, &entry->ipaddr);
        dns_req->err = NET_ERR_OK;
        return dns_req->err;
    }

    // 任务需要进入等待状态，等待查询结果
    dns_req->wait_sem = sys_sem_create(0);
    if (dns_req->wait_sem == SYS_SEM_INVALID) {
        dbg_error(DBG_DNS, "create sem failed.");
        return NET_ERR_SYS;
    }

    // 插入请求队列中，并发送请求
    dns_req_add(dns_req);
    net_err_t err = dns_send_query(dns_req);
    if (err < 0) {
        dbg_error(DBG_DNS, "send dns query failed. err=%d", err);
        goto dns_req_end;
    }

    return NET_ERR_OK;
dns_req_end:
    if (dns_req->wait_sem != SYS_SEM_INVALID) {
        sys_sem_free(dns_req->wait_sem);
        dns_req->wait_sem = SYS_SEM_INVALID;
    }
    return err;
}


/**
 * @brief 初始化DNS
 */
void dns_init (void) {
    dbg_info(DBG_DNS, "DNS init");

    // 建立请求表
    nlist_init(&req_list);
    mblock_init(&req_mblock, dns_req_list, sizeof(dns_req_t), DNS_REQ_SIZE, NLOCKER_THREAD);

    dbg_info(DBG_DNS, "DNS done");
}