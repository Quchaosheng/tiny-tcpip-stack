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
 * @brief DNS查询请求消息的处理
 * 所有未被立即解析的域名请求，将被暂时插入到就绪列表中处理
 */
net_err_t dns_req_in(func_msg_t* msg) {
    return NET_ERR_OK;
}
