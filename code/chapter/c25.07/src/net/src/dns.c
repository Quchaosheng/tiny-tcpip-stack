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
#include "udp.h"
#include "mblock.h"
#include "socket.h"
#include "tools.h"

static udp_t * dns_udp;
static nlist_t req_list;                                 // 请求列表
static mblock_t req_mblock;                       // 请求分配结构
static dns_req_t dns_req_list[DNS_REQ_SIZE];
static uint8_t working_buf[DNS_WORKING_BUF_SIZE];


/**
 * @brief 添加问题区段
 */
static uint8_t * add_query_field (const char * domain_name, char * buf, size_t size) {
    // 检查长度大小：包含字符串有效长，开头的.和结束的'\0'
    if (size < (sizeof(dns_qfield_t) + plat_strlen(domain_name) + 2)) {
        dbg_error(DBG_DNS, "no enough space for query: %s", domain_name);
        return (uint8_t *)0;
    }

    // 写入名字区域。先写入整个字符，构造成多个以.+字符串的形式
    char * name_buf = buf;
    name_buf[0] = '.';
    plat_strcpy(name_buf + 1, domain_name);

    // 然后将所有的.换成其之后的字符串长度
    char * c = name_buf;
    while (*c) {
        if (*c == '.') {
            // 统计后续字符串长度
            char * dot = c++;
            while (*c && (*c != '.')) {
                c++;
            }
            *dot = (uint8_t)(c - dot - 1);
        } else {
            c++;
        }
    }
    *c++ = '\0';

    dns_qfield_t * f = (dns_qfield_t *)c;
    f->class = htons(DNS_QUERY_CLASS_INET);
    f->type = htons(DNS_QUERY_TYPE_A);
    return (uint8_t *)f + sizeof(dns_qfield_t);
}

#include "netapi.h"         // 临时用

/**
 * @brief 针对指定的entry表，发送查询报文
 */
static net_err_t dns_send_query (dns_req_t * req) {
    // 构造DNS查询包头
    dns_hdr_t * dns_hdr = (dns_hdr_t *)working_buf;
    dns_hdr->id = htons(0);
    dns_hdr->flags.all = 0;
    dns_hdr->flags.rd = 1;          // 期望递归
    dns_hdr->flags.all = htons(dns_hdr->flags.all);
    dns_hdr->qdcount = htons(1);    // 暂时每次只查一个吧
    dns_hdr->ancount = 0;
    dns_hdr->nscount = 0;
    dns_hdr->arcount = 0;


    // 填充1个问题区段
    uint8_t * buf = working_buf + sizeof(dns_hdr_t);
    buf = add_query_field(req->domain_name, (char *)buf, sizeof(working_buf) - (buf - working_buf));
    if (!buf) {
        dbg_error(DBG_DNS, "add query question failed.");
        return NET_ERR_MEM;
    }

    // 向网络上发送查询消息
    struct x_sockaddr_in dest;
    plat_memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(DNS_PORT_DEFAULT);
    dest.sin_addr.s_addr = x_inet_addr("8.8.8.8");

    return udp_sendto((sock_t *)dns_udp, working_buf, buf - working_buf, 0,
                            (const struct x_sockaddr *)&dest, sizeof(dest), (ssize_t *)0);
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

    // 套接字初始化
    dns_udp = (udp_t *)udp_create(AF_INET, IPPROTO_UDP);
    dbg_assert(dns_udp != (udp_t *)0, "create udp socket failed");

    // 建立请求表
    nlist_init(&req_list);
    mblock_init(&req_mblock, dns_req_list, sizeof(dns_req_t), DNS_REQ_SIZE, NLOCKER_THREAD);

    dbg_info(DBG_DNS, "DNS done");
}