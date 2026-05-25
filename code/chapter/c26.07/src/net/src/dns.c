/**
 * 目前是针对每一个域名做一次查询，这样简单一些。虽然也可以一次查询多个，但是这样处理起来比较麻烦。
 */
#include "dns.h"
#include "timer.h"
#include "udp.h"
#include "fixq.h"
#include "dbg.h"
#include "udp.h"
#include "mblock.h"
#include "socket.h"
#include "tools.h"
#include "netapi.h"

static dns_entry_t dns_entry_tbl[DNS_ENTRY_SIZE];       // DNS缓存表
static net_timer_t entry_update_timer;
static udp_t * dns_udp;
static uint16_t id;
static nlist_t req_list;                                 // 请求列表
static mblock_t req_mblock;                       // 请求分配结构
static dns_req_t dns_req_list[DNS_REQ_SIZE];
static uint8_t working_buf[DNS_WORKING_BUF_SIZE];

#if DBG_DISP_ENABLED(DBG_DNS)
/*+---------------------+
|  DNS Entry List     |
+---------------------+
| domain_name         | --> 域名
| ttl                 | --> 生存时间
| age                 | --> 缓存条目的年龄
| ipaddr              | --> 对应的 IP 地址
+---------------------+
| domain_name         | --> 域名
| ttl                 | --> 生存时间
| age                 | --> 缓存条目的年龄
| ipaddr              | --> 对应的 IP 地址
+---------------------+
...
*/
static void show_entry_list (void) {
    int idx = 0;

    plat_printf("----------------dns entry list----------\n");
    for (int i = 0; i < DNS_ENTRY_SIZE; i++) {
        dns_entry_t * entry = dns_entry_tbl + i;
        if (ipaddr_is_any(&entry->ipaddr)) {
            continue;
        }

        plat_printf("%d: %s ttl(%d) age(%d) "IPV4_FMT"\n", idx++,
                entry->domain_name, entry->ttl, entry->age, dbg_ipv4(entry->ipaddr));
    }
    plat_printf("--------------------------------\n\n");
}
/*+---------------------------+
|  DNS Request List         |
+---------------------------+
| domain_name               | --> 请求的域名
| query_id                  | --> 查询标识符
| server                    | --> 目标服务器
| ipaddr                    | --> 请求的目标 IP 地址
| retry_tmo                 | --> 重试超时
| retry_cnt                 | --> 重试次数
+---------------------------+
| domain_name               | --> 请求的域名
| query_id                  | --> 查询标识符
| server                    | --> 目标服务器
| ipaddr                    | --> 请求的目标 IP 地址
| retry_tmo                 | --> 重试超时
| retry_cnt                 | --> 重试次数
+---------------------------+
...
*/
static void show_req_list (void) {
    int idx = 0;

    plat_printf("----------------dns req list----------\n");
    nlist_node_t * node;
    nlist_for_each(node, &req_list) {
        dns_req_t * req = nlist_entry(node, dns_req_t, node);

        plat_printf("%d: name(%s) query(%d) server:"IPV4_FMT" ip:"IPV4_FMT
                    " retry tmo: %d, retry_cnt: %d\n",
                    idx++,
                    req->domain_name,
                    req->query_id,
                    dbg_ipv4(dns_server_tbl[req->server].ipaddr),
                    dbg_ipv4(req->ipaddr),
                    req->retry_tmo, req->retry_cnt);
    }
    plat_printf("--------------------------------\n\n");
}
#else
#define show_entry_list()
#define show_req_list()
#endif

/*
 * 功能：
 * 要特别注意返回值的问题，稍微出错会导致后续包解析出问题
 * 解析 DNS 域名字段并跳过指定的长度。域名字段可以是 压缩格式，即指向先前的域名部分，这种格式有两个字节表示指针（0xc0 表示压缩）。
 * 该函数通过递归跳过域名中的各个部分，直到达到末尾。
 * 关键点：
压缩标签：DNS 中的域名可以被压缩成指针，避免重复存储相同的部分。
压缩格式使用前两个字节的高位（0xc0）来表示指向先前位置的指针。
跳过 \0：域名部分可能没有以 \0 结束，因此我们必须手动跳过它。
 */
static const uint8_t * domain_name_skip(const uint8_t * name, size_t size) {
    const uint8_t * c = name;
    const uint8_t * end = name + size;
    while (*c && (c < end)) {
        // 压缩标签，2个字节；非压缩，取计数累加
        if ((*c & 0xc0) == 0xc0) {
            // 一个域名仅能包含一个指针，要么只有两个字节就只包含一个指针，要么只在结尾部分跟随一个指针
            // 压缩标签无需以'\0'结束
            c += 2;//// 跳过压缩标签（2个字节）
            goto skip_end;
        } else {
            //跳过域名部分
            c += *c;
        }
    }

    // 非压缩标签没有'\0'，这里针对普通标签判断，跳过'\0'
    if (*c == '\0') {
        c++;
    }
skip_end:
    // 跳过字符符结束符'\0'
    return c >= end ? (const uint8_t *)0 : c;
}

/**
 * @brief 比较域名与问题、回答中的名称 它从源域名 domain_name 和目标域名 name 中依次比较每一部分（通过 . 分割）。
 * 要特别注意返回值的问题，稍微出错会导致后续包解析出问题
 * 返回值：如果匹配，则返回目标域名的下一个字符位置；如果不匹配，则返回 NULL
 */
static const char * domain_name_cmp(const char * domain_name, const char * name, size_t size) {
    const char * src = domain_name;
    const char * dest = name;

    // 这里不处理压缩标准，因为压缩标签指向的是前面的某个地方
    // 目前我们只检查问题域，这里不存在压缩标签
    //逐字符地比较两个字符串的部分（即域名的一部分）。
    //*src 和 *dest 对应的字符是域名的一个部分，它们之间的匹配是字符级别的，因此通过内循环来逐个字符地检查是否一致。
    while (*src) {
        int cnt = *dest++;
        for (int i = 0; i < cnt; i++) {
            // 不相同则退出
            if (*dest++ != *src++) {
                return (const char *)0;
            }
        }

        // 到这里, c指向了.，dest指向了数字值或者已经结束
        //外循环的任务就是 跳过分隔符（即 .），并进入下一部分的比较。
        if (*src == '\0') {
            break;
        } else if ((*src++ != '.')) {
            return (const char *)0;
        }
    }
    return (dest >= (name + size)) ? (const char *)0 : dest + 1; // 跳过'\0'
}

/*功能：
 * 构造 DNS 查询字段：将 域名 转换成 DNS 查询请求格式。DNS 查询格式要求每个部分的长度都要提前写入。
    分隔符处理：每个域名部分的长度写在其前面，分隔符 . 被用来分隔各个部分。
    查询类型：构造 dns_qfield_t 类型的查询字段，设置查询类型为 A（IPv4 地址查询），查询类为 INET。
关键点：域名格式：DNS 查询的域名格式与普通字符串不同，它要求每一部分的前面都有长度字节，并且各部分之间以 . 作为分隔符。
dns_qfield_t 字段：包含了查询的类型（A 类型）和查询的类（INET）。
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
            //计算当前部分的长度
            *dot = (uint8_t)(c - dot - 1);
        } else {
            c++;
        }
    }
    *c++ = '\0';

    /*在 name_buf 之后，开始构建 DNS 查询的相关字段，dns_qfield_t 结构包含查询的 类型 和 类，分别是：
DNS_QUERY_TYPE_A：表示查询 IPv4 地址。
DNS_QUERY_CLASS_INET：表示查询 互联网 地址。*/
    dns_qfield_t * f = (dns_qfield_t *)c;
    f->class = htons(DNS_QUERY_CLASS_INET);
    f->type = htons(DNS_QUERY_TYPE_A);
    return (uint8_t *)f + sizeof(dns_qfield_t);
}

/**
 * @brief 针对指定的entry表，发送查询报文
 * 功能：
构造一个 DNS 查询报文，填充 DNS 头部并加入查询字段。
使用 add_query_field 函数将域名信息添加到 DNS 查询中。
然后通过 UDP 将查询消息发送到 DNS 服务器（在这里是 Google 的 DNS 服务器 8.8.8.8）。
关键点：
递归标志（rd）：设置了 dns_hdr->flags.rd = 1，表示期望递归查询。
查询 ID：每个 DNS 查询都有一个唯一的 ID，用于区分不同的查询。
UDP 发送：通过 udp_sendto 函数将构建的 DNS 查询包发送到 DNS 服务器。
 */
static net_err_t dns_send_query (dns_req_t * req) {
    // 构造DNS查询包头
    dns_hdr_t * dns_hdr = (dns_hdr_t *)working_buf;
    dns_hdr->id = htons(req->query_id);
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
    dest.sin_family = AF_INET;       // 使用 IPv4 地址族
    dest.sin_port = htons(DNS_PORT_DEFAULT);    /// 设置目标端口为默认的 DNS 端口（53）
    dest.sin_addr.s_addr = x_inet_addr("8.8.8.8");//设置目标 IP 地址为 8.8.8.8（Google 的 DNS 服务器）
//udp_sendto：该函数用于通过 UDP 协议 发送数据包
// (sock_t *)dns_udp：这是一个指向 DNS UDP 套接字的指针，表示该数据包通过哪个 UDP 套接字发送。
    return udp_sendto((sock_t *)dns_udp, working_buf, buf - working_buf, 0,
                            (const struct x_sockaddr *)&dest, sizeof(dest), (ssize_t *)0);
}


/**
 * @brief 在DNS缓存表中查找指定域名对应的表项
 * 查找 DNS 缓存：遍历 dns_entry_tbl 数组，查找与给定 domain_name 匹配的 DNS 表项。
大小写不敏感的比较：使用 plat_stricmp 进行 不区分大小写 的字符串比较，确保能够匹配不同大小写的域名。
 */
dns_entry_t * dns_entry_find (const char * domain_name) {
    // 遍历列表，找稳定项，且名称相同的项
    for (int i = 0; i < DNS_ENTRY_SIZE; i++) {
        dns_entry_t * curr = dns_entry_tbl + i;
        if (!ipaddr_is_any(&curr->ipaddr)) {
            // 忽略大小写比较字符串名称，要求名称必须完全匹配
            if ((plat_stricmp(domain_name, curr->domain_name) == 0)) {
                dbg_info(DBG_DNS, "found dns entry: %s %s", curr->domain_name, domain_name);
                return curr;
            }
        }
    }

    return (dns_entry_t *)0;
}

/**
 * @brief 初始化DNS表项
 * 初始化一个新的 DNS 缓存条目，将 域名、TTL、IP 地址 赋值给 dns_entry_t 结构
 * TTL是一个在网络协议中使用的字段，主要用于限制数据包在网络中存在的时间
 * TTL 防止数据包在网络中无限制地传播。每经过一个路由器（即经过一次转发），TTL 的值都会减 1，当 TTL 值减到 0 时，数据包会被丢弃。
 */
static void dns_entry_init (dns_entry_t * entry, const char * domain_name, int ttl, ipaddr_t * ipaddr) {
    entry->ttl = ttl;
    ipaddr_copy(&entry->ipaddr, ipaddr);
    plat_strncpy(entry->domain_name, domain_name, DNS_DOMAIN_NAME_MAX - 1);
    entry->domain_name[DNS_DOMAIN_NAME_MAX - 1] = '\0';
}

/**
 * @brief 释放DNS表项
 */
static void dns_entry_free (dns_entry_t * entry) {
    ipaddr_set_any(&entry->ipaddr);
}

/**
 * @brief 插入一个新的DNS表项
 * 如果有空闲的，则使用空闲的，否则将TTL最小的最老项进行替换。
 */
static void dns_entry_insert (const char * domain_name, int ttl, ipaddr_t * ipaddr) {
    dns_entry_t * free = (dns_entry_t *)0;
    dns_entry_t * oldest = (dns_entry_t *)0;

    // 空闲， 老的
    for (int i = 0; i < DNS_ENTRY_SIZE; i++) {
        dns_entry_t * entry = dns_entry_tbl + i;

        if (ipaddr_is_any(&entry->ipaddr)) {
            free = entry;
            break;
        }

        if ((oldest == (dns_entry_t *)0) || (entry->ttl < oldest->ttl)) {
            oldest = entry;
        }
    }

    if (free == (dns_entry_t *)0) {
        free = oldest;
    }

    dns_entry_init(free, domain_name, ttl, ipaddr);

    show_entry_list();
}

/**
 * @brief 申请一个查询请求结构
 */
dns_req_t * dns_alloc_req (void) {
    return mblock_alloc(&req_mblock, 0);
}

void dns_free_req (dns_req_t * req) {
    if (req->wait_sem != SYS_SEM_INVALID) {
        sys_sem_free(req->wait_sem);
    }

    mblock_free(&req_mblock, req);
}

/**
 * @brief 加入查询队列
 */
static void dns_req_add (dns_req_t * req) {
    req->query_id = ++id;      // 纪录一下这个ID值以结构中
    req->err = NET_ERR_OK;
    req->retry_tmo = DNS_QUERY_RETRY_TMO;
    req->retry_cnt = DNS_QUERY_RETRY_CNT;
    ipaddr_set_any(&req->ipaddr);
    nlist_insert_last(&req_list, &req->node);

    show_req_list();
}

/**
 * @brief 移除请求项
 * 移除请求：将 DNS 请求从请求队列中移除。
更新请求状态：设置请求的错误码，并清空 IP 地址（如果出错）。
通知等待的任务：如果请求在等待中（wait_sem），则释放信号量，通知等待的任务可以继续执行。
 */
static void dns_req_remove (dns_req_t * req,  net_err_t err) {
    // 没有服务器可以重试了，删除该请求
    nlist_remove(&req_list, &req->node);

    // 刷新请求结构
    req->err = err;
    if (err < 0) {
        ipaddr_set_any(&req->ipaddr);
    }

    if (req->wait_sem != SYS_SEM_INVALID) {
        sys_sem_notify(req->wait_sem);
        sys_sem_free(req->wait_sem);
        req->wait_sem = SYS_SEM_INVALID;
    }

    show_req_list();
}

/**
 * @brief 当请求出现错误时的处理
 */
static void dns_req_fail(dns_req_t * req, net_err_t err) {
    // 需要停止，或者超过最大重试次数，中止
    dns_req_remove(req, err);
}

/**
 * @brief DNS查询请求消息的处理
 * 所有未被立即解析的域名请求，将被暂时插入到就绪列表中处理
 * 检查域名：验证域名的长度并进行处理。若是 localhost 或已经是 IP 地址，则直接返回。
查找缓存：首先查找是否已有对应的 DNS 解析结果（即查找缓存中的 DNS 条目）。
等待查询结果：如果缓存没有结果，创建一个信号量用于等待查询的响应，并将请求加入请求队列。
发送查询：调用 dns_send_query 发送 DNS 查询请求。
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
    //如果查询的域名是 localhost，直接返回本地回环地址 127.0.0.1
    if (plat_strcmp(dns_req->domain_name, "localhost") == 0) {
        ipaddr_from_str(&dns_req->ipaddr, "127.0.0.1");
        dns_req->err = NET_ERR_OK;
        return dns_req->err;
    }

    //如果查询的域名已经是一个有效的 IP 地址（例如 8.8.8.8），则直接将其复制到请求结构 dns_req->ipaddr 中
    //如果找到匹配的条目（即域名已解析过）
    //则直接将缓存中的 IP 地址 entry->ipaddr 赋值给请求结构 dns_req->ipaddr，并返回成功
    ipaddr_t ipaddr;
    if (ipaddr_from_str(&ipaddr, dns_req->domain_name) == NET_ERR_OK) {
        ipaddr_copy(&dns_req->ipaddr, &ipaddr);
        dns_req->err = NET_ERR_OK;
        return dns_req->err;
    }

    // 查找是否已在 DNS 缓存表 dns_entry_tbl 中找到对应的域名条目
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
 * @brief DNS表更新定时处理
 * 定时器会扫描整个表，并做不同的处理
 * 对于正在请求的表项，则会适当进行重新请求，包括简单重试或者换服务器
 * 对于已经得到结果的表项，如果生存时间过多，会进行删除
 */
static void dns_update_tmo (struct _net_timer_t* timer, void * arg) {
    // 增加age计数，有没有可能回绕呢？暂时不考虑
    for (int i = 0; i < DNS_ENTRY_SIZE; i++) {
        dns_entry_t * entry = dns_entry_tbl + i;
        if (ipaddr_is_any(&entry->ipaddr)) {
            continue;
        }

        // 稳定的项，到达生成时间后，就删除之。不自动查询了，让应用层自己去查
        // 因为应用获得IP地址后，比较少再重新使用DNS查询
        if (!entry->ttl || (--entry->ttl == 0)) {
            dns_entry_free(entry);
            show_entry_list();
        }
    }

    // 遍历列表，进行查询超时的处理或者重传超时
    nlist_node_t * curr, * next;
    for (curr = nlist_first(&req_list); curr; curr = next) {
        next = nlist_node_next(curr);

        dns_req_t * req = nlist_entry(curr, dns_req_t, node);
        if (--req->retry_tmo == 0) {
            if (--req->retry_cnt == 0) {
                dns_req_fail(req, NET_ERR_TMO);
            } else {
                req->retry_tmo = DNS_QUERY_RETRY_TMO;
                dns_send_query(req);
            }
        }
    }
}

/**
 * @brief 判断是还是否DNS数据包到达
 */
int dns_is_arrive (udp_t * udp) {
    return udp == dns_udp;
}

/**
 * @brief 当接收到 DNS报文时的处理
 * 接收 UDP 数据包：通过 udp_recvfrom 函数接收来自 DNS 服务器的响应数据包，将其存储在 working_buf 中，并记录接收到的数据长度。
解析 DNS 包头：将接收到的数据包解析为 DNS 包头 (dns_hdr_t)，并转换字段的字节序（使用 ntohs 等函数）。
 */
void dns_in (void) {
    ssize_t rcv_len;
    struct x_sockaddr_in src;
    x_socklen_t addr_len;

    // 读取数据包内容到缓存中
    net_err_t err = udp_recvfrom((sock_t *)dns_udp, working_buf, sizeof(working_buf), 0, (struct x_sockaddr *)&src, &addr_len, &rcv_len);
    if (err < 0) {
        dbg_error(DBG_DNS, "rcv udp error: %d", err);
        return;
    }
/*DNS 响应报文通常由两部分组成：
DNS 包头（包括标识符、标志位、计数等信息）。
查询区（通常是请求域名和类型信息）。
响应区（通常是域名解析的结果）*/
    const uint8_t * rcv_start = working_buf;
    const uint8_t * rcv_end = working_buf + rcv_len;

    dns_hdr_t * dns_hdr = (dns_hdr_t *)rcv_start;
    dns_hdr->id = ntohs(dns_hdr->id);
    dns_hdr->flags.all = ntohs(dns_hdr->flags.all);
    dns_hdr->qdcount = ntohs(dns_hdr->qdcount);
    dns_hdr->ancount = ntohs(dns_hdr->ancount);
    dns_hdr->nscount = ntohs(dns_hdr->nscount);
    dns_hdr->arcount = ntohs(dns_hdr->arcount);

    // 遍历请求列表，找到匹配的项
    // 遍历列表，进行查询超时的处理或者重传超时 请求的查询 ID (req->query_id)
    nlist_node_t * curr;
    nlist_for_each(curr, &req_list) {
        dns_req_t * req = nlist_entry(curr, dns_req_t, node);
        if (req->query_id != dns_hdr->id) {
            continue;
        }

        // 相同id的项，做一些更为细致地检查
        if (dns_hdr->flags.qr == 0) {
            dbg_warning(DBG_DNS, "not a responsed");
            goto req_failure;
        }

        // 不允许截断的消息
        if (dns_hdr->flags.tc == 1) {
            dbg_warning(DBG_DNS, "response truncated");
            goto req_failure;
        }

        // 服务器应当能递归查询
        if (dns_hdr->flags.ra == 0) {
            dbg_warning(DBG_DNS, "recursion not supported");
            goto req_failure;
        }

        // 检查是否有错误。对于服务器的问题，更换服务器并重试。如果是其它问题，则释放请求结构
        //错误码处理：根据 dns_hdr->flags.rcode 判断响应中的错误码，进行相应的处理：
        //DNS_ERR_NONE：没有错误，继续处理。
        //其它错误码（如 DNS_ERR_NOTIMP、DNS_ERR_REFUSED 等）：记录错误日志，并调用 req_failure 处理请求失败。
        net_err_t err = NET_ERR_OK;
        switch (dns_hdr->flags.rcode) {
        // 以下应当更换服务器
        case DNS_ERR_NONE:
            // 没有错误
            break;
        case DNS_ERR_NOTIMP:
            dbg_warning(DBG_DNS, "server reply: not support");
            err = NET_ERR_NOT_SUPPORT;
            goto req_failure;
        case DNS_ERR_REFUSED:
            dbg_warning(DBG_DNS, "server reply: refused");
            err = NET_ERR_REFUSED;
            goto req_failure;
        case DNS_ERR_SERV_FAIL:
            dbg_warning(DBG_DNS, "server reply: server failure");
            err = NET_ERR_SERVER_FAILURE;
            goto req_failure;
        case DNS_ERR_NXMOMAIN:
            dbg_warning(DBG_DNS, "server reply: domain not exist");
            err = NET_ERR_NOT_EXIST;
            goto req_failure;
        // 以下直接删除请求
        case DNS_ERR_FORMAT:
            dbg_warning(DBG_DNS, "server reply: format error");
            err = NET_ERR_FORMAT;
            goto req_failure;
        default:
            dbg_warning(DBG_DNS, "unknow error");
            err = NET_ERR_UNKNOW;
            goto req_failure;
        }

        // 检查问题区域
        if (dns_hdr->qdcount == 1) {
            rcv_start += sizeof(dns_hdr_t);
            rcv_start = (const uint8_t *)domain_name_cmp(req->domain_name, (const char *)rcv_start, rcv_end - rcv_start);
            if (rcv_start == (uint8_t *)0) {
                dbg_warning(DBG_DNS, "domain name not match");
                err = NET_ERR_FORMAT;
                goto req_failure;
            }

            // 检查问题其它字段，首先是大小
            if (rcv_start + sizeof(dns_qfield_t) > rcv_end) {
                dbg_warning(DBG_DNS, "size error");
                err = NET_ERR_SIZE;
                goto req_failure;
            }

            // 必须为互联网类
            dns_qfield_t * qf = (dns_qfield_t *)rcv_start;
            if (qf->class != ntohs(DNS_QUERY_CLASS_INET)) {
                dbg_warning(DBG_DNS, "query class not inet");
                err = NET_ERR_FORMAT;
                goto req_failure;
            }

            // 必须为A纪录类型，暂不支持其它类型
            if (qf->type != ntohs(DNS_QUERY_TYPE_A)) {
                dbg_warning(DBG_DNS, "query class not inet");
                err = NET_ERR_FORMAT;
                goto req_failure;
            }
            rcv_start += sizeof(dns_qfield_t);
        }

        // 检查响应区域
         // 响应区域至少要一个，当然如果有多个我们只读取一个。下面最好也检查一下，是否是只有一个
        if (dns_hdr->ancount < 1) {
            dbg_warning(DBG_DNS, "no answer");
            err = NET_ERR_NO_REPLY;
            goto req_failure;
        }

        // 循环遍历整个列表，找出A纪录项
        for (int i = 0; (i < dns_hdr->ancount) && (rcv_start < rcv_end); i++) {
            // 跳过域名，不做检查
            rcv_start = domain_name_skip(rcv_start, rcv_end - rcv_start);
            if (rcv_start == (uint8_t *)0) {
                dbg_warning(DBG_DNS, "size error");
                err = NET_ERR_FORMAT;
                goto req_failure;
            }

            // 检查其余字段，首先空间要够
            if (rcv_start + sizeof(dns_afield_t) > rcv_end) {
                dbg_warning(DBG_DNS, "size error");
                err = NET_ERR_FORMAT;
                goto req_failure;
            }

            // 进行必要的检查后取结果
            //dns_afield_t：这是 DNS 响应中 A 记录 的结构体
            dns_afield_t * af = (dns_afield_t *)rcv_start;
            if ((af->class == ntohs(DNS_QUERY_CLASS_INET))
                && (af->type == ntohs(DNS_QUERY_TYPE_A))
                && (af->rd_len == ntohs(IPV4_ADDR_SIZE))) {
                // 获取IP地址，同时往缓存表中插入新表项
                //af->rdata：这是 DNS A 记录的 响应数据，它包含了域名对应的 IP 地址
                ipaddr_from_buf(&req->ipaddr, (uint8_t *)af->rdata);
                dns_entry_insert(req->domain_name, ntohl(af->ttl), &req->ipaddr);

                dbg_info(DBG_DNS, "recv dns A type: %s %s", req->domain_name);
                dbg_dump_ip(DBG_DNS, "ipaddr:", &req->ipaddr);

                // 给应用发通知，通知解析完毕，退出解析
                dns_req_remove(req, NET_ERR_OK);
                return;
            }
//这两个字节是 rd_len 字段的长度。因为在 rdata 后面有一个长度字段（2 字节），所以需要减去这 2 个字节，指向下一个需要解析的数据。
            rcv_start += sizeof(dns_afield_t) + ntohs(af->rd_len) - 2;  // 减去结构体中的2个字节
        }
req_failure:
        // 出错处理，或者没有合适的解析项，选用下一个服务器进行请求。如果没有合适的服务器，请求将被删除
        dns_req_fail(req, err);
        return;
    }
}

/**
 * @brief 初始化DNS
 */
void dns_init (void) {
    dbg_info(DBG_DNS, "DNS init");

    plat_memset(dns_entry_tbl, 0, sizeof(dns_entry_tbl));

    // 表刷新定时器处理
    net_timer_add(&entry_update_timer, "dns timer", dns_update_tmo, (void *)0, DNS_UPDATE_PERIOID * 1000, NET_TIMER_RELOAD);

    // 套接字初始化
    dns_udp = (udp_t *)udp_create(AF_INET, IPPROTO_UDP);
    dbg_assert(dns_udp != (udp_t *)0, "create udp socket failed");

    // 建立请求表
    nlist_init(&req_list);
    mblock_init(&req_mblock, dns_req_list, sizeof(dns_req_t), DNS_REQ_SIZE, NLOCKER_THREAD);

    dbg_info(DBG_DNS, "DNS done");
}

/*在 DNS 协议 中，域名的表示有两种方式：普通表示 和 压缩表示。
1.普通表示：每个域名部分的前面都有一个字节表示该部分的长度，后跟该部分的字符。多个域名部分用 . 分隔。
2.压缩表示：DNS 中为了节省空间，域名中的某些部分可以 压缩，通过使用指针来引用之前出现过的域名部分。
压缩的域名部分用特殊的 压缩标签 来表示。压缩标签的格式如下：
高位为 0xC0，后跟 2 字节的指针，该指针指向 先前出现过的某个位置。
压缩标签格式：
0xC0（高位字节）
紧接着两个字节，表示指针的偏移量，指向前面的某个位置。*/