#include "tcp.h"
#include "tools.h"
#include "protocol.h"
#include "ipv4.h"
#include "mblock.h"
#include "dbg.h"
#include "exmsg.h"
#include "socket.h"
#include "timer.h"
#include "tcp_out.h"
#include "tcp_state.h"

static tcp_t tcp_tbl[TCP_MAX_NR];           // tcp控制块数组 存放所有 TCP 控制块
static mblock_t tcp_mblock;                 // 空闲TCP控制块链表 用于分配/回收 TCP 控制块
static nlist_t tcp_list;                     // 已创建的控制块链表    已建立连接和监听套接字都会挂tcp_list

#if DBG_DISP_ENABLED(DBG_TCP)
/**
 * @brief 显示TCP的状态
 */
void tcp_show_info (char * msg, tcp_t * tcp) {
    plat_printf("%s: %s\n", msg, (tcp->state < TCP_STATE_MAX) ? tcp_state_name(tcp->state) : "UNKNOWN");
    plat_printf("    local port: %u, remote port: %u\n", tcp->base.local_port, tcp->base.remote_port);
    plat_printf("    snd.una: %u, snd.nxt: %u\n", tcp->snd.una, tcp->snd.nxt);
}

void tcp_display_pkt (char * msg, tcp_hdr_t * tcp_hdr, pktbuf_t * buf) {
    plat_printf("%s\n", msg);
    plat_printf("    sport: %u, dport: %u\n", tcp_hdr->sport, tcp_hdr->dport);
    plat_printf("    seq: %u, ack: %u, win: %d\n", tcp_hdr->seq, tcp_hdr->ack, tcp_hdr->win);
    plat_printf("    flags:");
    /*打印 TCP 控制位：
SYN → 建立连接请求
RST → 重置连接
ACK → 确认号有效
PSH → 数据立即推送
FIN → 关闭连接*/
    if (tcp_hdr->f_syn) {
        plat_printf(" syn");
    }
    if (tcp_hdr->f_rst) {
        plat_printf(" rst");
    }
    if (tcp_hdr->f_ack) {
        plat_printf(" ack");
    }
    if (tcp_hdr->f_psh) {
        plat_printf(" push");
    }
    if (tcp_hdr->f_fin) {
        plat_printf(" fin");
    }

    plat_printf("\n    len=%d", buf->total_size - tcp_hdr_size(tcp_hdr));
    plat_printf("\n");
}

void tcp_show_list (void) {
    plat_printf("-------- tcp list -----\n");

    nlist_node_t * node;
    nlist_for_each(node, &tcp_list) {
        tcp_t * tcp = (tcp_t *)nlist_entry(node, sock_t, node);

        tcp_show_info("", tcp);
    }
}
#endif

/**
 * @brief 分配一个有效的TCP端口
 * 下面的算法中，端口号的选择从1024开始递增
 * 但实际不同系统的端口分配看起来是有一定随意性的 也许可以加一点点随机的处理 加随机偏移，避免端口冲突或 Wireshark 显示混乱
 */
int tcp_alloc_port(void) {
#if 1 // NET_DBG
    // 调用试用，以便每次启动调试时使用的端口都不同，wireshark中显示更干净
    // 并且不会与上次的连接重复，避免对本次连接造成干扰。并不严格的处理，只提供随机处理
    srand((unsigned int)time(NULL));
    int search_idx = rand() % 1000 + NET_PORT_DYN_START;
#else
    static int search_idx = NET_PORT_DYN_START;  // 搜索起点
#endif
    // 遍历所有动态端口
    for (int i = NET_PORT_DYN_START; i < NET_PORT_DYN_END; i++) {
        // 看看是否有使用，如果没有使用则返回；否则继续
        nlist_node_t* node;
        nlist_for_each(node, &tcp_list) {
            sock_t* sock = nlist_entry(node, sock_t, node);
            //如果 sock->local_port == search_idx，说明当前端口已被占用：
            //当 break 被触发时，node 不为 NULL → 不会走 return port → 会继续检查下一个 search_idx。
            //如果没有 break，循环会完整遍历到 NULL → if(!node) 会误判为端口空闲，这样可能返回已被占用的端口。
            if (sock->local_port == search_idx) {
                // 发现有使用，跳出继续比较
                break;
            }
        }

        // 增加索引
        int port = search_idx++;
        if (search_idx >= NET_PORT_DYN_END) {
            search_idx = NET_PORT_DYN_START;
        }

        // 没有使用，跳出使用该端口结束查询
        if (!node) {
            return port;
        }
    }
    return -1;
}

/**
 * @brief 根据目的IP和端口号地址对，找到对应的sock块
 * tcp链表只有三种类型的块，一是完全匹配的；二是只有指定了本地端口的，三是同时指定了本地端口和IP的

根据本地/远端 IP + 端口号，找到对应的 TCP 控制块。
完全匹配 → 半匹配 → 监听匹配

完全匹配（本地端口+远端端口+本地 IP + 远端 IP）
部分匹配（本地端口 + 本地 IP 或 ANY）
监听匹配TCP 服务器处于 LISTEN 状态，只知道本地端口号（例如 80），本地 IP 可能是具体 IP 或 ANY（0.0.0.0）远端 IP/端口未知，等待客户端发起连接。
 */
sock_t* tcp_find(ipaddr_t * local_ip, uint16_t local_port, ipaddr_t * remote_ip, uint16_t remote_port) {
    sock_t* match = (sock_t*)0;

    // 遍历整个列表, 找到对应的sock块
    // 优先找完全匹配的项，其次找处理监听匹配的项
    nlist_node_t* node;
    nlist_for_each(node, &tcp_list) {
        sock_t* s = nlist_entry(node, sock_t, node);

        // 地址对完全匹配，即是想要的项
        if ((s->local_port == local_port) &&
            ipaddr_is_equal(&s->remote_ip, remote_ip) && (s->remote_port == remote_port)) {
            if (ipaddr_is_any(&s->local_ip)) {
                return s;
            } else if (ipaddr_is_equal(&s->local_ip, local_ip)) {
                return s;
            }
        }

        // 也可能存在不完全匹配的项目，即只匹配了一部分，例如：
        // 对于服务器而言，会有处理listen状态的sock，只包含了本地端口号，其余都未给定
        tcp_t * tcp = (tcp_t *)s;
        if ((tcp->state == TCP_STATE_LISTEN) && (s->local_port == local_port)) {
            if (ipaddr_is_equal(&s->local_ip, local_ip)) {
                return s;
            } else if (ipaddr_is_any(&s->local_ip)) {
                match = s;
            }
        }
    }

    // 当没有完全匹配项时，使用部分目的端口匹配的项
    return (sock_t*)match;
}

/**
 * @brief 分配一个TCP，先尝试分配空闲的，然后是重用处于time_wait的
 * TIME_WAIT 回收是 TCP 规范的一部分，避免端口耗尽。
分配失败 → 说明 TCP 连接数量达到上限，需要合理配置 TCP_MAX_NR
 */
static tcp_t * tcp_get_free (int wait) {
    // 分配一个tcp sock结构
    tcp_t* tcp = (tcp_t*)mblock_alloc(&tcp_mblock, wait ? 0 : -1);
    if (!tcp) {
        // 从表中找处于time-wait的结点
        nlist_node_t* node;
        nlist_for_each(node, &tcp_list) {
            tcp_t* s = (tcp_t *)nlist_entry(node, sock_t, node);
            if (s->state == TCP_STATE_TIME_WAIT) {
                // 先销毁掉，再重新分配
                tcp_free(s);
                return (tcp_t*)mblock_alloc(&tcp_mblock, -1);
            }
        }
    }

    return tcp;
}

/**
 * @brief 设置TCP选项
 * SOL_SOCKET的通用套接字级别选项 Keepalive 开关（tcp_keepalive_start）	启用 TCP Keepalive 功能，用于检测死连接，尤其是长连接或服务器端
 步骤：先调用通用 sock_setopt。
如果通用处理不了，针对 TCP 进行处理：
检查参数长度。
设置 TCP keepalive 参数。
调用 tcp_keepalive_restart 重启计时器
 */
net_err_t tcp_setopt(struct _sock_t* sock,  int level, int optname, const char * optval, int optlen) {
	// 先用osck中的配置项处理
    // NET_ERR_OK → 选项被处理完成，直接返回。  < 0 且不是 NET_ERR_UNKNOW → 说明是严重错误，直接返回。
    //NET_ERR_UNKNOW → 未处理选项，继续 TCP 特有选项处理。
    net_err_t err = sock_setopt(sock, level, optname, optval, optlen);
    if (err == NET_ERR_OK) {
        return NET_ERR_OK;
    } else if ((err < 0) && (err != NET_ERR_UNKNOW)) {
        return err;
    }

    // 必要参数检查
    tcp_t * tcp = (tcp_t *)sock;
    if (level == SOL_SOCKET) {
        if (optlen != sizeof(int)) {
            dbg_error(DBG_TCP, "param size error");
            return NET_ERR_PARAM;
        }
        tcp_keepalive_start(tcp, *(int *)optval);
    } else if (level == SOL_TCP) {
        // TCP选项相关的处理
        //处理 TCP 协议特有选项：
/*TCP_KEEPIDLE → 空闲多久开始探测。
TCP_KEEPINTVL → 探测间隔。
TCP_KEEPCNT → 探测次数*/
        switch (optname) {
        case TCP_KEEPIDLE:
            if (optlen != sizeof(int)) {
                dbg_error(DBG_TCP, "param size error");
                return NET_ERR_PARAM;
            }
            tcp->conn.keep_idle = *(int *)optval;
            tcp_keepalive_restart(tcp);
            return NET_ERR_OK;
        case TCP_KEEPINTVL:
            if (optlen != sizeof(int)) {
                dbg_error(DBG_TCP, "param size error");
                return NET_ERR_PARAM;
            }
            tcp->conn.keep_intvl = *(int *)optval;
            tcp_keepalive_restart(tcp);
            return NET_ERR_OK;
        case TCP_KEEPCNT:
            if (optlen != sizeof(int)) {
                dbg_error(DBG_TCP, "param size error");
                return NET_ERR_PARAM;
            }
            tcp->conn.keep_cnt = *(int *)optval;
            tcp_keepalive_restart(tcp);
            return NET_ERR_OK;
        default:
            dbg_error(DBG_TCP, "unknowm param");
            break;
        }
    }
    return NET_ERR_PARAM;
}

/**
 * @brief 分配一个TCP块，该控制块用于用于主动打开或者被动打开
 * 对于处理listen状态的TCP，要避免锁住
 */
/*分配一个 TCP 控制块（tcp_t）
初始化基础 socket 操作表
初始化 TCP 状态机和各类参数
初始化发送/接收/连接等待结构
失败时进行回滚和资源释放*/
/*.connect / .close / .send / .recv → 基本连接和数据收发
.setopt → TCP 选项设置
.bind / .listen / .accept → 服务器监听/接受连接
.destroy → 回收资源*/
static tcp_t* tcp_alloc(int wait, int family, int protocol) {
    static const sock_ops_t tcp_ops = {
        .connect = tcp_connect,
        .close = tcp_close,
        .send = tcp_send,
        .recv = tcp_recv,
        .setopt = tcp_setopt,
        .bind = tcp_bind,
        .listen = tcp_listen,
        .accept = tcp_accept,
        .destroy = tcp_destory,
};

    // 分配一个tcp sock结构
    //从空闲 TCP 控制块池获取一个块。  如果池中没有，可能重用处于 TIME_WAIT 的块
    tcp_t* tcp = tcp_get_free(wait);
    if (!tcp) {
        dbg_error(DBG_TCP, "no tcp sock");
        return (tcp_t*)0;
    }
    //清0 保持干净
    plat_memset(tcp, 0, sizeof(tcp_t));

    // 基础部分
    //所有 TCP 连接必须从 CLOSED 状态开始。 如果初始化失败，需要释放分配的内存
    net_err_t err = sock_init((sock_t*)tcp, family, protocol, &tcp_ops);
    if (err < 0) {
        dbg_error(DBG_TCP, "create failed.");
        mblock_free(&tcp_mblock, tcp);
        return (tcp_t*)0;
    }
    tcp->state = TCP_STATE_CLOSED;
//初始化默认 Keepalive 设置：默认不启用 (keep_enable = 0)   idle、interval、probe 次数设置默认值
    tcp->flags.keep_enable = 0;
    tcp->conn.keep_idle = TCP_KEEPALIVE_TIME;
    tcp->conn.keep_intvl = TCP_KEEPALIVE_INTVL;
    tcp->conn.keep_cnt = TCP_KEEPALIVE_PROBES;

    // 发送部分初始化，缓存不必初始化，在建立连接时再做
    /*发送部分：una → 最早未确认序号   nxt → 下一个序号  iss → 初始序号  ostate → 发送状态  rto → 重传超时  rexmit_max → SYN 重传次数
    接收部分：nxt → 下一个期待的序号  iss → 初始序号*/
    tcp->snd.una = tcp->snd.nxt = tcp->snd.iss = 0;
    tcp->snd.ostate = TCP_OSTATE_IDLE;
    tcp->snd.rto = TCP_INIT_RTO;        // 设置缺省的RTO
    tcp->snd.ostate = TCP_OSTATE_IDLE;      // 空闲状态
    tcp->snd.rexmit_max = TCP_INT_RETRIES;  // SYN重发次数

    // 接收部分初始化，缓存不必初始化，在建立连接时再做
    tcp->rcv.nxt = tcp->rcv.iss = 0;

    // 初始化等待结构
    /*| 字段     | 阻塞用途   | 唤醒条件           | 核心功能                 |
| ----------- | ------ | -------------- | -------------------- |
| `snd.wait`  | 发送缓冲区满 | ACK 到来/窗口更新    | 流量控制、发送可靠性           |
| `rcv.wait`  | 接收缓冲区空 | TCP 数据到达       | 阻塞式接收、按序递交数据         |
| `conn.wait` | 等待连接完成 | 三次握手完成 / 新连接到达 | 阻塞式 connect / accept |
*/
    if (sock_wait_init(&tcp->snd.wait) < 0) {
        dbg_error(DBG_TCP, "create snd.wait failed");
        goto alloc_failed;
    }
    tcp->base.snd_wait = &tcp->snd.wait;

    if (sock_wait_init(&tcp->rcv.wait) < 0) {
        dbg_error(DBG_TCP, "create rcv.wait failed");
        goto alloc_failed;
    }
    tcp->base.rcv_wait = &tcp->rcv.wait;

    if (sock_wait_init(&tcp->conn.wait) < 0) {
        dbg_error(DBG_TCP, "create conn.wait failed");
        goto alloc_failed;
    }
    tcp->base.conn_wait = &tcp->conn.wait;
    return tcp;
alloc_failed:
    if (tcp->base.snd_wait) {
        sock_wait_destroy(tcp->base.snd_wait);
    }
    if (tcp->base.rcv_wait) {
        sock_wait_destroy(tcp->base.rcv_wait);
    }
    if (tcp->base.conn_wait) {
        sock_wait_destroy(tcp->base.conn_wait);
    }
    mblock_free(&tcp_mblock, tcp);
    return (tcp_t *)0;
}

/**
 * @brief 释放一个控制块
 * 只允许最终被TIME-WAIT状态下调用，或者由用户上层间接调用
 */
void tcp_free(tcp_t* tcp) {
    //确保 TCP 块未被重复释放，避免野指针
    dbg_assert(tcp->state != TCP_STATE_FREE, "tcp free");
    tcp_kill_all_timers(tcp);

    // 在create中，即便没有创建，但由于全部清空，所以下面处理也没问题
    sock_wait_destroy(&tcp->conn.wait);
    sock_wait_destroy(&tcp->snd.wait);
    sock_wait_destroy(&tcp->rcv.wait);

    // 释放回原来的缓存表
    tcp->state = TCP_STATE_FREE;        // 调试用，方便观察
    //从全局 TCP 列表中删除
    nlist_remove(&tcp_list, &tcp->base.node);
    //回收到 TCP 控制块池
    mblock_free(&tcp_mblock, tcp);
}

/**
 * @brief 插入TCP块
 */
//将新建的 TCP 控制块加入全局 TCP 列表。  便于 TCP 查找和管理
void tcp_insert (tcp_t * tcp) {
    nlist_insert_last(&tcp_list, &tcp->base.node);

    dbg_assert(tcp_list.count <= TCP_MAX_NR, "tcp free");
}

/**
 * @brief keepalive（TCP 协议功能，用于检测空闲连接是否还活着）定时超时
 * 工作流程：
 * 1增加 keep_retry 次数。
2如果未超过最大重试次数：
发送 Keepalive 探测包。
重新启动定时器。
3如果超过最大重试次数：
发送 RST 通知对端连接关闭。
触发 TCP 连接中止。
 */
static void tcp_keepalive_tmo(struct _net_timer_t* timer, void * arg) {
    tcp_t * tcp = (tcp_t *)arg;

    // 未超重试次数，继续尝试, 但以更小的时间发送
    if (++tcp->conn.keep_retry <= tcp->conn.keep_cnt) {
        // 发送keepalive报文
        tcp_send_keepalive(tcp);

        net_timer_remove(&tcp->conn.keep_timer);
        //net_timer_remove() + net_timer_add() → 重新设置下一个 Keepalive 超时时间
        net_timer_add(&tcp->conn.keep_timer, "keepalive", tcp_keepalive_tmo, tcp, tcp->conn.keep_intvl*1000, 0);
        dbg_info(DBG_TCP, "tcp keepalive tmo, retrying: %d", tcp->conn.keep_retry);
    } else {
        // 通知应用，TCP已经关闭
        tcp_send_reset_for_tcp(tcp);
        tcp_abort(tcp, NET_ERR_TMO);
        dbg_error(DBG_TCP, "tcp keepalive tmo, give up");
    }
}

/**
 * @brief 在 TCP 连接的合适状态下启动 Keepalive 定时器。
 * 不启动 Keepalive 的状态：
CLOSED：连接未建立
SYN_SENT、SYN_RECVD：三次握手阶段
LISTEN：服务器监听，但未建立连接
CLOSE_WAIT、FIN_WAIT_1/2、CLOSING、TIME_WAIT：连接关闭或关闭过程中
启动 Keepalive 的状态：
ESTABLISHED：TCP 连接已经成功建立，数据可以传输。
 */
static void keepalive_start_timer (tcp_t * tcp) {
    // 由关闭到运行
    switch (tcp->state) {
    case TCP_STATE_CLOSED:
    case TCP_STATE_SYN_SENT:
    case TCP_STATE_SYN_RECVD:
    case TCP_STATE_LISTEN:
        // 这些状态，没有建立连接，暂不启动keepalive，在后面建立连接之后再启动
        break;
    case TCP_STATE_ESTABLISHED:
        tcp->conn.keep_retry = 0;
        //软定时器
        net_timer_add(&tcp->conn.keep_timer, "keepalive", tcp_keepalive_tmo, tcp, tcp->conn.keep_idle*1000, 0);
        dbg_info(DBG_TCP, "tcp keepalive enabled.");
        break;
    case TCP_STATE_CLOSE_WAIT:
    case TCP_STATE_FIN_WAIT_1:
    case TCP_STATE_FIN_WAIT_2:
    case TCP_STATE_CLOSING:
    case TCP_STATE_TIME_WAIT:
        // 这些状态，要求或已经关闭了，不启用
        break;
    default:
        break;
    }
}

/**
 * @brief 启动TCP的keepavlie
 * 根据当前状态判断是否实际执行操作：
如果已启用且要关闭 → 移除定时器。
如果未启用且要启动 → 调用 keepalive_start_timer。
 */
void tcp_keepalive_start (tcp_t * tcp, int run) {
    if (tcp->flags.keep_enable && !run) {
        // 由运行到关闭, 关闭定时器即可
        net_timer_remove(&tcp->conn.keep_timer);
        dbg_info(DBG_TCP, "keepalive disabled");
    } else if (!tcp->flags.keep_enable && run) {
        keepalive_start_timer(tcp);
    }
    tcp->flags.keep_enable = run;
}

/**
 * @brief 重启keepalive处理
 * 如果未启用，则不用管他。如果已经启用了，则重启他
 * 会清除原定时器 (net_timer_remove) 并重新添加 (keepalive_start_timer)。
重置重试次数 keep_retry = 0，保证下一轮检测从 0 开始。
 */
void tcp_keepalive_restart (tcp_t * tcp) {
    if (tcp->flags.keep_enable) {
        // 移除后重启定时器
        net_timer_remove(&tcp->conn.keep_timer);
        keepalive_start_timer(tcp);
        tcp->conn.keep_retry = 0;
    }
}

/**
 * @brief 获取TCP初始序列号，用于新创建一个连接时
 * 根据RFC793：初始序号列根据时钟产生，每4微秒增长一次
 * 这个实现比较麻烦，所以不遵循这个规范，简单的实现
 * 初始序列号用于防止旧连接干扰新连接。
 */
static uint32_t tcp_get_iss(void) {
    static uint32_t seq = 0;

    // 每次调用增长一下，保证不一样就可以了
#if 0
    seq += seq == 0 ? clock() : 305;
#else
    seq += seq == 0 ? 32435 : 305;
#endif
    return seq;
}

/**
 * @brief 计算接收窗口的大小获取
即接收缓冲区还能接收多少字节数据。
 */
int tcp_rcv_window (tcp_t * tcp) {
    int window = tcp_buf_free_cnt(&tcp->rcv.buf);
    return window;
}

/**
 * @brief 清除TCP所有定时器
 * 避免定时器回调在 TCP 已销毁时执行。
是 TCP 资源释放的必要步骤
 */
void tcp_kill_all_timers (tcp_t * tcp) {
    net_timer_remove(&tcp->snd.timer);
    net_timer_remove(&tcp->conn.keep_timer);
}

/**
 * @brief 中止TCP连接，进入CLOSED状态，通知应用程序
 * 释放资源的工具由应用调用close完成
 */
net_err_t tcp_abort (tcp_t * tcp, int err) {
    tcp_kill_all_timers(tcp);
    tcp_set_state(tcp, TCP_STATE_CLOSED);
    sock_wakeup(&tcp->base, SOCK_WAIT_ALL, err);
    return NET_ERR_OK;
}

/**
 * @brief 为tcp连接做好准备，初始化其中的一些字段值
 */
static net_err_t tcp_init_connect(tcp_t * tcp) {
    // 重新计算mss，选项不计算在内
    rentry_t* rt = rt_find(&tcp->base.remote_ip);   //查找到达目标 IP 的路由条目
    if (rt->netif->mtu == 0) {
        //tcp->mss如果 MTU=0 或不在本地网络 → 使用默认 MSS（576字节，包括 IP/TCP 头部）。
        //如果在本地网络 → 使用接口 MTU 减去 IP/TCP 头部长度。
        tcp->mss = TCP_DEFAULT_MSS;         // RFC1122, 加上IP和TCP头，总共576字节
    } else if (!ipaddr_is_any(&rt->next_hop)) {
        // 非本地网络内，使用576
        tcp->mss = TCP_DEFAULT_MSS;         // RFC1122, 加上IP和TCP头，总共576字节
    } else {
        // 同一网段，使用MTU减去两个头部
        tcp->mss = rt->netif->mtu - sizeof(ipv4_hdr_t) - sizeof(tcp_hdr_t);
    }

    // 发送部分初始化
    tcp_buf_init(&tcp->snd.buf, tcp->snd.data, TCP_SBUF_SIZE); //初始化发送缓存区（TCP 发送队列
    //初始序列号设置
    //una = 已确认的序号（ACK 已收到的位置）  nxt = 下一个要发送的序号
    tcp->snd.iss = tcp_get_iss();
    tcp->snd.una = tcp->snd.nxt = tcp->snd.iss;

    // 接收部分初始化
    tcp_buf_init(&tcp->rcv.buf, tcp->rcv.data, TCP_RBUF_SIZE);
    tcp->rcv.nxt = 0;

    return NET_ERR_OK;
}

/**
 * @brief 开始TCP连接请求，这里会向远端发送SYN请求进行连接的建立
 */
net_err_t tcp_connect(sock_t* sock, const struct x_sockaddr* addr, x_socklen_t len) {
    tcp_t * tcp = (tcp_t *)sock;

    // 只有处于close状态的才能建立连接,其它状态不可以
    if (tcp->state != TCP_STATE_CLOSED) {
        dbg_error(DBG_TCP, "tcp is not closed. connect is not allowed");
        return NET_ERR_STATE;
    }

    // 设置远程IP和端口号
    const struct x_sockaddr_in* addr_in = (const struct x_sockaddr_in*)addr;
    ipaddr_from_buf(&sock->remote_ip, (uint8_t *)&addr_in->sin_addr.s_addr);
    sock->remote_port = x_ntohs(addr_in->sin_port);

    // 检查本地端口号，如果为0，则分配端口号
    if (sock->local_port == NET_PORT_EMPTY) {
        int port = tcp_alloc_port();
        if (port == -1) {
            dbg_error(DBG_TCP, "alloc port failed.");
            return NET_ERR_NONE;
        }
        sock->local_port = port;
    }

    // 检查本地IP地址：为空，根据路由表选择合适的接口IP
    if (ipaddr_is_any(&sock->local_ip)) {
        // 检查路径，看看是否能够到达目的地。不能达到返回错误
        rentry_t * rt = rt_find(&sock->remote_ip);
        if (rt == (rentry_t*)0) {
            dbg_error(DBG_TCP, "no route to dest");
            return NET_ERR_UNREACH;
        }
        ipaddr_copy(&sock->local_ip, &rt->netif->ipaddr);
    }

    // 初始化tcp连接
    net_err_t err;
    if ((err = tcp_init_connect(tcp)) < 0) {
        dbg_error(DBG_TCP, "init conn failed.");
        return err;
    }
//SYN 报文就是用于 建立 TCP 连接的报文
/*三次握手过程：
客户端 → 服务器：发送 SYN（带初始序列号）。
服务器 → 客户端：收到 SYN 后，发送 SYN+ACK（确认客户端序列号 + 自己的初始序列号）。
客户端 → 服务器：收到 SYN+ACK 后，发送 ACK，确认服务器序列号。*/
    if ((err = tcp_send_syn(tcp)) < 0) {
        dbg_error(DBG_TCP, "send syn failed.");
        return err;
    }
    // 发送SYNC报文，进入sync_send状态
    tcp_set_state(tcp, TCP_STATE_SYN_SENT);

    // 继续等待后续连接的建立
    return NET_ERR_NEED_WAIT;
}

/**
 * 绑定本地端口。
 * 主要用于服务器，服务器会监听本地IP和某个端口，以便处理收到的数据包
 * 客户端也可用，用于指定本地连接所用的ip和端口号
 *    同一个Socket只可以将1个端口绑定到1个地址上。 （ok）
 *    即使不同的Socket也不能重复绑定相同的地址和端口。  (ok)
 *    不同的Socket可以将不同的端口绑定到相同的IP地址上。 (ok)
 *    不同的Socket可以将相同的端口绑定到不同的IP地址上。 (ok)
 */
//TCP只能在 CLOSED 状态下绑定端口
net_err_t tcp_bind(sock_t* sock, const struct x_sockaddr* addr, x_socklen_t len) {
    tcp_t * tcp = (tcp_t *)sock;

    // 只有处于close状态的才能建立连接,其它状态不可以
    if (tcp->state != TCP_STATE_CLOSED) {
        dbg_error(DBG_TCP, "tcp is not closed. connect is not allowed");
        return NET_ERR_STATE;
    }

    // 如果已经绑定了，则不允许再次绑定
    if (sock->local_port != NET_PORT_EMPTY) {
        dbg_error(DBG_UDP, "already binded.");
        return NET_ERR_PARAM;
    }

    // 绑定的端口号不能为0
    const struct x_sockaddr_in* addr_in = (const struct x_sockaddr_in*)addr;
    if (addr_in->sin_port == NET_PORT_EMPTY) {
        dbg_error(DBG_TCP, "port is emptry");
        return NET_ERR_PARAM;
    }

    // 如果IP地址不为空，则应为本地某接口的地址
    ipaddr_t local_ip;
    ipaddr_from_buf(&local_ip, (const uint8_t*)&addr_in->sin_addr);
    if (!ipaddr_is_any(&local_ip)) {
        // 查找路由表，检查是否有该项
        rentry_t* rt = rt_find(&local_ip);
        if (rt == (rentry_t*)0) {
            dbg_error(DBG_TCP, "ipaddr error, no netif has this ip");
            return NET_ERR_ADDR;
        }

        // IP地址必须完全一样
        if (!ipaddr_is_equal(&local_ip, &rt->netif->ipaddr)) {
            dbg_error(DBG_TCP, "ipaddr error");
            return NET_ERR_ADDR;
        }
    }

    // 遍历列表，查找有是否有相同绑定的TCP（不检查已经连接的端口）
    nlist_node_t * node;
    nlist_for_each(node, &tcp_list) {
        sock_t * curr = (sock_t *)nlist_entry(node, sock_t, node);

        // 远端端口不非为空（已经连接的 Socket），既已经连接，不检查
        if ((sock == curr) || (curr->remote_port != NET_PORT_EMPTY)) {
            continue;
        }

        // 本地地址完全匹配，错误
        //TCP 不允许 同一 IP + 端口被两个监听 Socket 使用
        if (ipaddr_is_equal(&curr->local_ip, &local_ip) && (curr->local_port == addr_in->sin_port)) {
            dbg_error(DBG_TCP, "ipaddr and port already used");
            return NET_ERR_ADDR;
        }
    }

    // 记录下IP地址和端口号， IP地址可能为空
    ipaddr_copy(&sock->local_ip, &local_ip);
    sock->local_port = x_ntohs(addr_in->sin_port);;
    return NET_ERR_OK;
}

/**
 * @brief 清除父子连接关系
 */
void tcp_clear_parent (tcp_t * tcp) {
    nlist_node_t * node;

    // 遍历，寻找子TCP，断开连接
    nlist_for_each(node, &tcp_list) {
        sock_t * sock = nlist_entry(node, sock_t, node);
        tcp_t * child = (tcp_t *)sock;

        // 清除父子连接关系。在backlog队列中的处于自由状态
        //backlog 队列 在 TCP 实现中指的就是 服务器端用于暂存已经完成三次握手、但应用程序还没 accept 的 TCP 连接的队列。
  /*1 backlog 队列（半连接或已完成连接暂存队列）
类型通常是链表或环形数组。
存放已经完成 三次握手 的客户端 TCP 控制块（tcp_t）。
当服务器调用 accept() 时，从这个队列取出一个连接。
2未完成连接队列（SYN 阶段）
存放正在进行三次握手的连接。
当三次握手完成后，移到 backlog 队列。*/
        if (child->parent == tcp) {
            child->parent = (tcp_t *)0;
        }
    }
}


/**
 * @brief 关闭TCP连接
 * 关闭TCP连接，并且回收所TCP资源
 * TODO: tcp的释放
 */
net_err_t tcp_close(sock_t* sock) {
    tcp_t* tcp = (tcp_t*)sock;

    dbg_info(DBG_TCP, "closing tcp: state = %s", tcp_state_name(tcp->state));

    // 针对每一种TCP状态，做不同的关闭处理
    switch (tcp->state) {
        case TCP_STATE_CLOSED:
            dbg_info(DBG_TCP, "tcp already closed");
            tcp_free(tcp);
            return NET_ERR_OK;
        case TCP_STATE_LISTEN:          // listen没有连接，直接删除
            //调用 tcp_clear_parent() 清理 backlog 队列中指向这个监听 socket 的子连接。
            //调用 tcp_abort() 强制进入 CLOSED 状态。
            tcp_clear_parent(tcp);
            tcp_abort(tcp, NET_ERR_CLOSE);
            tcp_free(tcp);
            return NET_ERR_OK;
        case TCP_STATE_SYN_RECVD:
        case TCP_STATE_SYN_SENT:        // 连接未建立，直接删除
            tcp_abort(tcp, NET_ERR_CLOSE);
            tcp_free(tcp);
            return NET_ERR_OK;
        case TCP_STATE_CLOSE_WAIT:
            // 发送fin通知自己要关闭发送。但要注意，这里并不一定立即发送FIN, 并且要等
            tcp_send_fin(tcp);
            tcp_set_state(tcp, TCP_STATE_LAST_ACK);
            return NET_ERR_NEED_WAIT;
        case TCP_STATE_ESTABLISHED:
            // 发送fin通知自己要关闭发送。但要注意，这里并不一定立即发送FIN 进入 FIN_WAIT_1 状态
            tcp_send_fin(tcp);
            tcp_set_state(tcp, TCP_STATE_FIN_WAIT_1);
            return NET_ERR_NEED_WAIT;
        default:
            // 这些状态下已经处于主动关闭或已经完毕
            dbg_error(DBG_TCP, "tcp state error[%s]: send is not allowed", tcp_state_name(tcp->state));
            return NET_ERR_STATE;
    }
}

/**
 * @brief 强制删除tcp
 */
void tcp_destory (struct _sock_t * sock) {
    tcp_t * tcp = (tcp_t *)sock;

    // TIME-WAIT状态下，由定时器自动销毁
    if (tcp->state != TCP_STATE_TIME_WAIT) {
        tcp_free((tcp_t *)sock);
    }
}

/**
 * @brief 执行发送请求
 * 发送请求只在部分状态下有效，即对方未主动关闭的情况下
 */
net_err_t tcp_send (struct _sock_t* sock, const void* buf, size_t len, int flags, ssize_t * result_len) {
    tcp_t* tcp = (tcp_t*)sock;

    switch (tcp->state) {
        case TCP_STATE_CLOSED:
            dbg_error(DBG_TCP, "tcp closed: send is not allowed");
            return NET_ERR_CLOSE;
     //主动关闭方已经发送 FIN，等待对方确认 ACK
        case TCP_STATE_FIN_WAIT_1:
        //FIN 已被对方确认，自己仍然可以接收数据。
        case TCP_STATE_FIN_WAIT_2:
        case TCP_STATE_CLOSING:
        case TCP_STATE_TIME_WAIT:
        //自己收到对方 FIN，发送了最后一个 FIN，等待 ACK
        case TCP_STATE_LAST_ACK:
            // 以上状态，自己关闭了发送，因此不允许再发送
            dbg_error(DBG_TCP, "tcp closed[%s]: send is not allowed", tcp_state_name(tcp->state));
            return NET_ERR_CLOSE;
        case TCP_STATE_ESTABLISHED:
        case TCP_STATE_CLOSE_WAIT: {
            // 只有这两个状态允许使用send接口发送
            // CLOSE-WAIT下是对方关闭了发送，但我们可以发数据过去让对方接收
            break;
        }
        case TCP_STATE_LISTEN:
        case TCP_STATE_SYN_RECVD:
        case TCP_STATE_SYN_SENT:
        default:
            // 监听状态不允许发数据，连接状态未完全建立时也不允许发数据
            // 这种策略虽不符合RFC793，但影响的是只是自己上层的应用程序
            dbg_error(DBG_TCP, "tcp state error[%s]: send is not allowed", tcp_state_name(tcp->state));
            return NET_ERR_STATE;
    }

    // 将数据写入发送缓存中
    ssize_t size = tcp_write_sndbuf(tcp, (uint8_t *)buf, (int)len);
    if (size <= 0) {
        // 缓存可能已满，返回写入0. 上层应用应当等待
        *result_len = 0;
        return NET_ERR_NEED_WAIT;
    } else {
        *result_len = size;

        // 通知有发送数据事件发送，并进行处理
        tcp_out_event(tcp, TCP_OEVENT_SEND);
        return NET_ERR_OK;
    }
}

/**
 * @brief 执行读请求
 * //处理应用层读取 TCP 数据的请求。
根据当前 TCP 状态判断是否允许读取。
从 TCP 接收缓冲区返回数据，如果没有数据，则决定是否等待。
 */
net_err_t tcp_recv (struct _sock_t* s, void* buf, size_t len, int flags, ssize_t * result_len) {
    tcp_t* tcp = (tcp_t*)s;

    int need_wait = NET_ERR_NEED_WAIT;
    switch (tcp->state) {
        case TCP_STATE_LAST_ACK:  // 对方已经关了，自己主动关了
            // 已经完全关闭、自己关闭了发送，不允许再读取
            dbg_error(DBG_TCP, "tcp state error[%s]: recv is closed");
            return NET_ERR_CLOSE;
        case TCP_STATE_CLOSE_WAIT:    // 虽然收到了对方的FIN，但缓存可能仍有数据可读
        case TCP_STATE_CLOSING: {
            // 如果没有数据直接返回CLOSE, 不需要等待和进行后续的处理
            if (tcp_buf_cnt(&tcp->rcv.buf) == 0) {
                return NET_ERR_CLOSE;
            }
            need_wait = 0;
            break;
        }
        case TCP_STATE_ESTABLISHED:   // 正常连接时可允许通信
        case TCP_STATE_FIN_WAIT_1:    // 主动发起关闭发送
        case TCP_STATE_FIN_WAIT_2:    // 主动关闭送已经完成
            // 这些状态是允许接收数据的
            break;
        case TCP_STATE_CLOSED:
            // 关闭状态不允许读取
            dbg_error(DBG_TCP, "tcp closed: recv is not allowed");
            return NET_ERR_CLOSE;
        case TCP_STATE_LISTEN:
        case TCP_STATE_SYN_RECVD:
        case TCP_STATE_SYN_SENT:
        case TCP_STATE_TIME_WAIT:  // 2MS状态
        default:
            // 监听状态不允许发数据，连接状态未完全建立时也不允许发数据
            // 这种策略虽不符合RFC793，但影响的是只是自己上层的应用程序
            dbg_error(DBG_TCP, "tcp state error[%s]: recv is not allowed", tcp_state_name(tcp->state));
            return NET_ERR_STATE;
    }

    // 检查缓存中是否有数据，如果有返回给用户；如果没有，则等待
    *result_len = 0;
    int cnt = tcp_buf_read_rcv(&tcp->rcv.buf, buf, (int)len);
    if (cnt > 0) {
        *result_len = cnt;
        return NET_ERR_OK;
    }

    // 缓存中没有数据，告知用户需要等待
    return need_wait;
}

/**
 * @brief 创建一个TCP sock结构
 */
sock_t* tcp_create (int family, int protocol) {
    // 分配一个TCP块
    tcp_t* tcp = tcp_alloc(1, family, protocol);
    if (!tcp) {
        dbg_error(DBG_TCP, "alloc tcp failed.");
        return (sock_t *)0;
    }

    // 插入全局队列中, 注意此时端口号和IP地址全为0，因此不匹配任何不进行任何通信
    tcp_insert(tcp);
    return (sock_t *)tcp;
}

/**
 * @brief 设置TCP进入Listen状态
 *
 * 在此之后，TCP将接收输入的TCP连接并进行处理
 */
net_err_t tcp_listen (struct _sock_t* s, int backlog) {
    tcp_t * tcp = (tcp_t *)s;

    // 必要的参数检查
    if (backlog <= 0) {
        dbg_error(DBG_TCP, "backlog(%d) <= 0", backlog);
        return NET_ERR_PARAM;
    }

    // 只有处于close状态的才能建立连接,其它状态不可以
    if (tcp->state != TCP_STATE_CLOSED) {
        dbg_error(DBG_TCP, "tcp is not closed. listen is not allowed");
        return NET_ERR_STATE;
    }

    // 简单设置一下，不影响以前已经连接量。由于原初始值为0，所以不能接收连接。一旦这里设置后，即可允许连接
    tcp->state = TCP_STATE_LISTEN;
    tcp->conn.backlog = backlog;
    return NET_ERR_OK;
}

/**
 * @brief 获取一个TCP连接
 * 如何表示一个TCP在s的队列里，再建立一个链表吗?
 * 用于服务器端从监听 socket 获取已经建立的子连接。
返回一个新的 TCP 控制块 (child TCP) 给应用层使用
核心逻辑
1 遍历全局 TCP 列表：
跳过自身和不属于该监听 socket 的子连接。
找到属于该监听 socket 的 inactive 子连接。
2 填充客户端地址：
设置 addr 的 IP 和端口信息。
标记子连接为 active (inactive = 0)。
3 返回：
*client 指向子 TCP 控制块。
如果没有合适的子连接，返回 NET_ERR_NEED_WAIT（表示应用应阻塞等待）。
 */
net_err_t tcp_accept (struct _sock_t *s, struct x_sockaddr* addr, x_socklen_t* len, struct _sock_t ** client) {
    nlist_node_t * node;

    nlist_for_each(node, &tcp_list) {
        sock_t * sock = nlist_entry(node, sock_t, node);
        tcp_t * tcp = (tcp_t *)sock;

        // 跳过自己和不属于自己的
        if ((sock == s) || (tcp->parent != (tcp_t *)s)) {
            continue;
        }

        // 属于自己的子child，且处于非激活状态
        //只有 inactive 为 1 的子连接，才会被返回给应用层
        if (tcp->flags.inactive) {
            struct x_sockaddr_in * addr_in = (struct x_sockaddr_in *)addr;
            //plat_memset 清零，初始化所有字段，避免残留数据
            plat_memset(addr_in, 0, sizeof(struct x_sockaddr_in));
            addr_in->sin_family = AF_INET;
            //设置子连接的 远端端口号（对方客户端端口）
            addr_in->sin_port = x_htons(tcp->base.remote_port);
            //将子连接的 远端 IP 地址 写入 sin_addr
            ipaddr_to_buf(&tcp->base.remote_ip, (uint8_t *)&addr_in->sin_addr.s_addr);
            if (len) {
                *len = sizeof(struct x_sockaddr_in);
            }

            tcp->flags.inactive = 0;       // 清除非活动标志

            // 返回给调用者
            *client = (sock_t *)tcp;
            return NET_ERR_OK;
        }

    }
    return NET_ERR_NEED_WAIT;
}


/**
 * @brief 获取一个TCP连接
 * 如何表示一个TCP在s的队列里，再建立一个链表吗?
 */
int tcp_backlog_count (tcp_t * tcp) {
    int count = 0;
    nlist_node_t * node;

    nlist_for_each(node, &tcp_list) {
        sock_t * sock = nlist_entry(node, sock_t, node);
        tcp_t * child = (tcp_t *)sock;

        // 跳过自己和不属于自己的
        if ((child->parent == tcp) && (child->flags.inactive)) {
            count++;
        }
    }
    return count;
}


/**
 * TCP模块初始化
 */
net_err_t tcp_init(void) {
    dbg_info(DBG_TCP, "tcp init.");

    mblock_init(&tcp_mblock, tcp_tbl, sizeof(tcp_t), TCP_MAX_NR, NLOCKER_NONE);
    nlist_init(&tcp_list);

    dbg_info(DBG_TCP, "init done.");
    return NET_ERR_OK;
}

/**
 * @brief 用于 监听 socket 接收到 SYN 时创建一个新的子 TCP 控制块。
模拟 BSD socket 中 accept() 的子连接管理机制
 * 注意，生成的TCP已经处理连接状态，因此相关的状态值应当设置好
 */
tcp_t * tcp_create_child (tcp_t * parent, tcp_seg_t * seg) {
    // 创建一个新的子TCP，只从父中拷贝少量相关信息
    tcp_t * child = (tcp_t *)tcp_alloc(0, parent->base.family, parent->base.protocol);
    if (!child) {
        dbg_error(DBG_TCP, "no child tcp");
        return (tcp_t *)0;
    }

    // 必要的复制
    ipaddr_copy(&child->base.local_ip, &seg->local_ip);
    ipaddr_copy(&child->base.remote_ip, &seg->remote_ip);
    child->base.local_port = seg->hdr->dport;
    child->base.remote_port = seg->hdr->sport;
    child->parent = parent;
    //irs_valid = 1 → 初始序号有效。  inactive = 1 → 子连接还未被应用 accept() 获取。
    child->flags.irs_valid = 1;                 // 初始已经有效了
    child->flags.inactive = 1;                  // 未被aceept接收，不可用
    child->conn.backlog = 0;
                                                 //MSS = MTU - IP头大小 - TCP头大小
    tcp_init_connect(child);                    // 初始连接，计算mss等    MSS 是 TCP 连接中 一次能发送的最大 TCP 数据量（Payload，不包括 TCP/IP 头）
    child->rcv.iss = seg->seq;
    child->rcv.nxt = child->rcv.iss + 1;        // 跳过SYN 

    tcp_read_options(child, seg->hdr);          // 读取选项

    // 别忘了队列中
    tcp_insert(child);
    return child;
}