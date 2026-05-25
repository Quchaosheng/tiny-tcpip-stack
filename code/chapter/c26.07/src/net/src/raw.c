/**
 * @brief 原始套接字
 * 给应用层使用的IP控制块, 用于收发IP层的数据报，可以实现例如ping等功能
 */
#include "raw.h"
#include "mblock.h"
#include "dbg.h"
#include "sock.h"
#include "socket.h"
#include "ipv4.h"

static raw_t raw_tbl[RAW_MAX_NR];           // raw控制块数组
static mblock_t raw_mblock;                 // 空闲raw控制块链表
static nlist_t raw_list;                     // 已绑定的控制块链表

#if DBG_DISP_ENABLED(DBG_RAW)
static void display_raw_list (void) {
    plat_printf("\n--- raw list\n --- ");

    int idx = 0;
    nlist_node_t * node;

    nlist_for_each(node, &raw_list) {
        raw_t * raw = (raw_t *)nlist_entry(node, sock_t, node);
        plat_printf("[%d]\n", idx++);
        dump_ip_buf("\tlocal:", (const uint8_t *)&raw->base.local_ip.a_addr);
        dump_ip_buf("\tremote:", (const uint8_t *)&raw->base.remote_ip.a_addr);
    }
}
#else
#define display_raw_list()
#endif

/**
 * @brief 
 * 绑定地址：将原始套接字绑定到一个本地地址（如 IP 地址和端口）。实际上，它是调用了 sock_bind 函数来实现绑定操作。
显示绑定的套接字列表：通过 display_raw_list() 函数输出当前所有已绑定的原始套接字信息。
 */
net_err_t raw_bind(sock_t* sock, const struct x_sockaddr* addr, x_socklen_t len) {
    net_err_t err = sock_bind(sock, addr, len);
    display_raw_list();
    return err;
}

/**
 * @breif 连接到远程主机
 */
net_err_t raw_connect(sock_t* sock, const struct x_sockaddr* addr, x_socklen_t len) {
    net_err_t err = sock_connect(sock, addr, len);
    display_raw_list();
    return err;
}

/**
 * @brief 
 * 发送数据包：将应用程序的数据发送到指定的远程 IP 地址。
    检查目标 IP：如果套接字已经连接并且目标 IP 地址不匹配，则返回错误。
    分配数据包：为要发送的数据分配内存空间。
    数据写入：将数据写入数据包缓冲区。
    发送数据：通过 ipv4_out 函数将数据包发送出去。
    返回发送结果：返回成功或失败的状态，并将发送的字节数赋给 result_len
 */
static net_err_t raw_sendto (struct _sock_t * sock, const void* buf, size_t len, int flags, const struct x_sockaddr* dest,
            x_socklen_t dest_len, ssize_t * result_len) {
    // 如果已经连接，则检查IP是否一致，不一致则报错
    ipaddr_t dest_ip;
    struct x_sockaddr_in* addr = (struct x_sockaddr_in*)dest;
    ipaddr_from_buf(&dest_ip, addr->sin_addr.addr_array);
    if (!ipaddr_is_any(&sock->remote_ip) && !ipaddr_is_equal(&dest_ip, &sock->remote_ip)) {
        dbg_error(DBG_RAW, "dest is incorrect");
        return NET_ERR_CONNECTED;
    }

    // 分配缓存空间
    pktbuf_t* pktbuf = pktbuf_alloc((int)len);
    if (!pktbuf) {
        dbg_error(DBG_RAW, "no buffer");
        return NET_ERR_MEM;
    }

    // 数据拷贝过去
    net_err_t err = pktbuf_write(pktbuf, (uint8_t *)buf, (int)len);
    if (sock->err < 0) {
        dbg_error(DBG_RAW, "copy data error");
        goto end_sendto;
    }

    // 通过IP层发送出去
    err = ipv4_out(sock->protocol, &dest_ip, &sock->local_ip, pktbuf);
    if (err < 0) {
        dbg_error(DBG_RAW, "send error");
        goto end_sendto;
    }

    *result_len = (ssize_t)len;
    return NET_ERR_OK;
end_sendto:
    pktbuf_free(pktbuf);
    return err;
}

/**
 * 接收数据：从原始套接字接收数据包并返回。
    从接收队列中移除数据包：使用 nlist_remove_first 从接收队列中取出第一个数据包。
    IP 地址拷贝：将接收到的数据包中的源 IP 地址提取到 src 中。
    数据读取：从数据包中读取数据到应用提供的缓冲区中，并返回读取的字节数。
 */
static net_err_t raw_recvfrom (struct _sock_t* sock, void* buf, size_t len, int flags,
            struct x_sockaddr* src, x_socklen_t * addr_len, ssize_t * result_len) {
    raw_t * raw = (raw_t *)sock;

    nlist_node_t * first = nlist_remove_first(&raw->recv_list);
    if (!first) {
        *result_len = 0;
        // 后续任务需要继续等待
        return NET_ERR_NEED_WAIT;
    }
//使用 nlist_entry 将链表节点转换为数据包指针，并通过 dbg_assert 确保 pktbuf 不为空。
//这是一个调试断言，确保从队列中移除的节点有效
    pktbuf_t* pktbuf = nlist_entry(first, pktbuf_t, node);
    dbg_assert(pktbuf != (pktbuf_t *)0, "pktbuf error");

    // 将IP地址从包中拷贝到src结构中
    ipv4_hdr_t* iphdr = (ipv4_hdr_t*)pktbuf_data(pktbuf);
    struct x_sockaddr_in* addr = (struct x_sockaddr_in*)src;
    plat_memset(addr, 0, sizeof(struct x_sockaddr));
    addr->sin_family = AF_INET;
    addr->sin_port = 0;
    plat_memcpy(&addr->sin_addr, iphdr->src_ip, IPV4_ADDR_SIZE);

    // 从包中读取数据
    //确保不会读取超过请求缓冲区 len 大小的数据。
    //如果接收到的数据包比预期的要大，最多只读取请求的字节数。这是为了避免缓冲区溢出。
    int size = (pktbuf->total_size > (int)len) ? (int)len : pktbuf->total_size;
    pktbuf_reset_acc(pktbuf);
    net_err_t err= pktbuf_read(pktbuf, buf, size);
    if (err < 0) {
        pktbuf_free(pktbuf);
        dbg_error(DBG_RAW, "pktbuf read error");
        return err;
    }

    pktbuf_free(pktbuf);

    *result_len = size;
    return NET_ERR_OK;
}

/**
 * @brief 关闭原始套接字：关闭一个已经存在的原始套接字连接。
移除套接字：将套接字从已绑定的列表 raw_list 中移除。
释放数据包：释放接收队列中的所有数据包。
释放套接字资源：通过 sock_uninit 和 mblock_free 释放套接字占用的资源。
显示更新的原始套接字列表：调用 display_raw_list() 输出当前的原始套接字信息。
 */
net_err_t raw_close(sock_t * sock) {
    raw_t * raw = (raw_t *)sock;

    // 从链表中移除
    nlist_remove(&raw_list, &sock->node);

    // 释放所有数据包
	nlist_node_t* node;
	while ((node = nlist_remove_first(&raw->recv_list))) {
		pktbuf_t* buf = nlist_entry(node, pktbuf_t, node);
		pktbuf_free(buf);
	}

    // sock关闭并释放掉
    sock_uninit(sock);
    mblock_free(&raw_mblock, sock);

    display_raw_list();
    return NET_ERR_OK;
}

/**
 * @brief 创建原始套接字操作结构
 */
sock_t* raw_create(int family, int protocol) {
     // raw特有的sock操作列表
    static const sock_ops_t raw_ops = {
         .sendto = raw_sendto,
         .recvfrom = raw_recvfrom,
        .setopt = sock_setopt,
        .close = raw_close,
        .connect = raw_connect,
        .bind = raw_bind,
        .send = sock_send,      // 使用基础sock默认提供的
        .recv = sock_recv,
    };

    // 分配一个raw sock结构
    raw_t* raw = mblock_alloc(&raw_mblock, -1);
    if (!raw) {
        dbg_error(DBG_RAW, "no raw sock");
        return (sock_t*)0;
    }

    // 初始化通用的sock结构部分
    net_err_t err = sock_init((sock_t*)raw, family, protocol, &raw_ops);
    if (err < 0) {
        dbg_error(DBG_RAW, "create raw failed.");
        mblock_free(&raw_mblock, raw);
        return (sock_t*)0;
    }
    nlist_init(&raw->recv_list);

    // 接收时需要等待
    raw->base.rcv_wait = &raw->rcv_wait;
    //sock_wait_init 初始化一个等待接收数据的信号量，用于实现线程同步
    if (sock_wait_init(raw->base.rcv_wait) < 0) {
        dbg_error(DBG_RAW, "create rcv.wait failed");
        goto create_failed;
    }

    // 插入全局队列中
    //将新创建的原始套接字插入到全局的 raw_list 中，表示当前有一个新的原始套接字在活动中，允许接收和发送数据
    nlist_insert_last(&raw_list, &raw->base.node);

    display_raw_list();
    return (sock_t *)raw;
create_failed:
    sock_uninit((sock_t *)raw);
    return (sock_t *)0;
}

/**
 * @brief 初始化内存池：使用 mblock_init 初始化内存块池 raw_mblock，为 raw_t 类型的套接字控制块分配内存。
初始化全局链表：使用 nlist_init 初始化全局链表 raw_list，用于存储已创建的原始套接字控制块
 */
net_err_t raw_init(void) {
    dbg_info(DBG_RAW, "raw init.");

    mblock_init(&raw_mblock, raw_tbl, sizeof(raw_t), RAW_MAX_NR, NLOCKER_NONE);
    nlist_init(&raw_list);

    dbg_info(DBG_RAW, "init done.");
    return NET_ERR_OK;
}

/**
 * @brief 查找匹配的raw控制块
 * 下面的算法比较简单，先找到哪个匹配即使用哪个，不会去查更全匹配的项
 * 协议匹配：首先检查原始套接字是否指定了协议。如果指定了协议，但数据包的协议与指定的协议不匹配，则跳过。
源 IP 和目标 IP 匹配：接下来，函数检查是否指定了本地和远程 IP 地址。如果指定了某个 IP 地址，则确保数据包中的 IP 地址与本地或远程 IP 匹配。若不匹配，则跳过当前原始套接字。
返回匹配的原始套接字：如果找到一个匹配的原始套接字，就返回该套接字。如果没有找到匹配的套接字，则返回 NULL
 */
static raw_t * raw_find (ipaddr_t * src, ipaddr_t * dest, int protocol) {
    nlist_node_t* node;
    raw_t * found = (raw_t *)0;

    nlist_for_each(node, &raw_list) {
        raw_t* raw = (raw_t *)nlist_entry(node, sock_t, node);

       
        // 指定了协议，但是协议与收到的不同，不匹配
        if (raw->base.protocol && (raw->base.protocol != protocol)) {
            continue;
        }

        // 指定了本地IP，但是收到的IP不是自己的这个，不匹配
        if (!ipaddr_is_any(&raw->base.local_ip) && !ipaddr_is_equal(&raw->base.local_ip, dest)) {
            continue;
        }

        // 指定了远端IP，但是收到的IP不是对方的，不匹配
        if (!ipaddr_is_any(&raw->base.remote_ip) && !ipaddr_is_equal(&raw->base.remote_ip, src)) {
            continue;
        }

        found = raw;
        break;
    }

    return found;
}

/**
 * @brief raw_in 函数用于处理接收到的原始数据包：
    从数据包中提取源 IP 和目标 IP：首先，函数从数据包的 IP 头中提取源 IP 和目标 IP 地址。
    查找匹配的原始套接字控制块：通过 raw_find 函数查找能够处理该数据包的原始套接字控制块。
如果没有找到匹配的套接字，函数会输出警告并返回 NET_ERR_UNREACH。
    数据包存储与通知：
如果找到匹配的原始套接字，且接收队列 recv_list 不满（RAW_MAX_RECV），则将接收到的数据包添加到接收队列中。
然后通过 sock_wakeup 通知相关的线程去读取数据包。sock_wakeup 会唤醒等待数据的线程，使得应用可以从套接字读取数据。
    处理数据包溢出：
如果接收队列已满，则丢弃当前数据包，释放资源并结束操作。
 */
net_err_t raw_in(pktbuf_t* pktbuf) {
    ipv4_hdr_t* iphdr = (ipv4_hdr_t*)pktbuf_data(pktbuf);
    net_err_t err = NET_ERR_UNREACH;

    ipaddr_t src, dest;
    ipaddr_from_buf(&dest, iphdr->dest_ip);
    ipaddr_from_buf(&src, iphdr->src_ip);

    // 找能处理的控制块
    raw_t * raw = raw_find(&src, &dest, iphdr->protocol);
    if (raw == (raw_t *)0) {
        dbg_warning(DBG_RAW, "no raw for this packet");
        return NET_ERR_UNREACH;
    }

    // 将数据包发送给raw，并通知应用程序去取，只发给一个应用
    if (nlist_count(&raw->recv_list) < RAW_MAX_RECV) {
        nlist_insert_last(&raw->recv_list, &pktbuf->node);

        // 信号量通知线程去取包
        sock_wakeup((sock_t *)raw, SOCK_WAIT_READ, NET_ERR_OK);
    } else {
        // 没有可处理的，释放掉
        pktbuf_free(pktbuf);
    }
    return NET_ERR_OK;
}
/*1内存管理与资源分配：
通过 mblock_alloc 分配原始套接字控制块，如果资源不足，则返回 NULL，确保不会在内存不足时造成程序崩溃。
原始套接字在关闭时，通过 mblock_free 释放内存。
2多线程同步与队列管理：
在接收数据包时，使用了 sock_wait_init 和 sock_wakeup 来实现 同步，确保当数据到达时，等待的线程能够被唤醒处理数据包。
使用链表（nlist）来管理 已创建的原始套接字 和 接收的数据包，确保数据包可以在适当的套接字中处理。
3原始套接字的状态管理：
函数通过查找匹配的原始套接字控制块来决定是否接收数据。通过匹配源 IP、目标 IP 和协议，确保数据包被正确处理。
原始套接字操作包括发送、接收、绑定和连接操作。它们通过 sock_ops_t 中定义的操作进行封装，这让原始套接字的操作更加简洁和统一。
4连接状态和数据包过滤：
raw_find 函数确保只有满足协议和 IP 地址匹配的原始套接字才能处理数据包。
这在多线程和多连接的情况下尤其重要，确保每个数据包都被正确地分配到合适的套接字进行处理。*/