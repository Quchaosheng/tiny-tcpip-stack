/**
 * 该接口层代码负责将所有的网络接口统一抽像为netif结构，并提供统一的接口进行处理
 */
#include <string.h>
#include <stdlib.h>
#include "netif.h"
#include "net.h"
#include "dbg.h"
#include "fixq.h"
#include "exmsg.h"
#include "mblock.h"
#include "pktbuf.h"
#include "ether.h"
#include "protocol.h"

static netif_t netif_buffer[NETIF_DEV_CNT];     // 网络接口的数量
static mblock_t netif_mblock;                   // 接口分配结构
static nlist_t netif_list;               // 网络接口列表
static netif_t * netif_default;          // 缺省的网络列表
static const link_layer_t* link_layers[NETIF_TYPE_SIZE];      // 链接层驱动表

/**
 * @brief 显示系统中的网卡列表信息
 */
#if DBG_DISP_ENABLED(DBG_NETIF)
void display_netif_list (void) {
    nlist_node_t * node;

    plat_printf("netif list:\n");
    nlist_for_each(node, &netif_list) {
        //链表节点反推出结构体地址 根据 node 地址减去 node 在结构体里的位置得到 netif
        netif_t * netif = nlist_entry(node, netif_t, node);
        plat_printf("%s:", netif->name);
        //打印网卡状态
        switch (netif->state) {
            case NETIF_CLOSED:
                plat_printf(" %s ", "closed");
                break;
            case NETIF_OPENED:
                plat_printf(" %s ", "opened");
                break;
            case NETIF_ACTIVE:
                plat_printf(" %s ", "active");
                break;
            default:
                break;
        }
        //switch (netif->type)打印网卡类型
        /*
        | 类型               | 含义   |
        | ---------------- | ---- |
        | NETIF_TYPE_ETHER | 以太网  |
        | NETIF_TYPE_LOOP  | 回环接口 |
        */
        switch (netif->type) {
            case NETIF_TYPE_ETHER:
                plat_printf(" %s ", "ether");
                break;
            case NETIF_TYPE_LOOP:
                plat_printf(" %s ", "loop");
                break;
            default:
                break;
        }
        //MTU = 最大传输单元
        plat_printf(" mtu=%d ", netif->mtu);
        plat_printf("\n");
        dump_mac("\tmac:", netif->hwaddr.addr);
        dump_ip_buf(" ip:", netif->ipaddr.a_addr);
        dump_ip_buf(" netmask:", netif->netmask.a_addr);
        dump_ip_buf(" gateway:", netif->gateway.a_addr);

        // 队列中包数量的显示
        plat_printf("\n");
    }
}
#else
#define display_netif_list()
#endif // DBG_NETIF

/**
 * @brief 网络接口层初始化
 */
net_err_t netif_init(void) {
    dbg_info(DBG_NETIF, "init netif");

    // 建立接口列表
    nlist_init(&netif_list);
    mblock_init(&netif_mblock, netif_buffer, sizeof(netif_t), NETIF_DEV_CNT, NLOCKER_NONE);

    // 设置缺省接口
    netif_default = (netif_t *)0;

    // 清除链路层类型表
    plat_memset((void *)link_layers, 0, sizeof(link_layers));
    
    dbg_info(DBG_NETIF, "init done.\n");
    return NET_ERR_OK;
}

/**
 * @brief 注册链表层处理类型
 */
net_err_t netif_register_layer(int type, const link_layer_t* layer) {
    // 类型错误
    if ((type < 0) || (type >= NETIF_TYPE_SIZE)) {
        dbg_error(DBG_NETIF, "type error: %d", type);
        return NET_ERR_PARAM;
    }

    // 已经存在
    if (link_layers[type]) {
        dbg_error(DBG_NETIF, "link layer: %d exist", type);
        return NET_ERR_EXIST;
    }
//把链路层注册进协议栈
//在协议栈里建立一个网卡类型 → 链路层驱动 的映射表。 以后只要根据 type 查表，就能找到对应的链路层。
    link_layers[type] = layer;
    return NET_ERR_OK;
}

/**
 * @brief 获取链路层协议处理模块
 */
static const link_layer_t * netif_get_layer(int type) {
    if ((type < 0) || (type >= NETIF_TYPE_SIZE)) {
        return (const link_layer_t*)0;
    }

    return link_layers[type];
}
/* 如何打开网口：
netif_open
分配 netif 结构
初始化字段
初始化收发队列
调用驱动 open()
检查驱动是否设置正确
获取链路层
加入 netif_list
*/

/*参数含义：
| 参数       | 含义               |
| -------- | ---------------- |
| dev_name | 网卡名字，例如 `"eth0"` |
| ops      | 驱动函数表            |
| ops_data | 驱动私有数据           |
*/
netif_t* netif_open(const char* dev_name, const netif_ops_t* ops, void * ops_data) {
    // 分配一个网络接口 从内存池里分配一个 netif 结构
    netif_t*  netif = (netif_t *)mblock_alloc(&netif_mblock, -1);
    if (!netif) {
        dbg_error(DBG_NETIF, "no netif");
        return (netif_t*)0;
    }

    // 设置各种缺省值, 这些值有些将被驱动处理，有些将被上层netif_xxx其它函数设置
    //IP地址 = 0.0.0.0 掩码   = 0.0.0.0    网关   = 0.0.0.0   
    ipaddr_set_any(&netif->ipaddr);
    ipaddr_set_any(&netif->netmask);
    ipaddr_set_any(&netif->gateway);
    netif->mtu = 0;                      // 默认为0，即不限制 通常驱动会设置1500
    //网卡类型未知 驱动初始化时会改成NETIF_TYPE_ETHER  or  NETIF_TYPE_LOOP
    netif->type = NETIF_TYPE_NONE;
    nlist_node_init(&netif->node);

    plat_strncpy(netif->name, dev_name, NETIF_NAME_SIZE);
    //防止字符串越界
    netif->name[NETIF_NAME_SIZE - 1] = '\0';
    netif->ops = ops;                   // 设置驱动和私有参数
    netif->ops_data = (void *)ops_data;

    // 初始化接收队列
    //数据流：网卡 → in_q → 协议栈  当驱动收到数据包时就会把数据放入in_q
    net_err_t err = fixq_init(&netif->in_q, netif->in_q_buf, NETIF_INQ_SIZE, NLOCKER_THREAD);
    if (err < 0) {
        dbg_error(DBG_NETIF, "netif in_q init error, err: %d", err);
        return (netif_t *)0;
    }

    // 初始化发送队列
    //数据流：协议栈 → out_q → 网卡
    err = fixq_init(&netif->out_q, netif->out_q_buf, NETIF_OUTQ_SIZE, NLOCKER_THREAD);
    if (err < 0) {
        dbg_error(DBG_NETIF, "netif out_q init error, err: %d", err);
        fixq_destroy(&netif->in_q);
        return (netif_t *)0;
    }

    // 打开设备，对硬件做进一步的设置, 在其内部可对netif字段进行设备
    // 特别是要对type和link_layer做设备
    err = ops->open(netif, ops_data);
    if (err < 0) {
        dbg_error(DBG_NETIF, "netif ops open error: %d");
        goto free_return;
    }
    netif->state = NETIF_OPENED;        // 切换为opened

    // 驱动初始化完成后，对netif进行进一步检查
    // 做一些必要性的检查，以免驱动没写好
    if (netif->type == NETIF_TYPE_NONE) {
        dbg_error(DBG_NETIF, "netif type unknown");
        goto free_return;
    }

    // 获取驱动层接口
    netif->link_layer = netif_get_layer(netif->type);
    //如果不是 loopback且找不到链路层  说明协议栈没有注册驱动
    if (!netif->link_layer && (netif->type != NETIF_TYPE_LOOP)) {
        dbg_error(DBG_NETIF, "no link layer. netif name: %s", dev_name);
        goto free_return;
    }

    // 插入队列中
    nlist_insert_last(&netif_list, &netif->node);
    display_netif_list();
    return netif;

free_return:
    if (netif->state == NETIF_OPENED) {
        netif->ops->close(netif);
    }

    fixq_destroy(&netif->in_q);
    fixq_destroy(&netif->out_q);
    mblock_free(&netif_mblock, netif);
    return (netif_t*)0;
}

/**
 * @brief 设置IP地址、掩码、网关等
 * 这里只是简单的设置接口的各个地址，进行写入
 */
//如果参数存在 → 使用参数 如果参数为 NULL → 使用 0.0.0.0
net_err_t netif_set_addr(netif_t* netif, ipaddr_t* ip, ipaddr_t* netmask, ipaddr_t* gateway) {
    ipaddr_copy(&netif->ipaddr, ip ? ip : ipaddr_get_any());
    ipaddr_copy(&netif->netmask, netmask ? netmask : ipaddr_get_any());
    ipaddr_copy(&netif->gateway, gateway ? gateway : ipaddr_get_any());
    return NET_ERR_OK;
}

/**
 * @brief 设置硬件地址 把 MAC 地址复制到 netif 结构体里
 */
net_err_t netif_set_hwaddr(netif_t* netif, const uint8_t* hwaddr, int len) { 
    plat_memcpy(netif->hwaddr.addr, hwaddr, len);
    netif->hwaddr.len = len;
    return NET_ERR_OK;
}

/**
 * @brief 激活网络设备
 */
net_err_t netif_set_active(netif_t* netif) {
    // 必须为打开状态地能激活      避免：未初始化就启动
    if (netif->state != NETIF_OPENED) {
        dbg_error(DBG_NETIF, "netif is not opened");
        return NET_ERR_STATE;
    }

    // 如果有底层链路层，则调用。否则不处理
    if (netif->link_layer) {
        // 打开失败，失败则退出
        net_err_t err = netif->link_layer->open(netif);
        if (err < 0) {
            dbg_info(DBG_NETIF, "active error.");
            return err;
        }
    }

//一条负责：本机通信 一条负责：局域网通信    路由查找原则是：最长前缀匹配
//如果只用一条：协议栈无法区分这是给本机的包还是要转发的包
    // 添加路由表，不处理广播的情况(子网广播和本地广播)
    // 同一网段的路由
    ipaddr_t ip = ipaddr_get_net(&netif->ipaddr, &netif->netmask);
    rt_add(&ip, &netif->netmask, ipaddr_get_any(), netif);

    // 目标地址为本接口   如果数据包的目标IP是我自己的IP 就交给本机处理
    ipaddr_set_all_1(&ip);
    rt_add(&netif->ipaddr, &ip, ipaddr_get_any(), netif);

    // 看看是否要添加缺省接口
    // 缺省网络接口用于外网数据收发时的包处理
    if (!netif_default && (netif->type != NETIF_TYPE_LOOP)) {
        netif_set_default(netif);
    }

    // 切换为就绪状态
    netif->state = NETIF_ACTIVE;
    display_netif_list();
    return NET_ERR_OK;
}

/**
 * @brief 取消设备的激活态
 */
//关闭网卡通信  但不销毁网卡对象。
net_err_t netif_set_deactive(netif_t* netif) {
    // 必须已经激活的状态
    if (netif->state != NETIF_ACTIVE) {
        dbg_error(DBG_NETIF, "netif is not actived");
        return NET_ERR_STATE;
    }

    // 底层链路的处理
    if (netif->link_layer) {
        netif->link_layer->close(netif);
    }

    // 释放掉队列中的所有数据包
    //网卡关闭 包不应该再存在   否则会：内存泄漏
    pktbuf_t* buf;
    while ((buf = fixq_recv(&netif->in_q, -1))) {
        pktbuf_free(buf);
    }
    while ((buf = fixq_recv(&netif->out_q, -1))) {
        pktbuf_free(buf);
    }

    // 移除各项路由表，不处理广播的情况(子网广播和本地广播)
    // 同一网段的路由
    ipaddr_t ip = ipaddr_get_net(&netif->ipaddr, &netif->netmask);
    rt_remove(&ip, &netif->netmask);

    // 目标地址为本接口
    ipaddr_set_all_1(&ip);
    rt_remove(&netif->ipaddr, &netif->netmask);

    // 重设缺省网口
    if (netif_default == netif) {
        netif_default = (netif_t*)0;
        rt_remove(ipaddr_get_any(), ipaddr_get_any());
    }

    // 切换回打开（非激活状态）
    netif->state = NETIF_OPENED;
    display_netif_list();
    return NET_ERR_OK;
}

/**
 * @brief 关闭网络接口 
检查状态
关闭驱动
释放netif对象

 */
net_err_t netif_close(netif_t* netif) {
    // 需要先取消active状态才能关闭
    if (netif->state == NETIF_ACTIVE) {
        dbg_error(DBG_NETIF, "netif(%s) is active, close failed.", netif->name);
        return NET_ERR_STATE;
    }

    // 先关闭设备
    netif->ops->close(netif);
    netif->state = NETIF_CLOSED;

    // 最后释放netif结构
    nlist_remove(&netif_list, &netif->node);
    mblock_free(&netif_mblock, netif);
    display_netif_list();
    return NET_ERR_OK;
}

/**
 * @brief 设置缺省的网络接口
 * @param netif 缺省的网络接口
 * 设置默认网卡如果路由表找不到目标网络就从默认网卡发送
 * 如果之前已经有默认网卡先删除旧的默认路由 添加新的默认路由0.0.0.0/0 → gateway → netif
 */
void netif_set_default(netif_t* netif) {
    // 添加新缺省路由, 仅当网关有效时
    if (!ipaddr_is_any(&netif->gateway)) {
        // 如果已经设置了缺省的，移除缺省路由
        if (netif_default) {
            rt_remove(ipaddr_get_any(), ipaddr_get_any());
        }

        // 再添加新的路由
        rt_add(ipaddr_get_any(), ipaddr_get_any(), &netif->gateway, netif);
    }

    // 纪录新的网卡
    netif_default = netif;
}

/**
 * @brief 获取缺省网卡
 * 如果没有指定网卡，就会用默认网卡
 */
netif_t * netif_get_default (void) {
    return netif_default;
}


//netif 的 线程模型核心
/* 网卡驱动   协议栈线程   通常在 不同线程 / 中断环境
如果直接处理数据：会有并发问题   阻塞问题   中断问题
驱动 → in_q → 协议栈
协议栈 → out_q → 驱动
*/
/**
 * @brief 将buf加入到网络接口的输入队列中
 */
net_err_t netif_put_in(netif_t* netif, pktbuf_t* buf, int tmo) {
    // 写入接收队列
    net_err_t err = fixq_send(&netif->in_q, buf, tmo);
    if (err < 0) {
        //之前队列为空，协议栈线程可能在睡眠
        dbg_warning(DBG_NETIF, "netif %s in_q full", netif->name);
        return NET_ERR_FULL;
    }

    // 当输入队列中只有刚写入的这个包时，发消息通知工作线程去处理
    // 可能的情况：
    // 1. 数量为1，只有刚写入的包，发消息通知
    // 2. 数量为0，前面刚写入，正好立即被工作线程处理掉，无需发消息
    // 3. 数量超过1，即有累积的包，工作线程正在处理，无需发消息
    if (fixq_count(&netif->in_q) == 1) {
        exmsg_netif_in(netif);
    }
    return NET_ERR_OK;
}

/**
 * @brief 将Buf添加到网络接口的输出队列中
 */
net_err_t netif_put_out(netif_t* netif, pktbuf_t* buf, int tmo) {
    // 写入发送队列
    net_err_t err = fixq_send(&netif->out_q, buf, tmo);
    if (err < 0) {
        dbg_info(DBG_NETIF, "netif %s out_q full", netif->name);
        return err;
    }

    // 只是写入队列，具体的发送会调用ops->xmit来启动发送
    return NET_ERR_OK;
}

/**
 * @brief 从输入队列中取出一个数据包
 */
pktbuf_t* netif_get_in(netif_t* netif, int tmo) {
    // 从接收队列中取数据包
    pktbuf_t* buf = fixq_recv(&netif->in_q, tmo);
    if (buf) {
        // 重新定位，方便进行读写
        pktbuf_reset_acc(buf);
        return buf;
    }

    dbg_info(DBG_NETIF, "netif %s in_q empty", netif->name);
    return (pktbuf_t*)0;
}

/**
 * 从输出队列中取出一个数据包
 */
 pktbuf_t* netif_get_out(netif_t* netif, int tmo) {
    // 从发送队列中取数据包，不需要等待。可能会被中断处理程序中调用
    // 因此，不能因为没有包而挂起程序
    pktbuf_t* buf = fixq_recv(&netif->out_q, tmo);
    if (buf) {
        // 重新定位，方便进行读写
        pktbuf_reset_acc(buf);
        return buf;
    }

    dbg_info(DBG_NETIF, "netif %s out_q empty", netif->name);
    return (pktbuf_t*)0;
}

/**
 * @brief 发送一个网络包到网络接口上, 目标地址为ipaddr
 * 在发送前，先判断驱动是否正在发送，如果是则将其插入到发送队列，等驱动有空后，由驱动自行取出发送。
 * 否则，加入发送队列后，启动驱动发送
 */
net_err_t netif_out(netif_t* netif, ipaddr_t * ipaddr, pktbuf_t* buf) {
    // 发往外部，根据不同的接口类型作不同处理
    if (netif->link_layer) {
        net_err_t err = netif->link_layer->out(netif, ipaddr, buf);
        if (err < 0) {
            dbg_warning(DBG_NETIF, "netif link out error: %d", err);
            return err;
        }
        return NET_ERR_OK;
    } else {
        // 缺省情况，将数据包插入就绪队列，然后通知驱动程序开始发送
        // 硬件当前发送如果未进行，则启动发送，否则不处理，等待硬件中断自动触发进行发送
        net_err_t err = netif_put_out(netif, buf, -1);
        if (err < 0) {
            dbg_info(DBG_NETIF, "send to netif queue failed. err: %d", err);
            return err;
        }

        // 启动发送
        return netif->ops->xmit(netif);
    }
}



/*netif.c 的核心功能
| 功能    | 函数                            |
| ----- | ----------------------------- |
| 初始化   | `netif_init`                  |
| 注册链路层 | `netif_register_layer`        |
| 打开网卡  | `netif_open`                  |
| 激活网卡  | `netif_set_active`            |
| 发送数据  | `netif_out`                   |
| 收发队列  | `netif_put_in / netif_get_in` |

netif_open() 做的事情可以总结为：
1 分配 netif 结构
2 初始化默认值
3 保存驱动接口
4 创建收发队列
5 调用驱动初始化
6 获取链路层
7 加入网卡列表
最终协议栈成功创建一个网卡






整个数据流：
网卡硬件
 ↓
驱动
 ↓
netif_put_in
 ↓
in_q
 ↓
协议栈线程
 ↓
ethernet
 ↓
IP
 ↓
TCP/UDP

发送路径：
TCP/UDP
 ↓
IP
 ↓
netif_out
 ↓
link_layer
 ↓
驱动
 ↓
网卡

*/