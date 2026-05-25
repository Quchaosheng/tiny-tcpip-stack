#include "net.h"
#include "net_plat.h"
#include "exmsg.h"
#include "pktbuf.h"
#include "dbg.h"
#include "netif.h"
#include "loop.h"
#include "ether.h"
#include "tools.h"
#include "timer.h"
#include "arp.h"
#include "ipv4.h"
#include "icmpv4.h"
#include "sock.h"
#include "raw.h"
#include "udp.h"
#include "dns.h"
#include "tcp.h"

/**
 * 协议栈初始化
 */
net_err_t net_init(void) {
    dbg_info(DBG_INIT, "init net...");

    // 各模块初始化
    net_plat_init();

    
    //整个协议栈的初始化顺序
    // 放在前头，提前进行大小端转换，后面初始化的时候可能发数据包
    //大小端转换 工具函数
    tools_init();
    //事件驱动 + 消息队列
    exmsg_init();
    //数据包缓冲池
    pktbuf_init();
    //网卡接口管理
    netif_init();
    //初始化Ethernet协议 网卡收上来的第一层就是以太网
    ether_init();
    //定时器
    net_timer_init();
    //IP地址 → MAC地址        MAC网卡的物理地址 数据链路层
    arp_init();
    //IP层初始化 负责：IP包处理 路由 分片
    ipv4_init();
    //ping
    icmpv4_init();
    //应用层接口
    socket_init();
    //允允许程序直接操作 IP 层的数据包，而不是通过 TCP / UDP
    raw_init();
    //初始化 UDP 协议。
    udp_init();
    //域名解析
    dns_init();
    //连接  重传 窗口 拥塞控制
    tcp_init();

    // 环回接口作用：① 测试网络协议栈② 本机程序之间通信③ 网络栈必须有的接口
    //数据包不会真的发到网卡，而是在本机内部绕一圈返回
    loop_init();
    return NET_ERR_OK;
}

net_err_t net_start(void) {
    // 启动消息传递机制
    exmsg_start();

    dbg_info(DBG_INIT, "net is running.");
    return NET_ERR_OK;
}







/*初始化顺序：必须符合模块依赖关系
基础设施
↓
数据包系统
↓
网卡
↓
链路层
↓
网络层
↓
传输层
↓
应用接口



net_plat_init()   平台
tools_init()      工具
exmsg_init()      消息系统
pktbuf_init()     数据包
netif_init()      网卡接口
ether_init()      以太网
timer_init()      定时器
arp_init()        ARP
ipv4_init()       IP
icmp_init()       ICMP
socket_init()     socket
raw_init()        raw socket
udp_init()        UDP
dns_init()        DNS
tcp_init()        TCP
loop_init()       loopback

*/