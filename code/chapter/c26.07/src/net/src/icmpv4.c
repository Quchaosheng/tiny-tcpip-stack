#include <string.h>
#include "icmpv4.h"
#include "dbg.h"
#include "ipv4.h"
#include "protocol.h"
#include "tools.h"
#include "raw.h"

/**
 * @brief 显示icmp包
 */
#if DBG_DISP_ENABLED(DBG_ICMP)
static void display_icmp_packet(char * title, icmpv4_pkt_t  * pkt) {
    plat_printf("--------------- %s ------------------ \n", title);
    plat_printf("type: %d\n", pkt->hdr.type);
    plat_printf("code: %d\n", pkt->hdr.code);
    plat_printf("checksum: %x\n", x_ntohs(pkt->hdr.checksum));
    plat_printf("------------------------------------- \n");
}
#else
#define display_icmp_packet(title, packet)
#endif //debug_icmp

/**
 * @brief 发送icmp包
 */
//把已经构造好的 ICMP 报文补上校验和，然后交给 IPv4 发出去。
static net_err_t icmpv4_out(ipaddr_t* dest, ipaddr_t* src, pktbuf_t* buf) {
    icmpv4_pkt_t* pkt = (icmpv4_pkt_t*)pktbuf_data(buf);

    // 重新定位到icmp包头
    pktbuf_seek(buf, 0);
    //ICMP 的校验和覆盖的是：整个 ICMP 报文
    pkt->hdr.checksum = pktbuf_checksum16(buf, buf->total_size, 0, 1);

    // 然后再直接发回去
    display_icmp_packet("icmp reply", pkt);
    //ICMP 不是自己“直接上网” 它必须被封装进 IPv4 包里发出去 IPv4头 + ICMP报文
    return ipv4_out(NET_PROTOCOL_ICMPv4, dest, src, buf);
}

/**
 * @brief 发送icmp echo响应  把收到的 Echo Request 改成 Echo Reply，再发回去
 */
static net_err_t icmpv4_echo_reply(ipaddr_t *dest, ipaddr_t * src, pktbuf_t *buf) {
    icmpv4_pkt_t* pkt = (icmpv4_pkt_t*)pktbuf_data(buf);

    // 这里不用调整连续性，因为是直接修改了输入包，输入包是连续的  默认这个 buf 已经是连续可访问

    // 只修改类型和校验和，其余数据完全保持不变
    pkt->hdr.type = ICMPv4_ECHO_REPLY;
    pkt->hdr.checksum = 0;
    return icmpv4_out(dest, src, buf);
}

/**
 * @brief 发送不可达信息    ICMP 错误报文要把“导致错误的那个原始 IP 包的部分内容”带回去。
 * ICMP 差错消息 = 差错类型 + 原报文上下文
 */
//当某个 IPv4 包无法继续处理/转发/投递时，给对方发一个“不可达”ICMP消息 
/*
收到一个导致错误的原始IP包 ip_buf
    ↓
构造一个新的 ICMP 不可达报文
    ↓
把原始 IP 包的一部分拷进去，作为“出错依据”
    ↓
算好 ICMP 校验和
    ↓
通过 IPv4 发回给对方*/
net_err_t icmpv4_out_unreach(ipaddr_t* dest, ipaddr_t * src, uint8_t code, pktbuf_t * ip_buf) {
    // 根据RFC要求：原IP首部数据 + 64字节原IP数据包中数据区的内容
    // 不过在TCPIP详解卷一中其要求是尽可能多的IPv4数据包，总的IP长度不超过576字节
    int copy_size = ipv4_hdr_size((ipv4_pkt_t*)pktbuf_data(ip_buf)) + 576;
    if (copy_size > ip_buf->total_size) {
        copy_size = ip_buf->total_size;
    }

    // 分配一个新的数据包，预留一部分空间
    //ICMP 不可达报文除了通用头，还需要一个固定的附加区域，然后才是原始 IP 包片段
    //[ICMP头][附加4字节][原IP片段]
    pktbuf_t * new_buf = pktbuf_alloc(copy_size + sizeof(icmpv4_hdr_t) + 4);
    if (new_buf == (pktbuf_t*)0) {
        dbg_warning(DBG_ICMP, "alloc buf failed");
        return NET_ERR_NONE;
    }

    // 就目前的设计而言，肯定是连续的，不过还是要加上去
    net_err_t err  = pktbuf_set_cont(new_buf, sizeof(icmpv4_pkt_t));
    if (err < 0) {
        dbg_error(DBG_ICMP, "set cont faile.");
        return NET_ERR_SIZE;
    }

    // 生成icmp包头, 这边肯定是连续的
    icmpv4_pkt_t* pkt = (icmpv4_pkt_t*)pktbuf_data(new_buf);
    pkt->hdr.type = ICMPv4_UNREACH;
    pkt->hdr.code = code;
    pkt->hdr.checksum = 0;
    pkt->reverse = 0;

    // 从原ip数据包中拷由部分数据,填充校验和
    pktbuf_reset_acc(ip_buf);
    pktbuf_seek(new_buf, sizeof(icmpv4_hdr_t) + 4);     // 跳过头部开始写, 包含4字节无用的区域
    //没有这个，接收方只能知道“有错”，却不知道“哪个包错了
    err = pktbuf_copy(new_buf, ip_buf, copy_size);
    if (err < 0) {
        dbg_error(DBG_ICMP, "copy ip buf failed. err = %d", err);
        pktbuf_free(new_buf);
        return err;
    }

    // 发包
    err = icmpv4_out(dest, src, new_buf);
    if (err < 0) {
        dbg_error(DBG_ICMP, "send icmp unreach failed.");
        pktbuf_free(new_buf);
        return err;
    }
    return NET_ERR_OK;
}

/**
 * @brief 检查包是否有错误
 */
static net_err_t is_pkt_ok(icmpv4_pkt_t * pkt, int size, pktbuf_t * buf) {
    // 比头部空间小，有问题
    if (size <= sizeof(icmpv4_hdr_t)) {
        dbg_warning(DBG_ICMP, "size error: %d", size);
        return NET_ERR_SIZE;
    }

    // 校验和检查
    //ICMP 的校验和覆盖的是：整个 ICMP 报文
    uint16_t checksum = pktbuf_checksum16(buf, size, 0, 1);
    if (checksum != 0) {
        dbg_warning(DBG_ICMP, "Bad checksum %0x(correct is: %0x)\n", pkt->hdr.checksum, checksum);
        return NET_ERR_CHKSUM;
    }

    return NET_ERR_OK;
}

/**
 *  @brief ICMP输入报文处理
 * ICMP本身没有数据长字段，需要通过ip头来确定，所以这里加size参数，由ip层设置
 * 输入进来的包是IP包，因为有可能其它模块会需要处理这个包，需要知道IP包头
 */
net_err_t icmpv4_in(ipaddr_t *src, ipaddr_t * netif_ip, pktbuf_t *buf) {
    dbg_info(DBG_ICMP, "icmp in !\n");

    // 调整头部空间，给出icmp的头. 下面这里预留了ip包，方便以后处理
    //ICMP 报文并不在 buf 的开头，而是在 IP头后面
    ipv4_pkt_t* ip_pkt = (ipv4_pkt_t*)pktbuf_data(buf);
    int iphdr_size = ip_pkt->hdr.shdr * 4;   // ip包头和icmp包头连续
    net_err_t err = pktbuf_set_cont(buf, sizeof(icmpv4_hdr_t) + iphdr_size);
    if (err < 0) {
        dbg_error(DBG_ICMP, "set icmp cont failed");
        return err;
    }
    ip_pkt = (ipv4_pkt_t*)pktbuf_data(buf);

    //同一个 buf，在不同层次可以有不同“观察起点”。  从 IPv4 层看，起点是 IP 头  从 ICMP 层看，起点是 IP 头后面的 ICMP 报文
    icmpv4_pkt_t * icmp_pkt = (icmpv4_pkt_t*)(pktbuf_data(buf) + iphdr_size);
    pktbuf_reset_acc(buf);
    pktbuf_seek(buf, iphdr_size);       // 跳到icmp的包头
    //先从整个 IP 包里扣掉前面的 IPv4 头，再检查剩下的 ICMP 部分是否完整、校验和是否正确
    if ((err = is_pkt_ok(icmp_pkt, buf->total_size - iphdr_size, buf)) != NET_ERR_OK) {
        dbg_warning(DBG_ICMP, "icmp pkt error.drop it. err=%d", err);
        return err;
    }
    display_icmp_packet("icmp in", icmp_pkt);

    // 根据类型做不同的处理
    //至少先支持 ping 请求与响应，其它 ICMP 类型先作为原始协议数据交给更上层
    switch (icmp_pkt->hdr.type) {
        case ICMPv4_ECHO_REQUEST: {
            // 移除IP包头部, ICMP处理不需要
            err = pktbuf_remove_header(buf, iphdr_size);
            if (err < 0) {
                dbg_error(DBG_ICMP, "remove ip header failed. err = %d\n", err);
                return NET_ERR_SIZE;
            }

            dbg_dump_ip(DBG_ICMP, "icmp request, ip:", src);
            //把收到的 Echo Request 改成 Echo Reply，然后从本机发回给原发送者
            return icmpv4_echo_reply(src, netif_ip, buf);
        }
        default: {
            // 不能识别的统一交由raw处理
            /*1. ICMP 模块不用一开始就把所有类型全部写死把常见的 Echo 支持起来就够用。
            2. 其它类型不会直接被吞掉仍然能通过 raw 层暴露给别的模块处理。 */
            err = raw_in(buf);
            if (err < 0) {
                dbg_warning(DBG_ICMP, "raw in failed.");
                return err;
            }
            return NET_ERR_OK;
        }
    }
}

/**
 * 初始化icmp模块
 */
net_err_t icmpv4_init(void) {
    dbg_info(DBG_ICMP, "init icmp");
    dbg_info(DBG_ICMP, "done");
    return NET_ERR_OK;
}

/*
ICMPv4 理解成：IPv4 自带的“反馈机制”和“诊断机制”。


发送方向
构造 ICMP 报文
算校验和
交给 ipv4_out()

接收方向
从 IPv4 交过来的包中解析 ICMP
检查它是否是合法 ICMP
根据 type 分发
如果是 Echo Request，就回 Echo Reply
其它类型交给 raw 层







*/