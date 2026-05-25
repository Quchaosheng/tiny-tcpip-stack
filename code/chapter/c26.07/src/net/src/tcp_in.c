/**
 * 如果收到了TCP包，可能需要即地其进行排序，因为TCP可能会先收到
 * 大序列号的数据，再收到小的；甚至有可能出现多个包之间序列号重叠。
 * 即处理数据空洞、乱序、重复等多种问题。
 */
#include "socket.h"
#include "pktbuf.h"
#include "tcp.h"
#include "tcp_in.h"
#include "tcp_out.h"
#include "ipaddr.h"
#include "tcp_state.h"

/**
 * @brief TCP报文段初始化
 */
void tcp_seg_init (tcp_seg_t * seg, pktbuf_t * buf, ipaddr_t * local, ipaddr_t * remote) {
    seg->buf = buf;
    seg->hdr = (tcp_hdr_t*)pktbuf_data(buf);

    ipaddr_copy(&seg->local_ip, local);
    ipaddr_copy(&seg->remote_ip, remote);
    seg->data_len = buf->total_size - tcp_hdr_size(seg->hdr);
    seg->seq = seg->hdr->seq;
    seg->seq_len = seg->data_len + seg->hdr->f_syn + seg->hdr->f_fin;
}

/**
 * @brief 对输入的TCP报文进行处理，使用序号范围被调用在当前的接收窗口范围内
 * 这就意味着：如果有序号超出了窗口的头部或尾部，将被截断
 */
static int copy_data_to_rcvbuf(tcp_t * tcp, tcp_seg_t * seg) {
    tcp_hdr_t * tcp_hdr = seg->hdr;
    pktbuf_t * buf = seg->buf;

    // doffset相对于缓存开始的偏移量。目前只处理==0的情况，以便过滤掉调试中收到的对方重传的数据包
    int doffset = seg->seq - tcp->rcv.nxt;      // 非0时，表示出现了空洞
    if (seg->data_len && (doffset == 0)) {
        // 拷贝数据，目前暂不支持空洞的写入
        return tcp_buf_write_rcv(&tcp->rcv.buf, doffset, buf, seg->data_len);
    }

    return 0;
}

/**
 * @brief 当 TCP 连接已经建立以后，这个函数专门负责处理“收到的数据段”，
 * 把数据放进接收缓冲区，更新接收序号，在必要时唤醒应用层，并给对方回 ACK。
 */
net_err_t tcp_data_in (tcp_t * tcp, tcp_seg_t * seg) {

    // 从报文中提取数据到输入缓存中。注意数据量可能为0
    int size = copy_data_to_rcvbuf(tcp, seg);
    if (size < 0) {
        dbg_error(DBG_TCP, "copy data to tcp rcvbuf failed.");
        return NET_ERR_SIZE;
    }

    // 是否要唤醒任务
    int wakeup = 0;
    if (size) {
        tcp->rcv.nxt += size ;
        wakeup++;
    }

    // 还有可能收到FIN，发送ACK，同时标记已经收到FIN.
    // 但要注意，数据可能乱序到达，即先收到了FIN。因此这里要判断前面的数据是否已经完全收到
    // 如果是的话，才将FIN置位。否则，不予理会，让对方重传
    //seg 里面取出 TCP 首部指针
    tcp_hdr_t * tcp_hdr = seg->hdr;
//tcp_hdr->f_fin 表示这个报文带有 FIN 标志。后面说明这个 FIN 的位置是正确的，前面没有空洞，可以正式接收这个 FIN。
    if (tcp_hdr->f_fin && (tcp->rcv.nxt == seg->seq)) {
        //FIN 虽然不携带普通数据，但它要占用一个序号
        tcp->rcv.nxt++;
        tcp->flags.fin_in = 1;   // 接收完毕
        wakeup++;
    }

    // 只有要数据到达，且被处理，均需通知用户
    if (wakeup) {
        //如果 fin_in 已经置位，说明接收方向已经结束
        if (tcp->flags.fin_in) {
            sock_wakeup((sock_t *)tcp, SOCK_WAIT_ALL, NET_ERR_CLOSE);
        } else {
            sock_wakeup((sock_t *)tcp, SOCK_WAIT_READ, NET_ERR_OK);
        }

        // 只要这次事件被认为有效处理了，就立即给对方发一个 ACK
        //采用延迟确认策略，也就是先等一小会儿，看是否能把 ACK 和将要发送的数据一起捎带出去，减少小包数量，提高效率。
        tcp_send_ack(tcp, seg);
    }

    // 还要给对方发送响应
    return NET_ERR_OK;
}

/**
 * @brief 检查TCP包是否可被接受
 * 主要是检查序号是否在可接受的空间范围内. 注意收到的报文分片范围可能超过窗口的左右边界，需要进行处理
 * 因为已经与对方进行了通信，知道了对方的初始序号
 * 因此，在通信时可以通过妆始序列来判断数据包是否应该被自己处理
 * RFC 793:
 * Segment Receive  Test
 * Length  Window
 * ------- -------  -------------------------------------------
 *    0       0     SEG.SEQ = RCV.NXT
 *    0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
 *   >0       0     not acceptable
 *   >0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
 *                  or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
 *
 * 注意，分片的序列范围可能不完全在接受窗口内，需要在头部或尾部截断。该操作在从分片中提取数据时处理。
 */
static int tcp_seq_acceptable(tcp_t *tcp, tcp_seg_t *seg) {
    //表示当前还能接收多少数据
    uint32_t rcv_win = tcp_rcv_window(tcp);
//包不带数据，也没有 SYN、FIN 纯ACK包
    if (seg->seq_len == 0) {
        // 没有SYN、FIN、无数据，那么只要ACK匹配即可。因此仍然可接收RST和ACK包
        if (rcv_win == 0) {
            // 0(len)   0(win)     SEG.SEQ = RCV.NXT
            return seg->seq == tcp->rcv.nxt;
        } else {
            // 窗口非0，由于序长长度为0，只需要落在窗口内即可
            // 0(len)   >0(win)     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
            int v = TCP_SEQ_LE(tcp->rcv.nxt, seg->seq) && TCP_SEQ_LE(seg->seq, tcp->rcv.nxt + rcv_win - 1);
            //int v = (seg->seq - tcp->rcv.nxt >= 0) && ((seg->seq - (tcp->rcv.nxt + rcv_win)) < 0);
            return v;
        }
    } else {
        // 序号长度不为0，但是窗口为0，不可接受
        //窗口为 0 时，任何带数据长度的包都不接收
        if (rcv_win == 0) {
            return 0;
        } else {
            // 只要首部或尾部的序号在接受窗口内，就说明当前数据报中有部分数据是可以提取出来的(在取数据时再做这个事情)
            // 因此，虽然不是全部数据都可接受，这个包仍然是可能被接受处理的
            uint32_t slast = seg->seq + seg->seq_len - 1;           // 本次的结束序号
            //第一次看起始序号是否在窗口内。
            int v = TCP_SEQ_LE(tcp->rcv.nxt, seg->seq) && TCP_SEQ_LE(seg->seq, tcp->rcv.nxt + rcv_win - 1);
            //int v = (seg->seq - tcp->rcv.nxt >= 0) && ((seg->seq - (tcp->rcv.nxt + rcv_win)) < 0); // 起始
            // 第二次看结束序号是否在窗口内。
            v |= TCP_SEQ_LE(tcp->rcv.nxt, slast) && TCP_SEQ_LE(slast, tcp->rcv.nxt + rcv_win - 1);
            // v |= (slast - tcp->rcv.nxt >= 0) && ((slast - (tcp->rcv.nxt + rcv_win)) < 0); // 起始
            return v;
        }
    }
}

/**
 * @brief TCP数据报的输入处理
 * 注意:传入进来的包为IP数据包
 */
net_err_t tcp_in(pktbuf_t *buf, ipaddr_t *src_ip, ipaddr_t *dest_ip) {
    static const tcp_proc_t tcp_state_proc[] = {
        [TCP_STATE_CLOSED] = tcp_closed_in,
        [TCP_STATE_SYN_SENT] = tcp_syn_sent_in,
        [TCP_STATE_ESTABLISHED] = tcp_established_in,
        [TCP_STATE_FIN_WAIT_1] = tcp_fin_wait_1_in,
        [TCP_STATE_FIN_WAIT_2] = tcp_fin_wait_2_in,
        [TCP_STATE_CLOSING] = tcp_closing_in,
        [TCP_STATE_TIME_WAIT] = tcp_time_wait_in,
        [TCP_STATE_CLOSE_WAIT] = tcp_close_wait_in,
        [TCP_STATE_LAST_ACK] = tcp_last_ack_in,
        [TCP_STATE_LISTEN] = tcp_listen_in,
        [TCP_STATE_SYN_RECVD] = tcp_syn_recvd_in,
    };
//作用是确保缓冲区里至少有一整块连续的 TCP 头，方便后面读取字段
    tcp_hdr_t * tcp_hdr = (tcp_hdr_t *)pktbuf_data(buf);
    if (pktbuf_set_cont(buf, sizeof(tcp_hdr_t)) < 0) {
        dbg_error(DBG_TCP, "set cont failed.");
        return -1;
    }
    tcp_hdr = (tcp_hdr_t *)pktbuf_data(buf);

    // 先查验TCP包头的校验和
    if (tcp_hdr->checksum) {
        pktbuf_reset_acc(buf);
        if (checksum_peso(dest_ip->a_addr, src_ip->a_addr, NET_PROTOCOL_TCP, buf)) {
            dbg_warning(DBG_TCP, "tcp checksum incorrect");
            return NET_ERR_CHKSUM;
        }
    }

    // 检查包的合法性，只做初步的检查，不检查序号等内容
    // 大小应当至少和包头一样大小
    if ((buf->total_size < sizeof(tcp_hdr_t)) || (buf->total_size < tcp_hdr_size(tcp_hdr))) {
        dbg_warning(DBG_TCP, "tcp packet size incorrect: %d!", buf->total_size);
        return NET_ERR_SIZE;
    }

    // 端口不能为空
    if (!tcp_hdr->sport || !tcp_hdr->dport) {
        dbg_warning(DBG_TCP, "port == 0");
        return NET_ERR_UNREACH;
    }

    // 标志位不能为空，总有一个置位
    if (tcp_hdr->flags == 0) {
        dbg_warning(DBG_TCP, "flag == 0");
        return NET_ERR_UNREACH;
    }

    // 调整大小端
    tcp_hdr->sport = x_ntohs(tcp_hdr->sport);
    tcp_hdr->dport = x_ntohs(tcp_hdr->dport);
    tcp_hdr->seq = x_ntohl(tcp_hdr->seq);
    tcp_hdr->ack = x_ntohl(tcp_hdr->ack);
    tcp_hdr->win = x_ntohs(tcp_hdr->win);
    tcp_hdr->urgptr = x_ntohs(tcp_hdr->urgptr);

    tcp_display_pkt("tcp packet in!", tcp_hdr, buf);

    // 初始化报文段结构，方便后续处理
    tcp_seg_t seg;
    tcp_seg_init(&seg, buf, dest_ip, src_ip);

    // 遍历查找是否有可供处理的TCP连接
    tcp_t *tcp = (tcp_t *)tcp_find(dest_ip, tcp_hdr->dport, src_ip, tcp_hdr->sport);
    if (!tcp || (tcp->state >= TCP_STATE_MAX)) {
        dbg_info(DBG_TCP, "no tcp found: port = %d", tcp_hdr->dport);
        tcp_closed_in((tcp_t *)0, &seg);
        pktbuf_free(buf);

        tcp_show_list();
        return NET_ERR_OK;
    }
//跳过 TCP 头，指向数据区
    net_err_t err = pktbuf_seek(buf, tcp_hdr_size(tcp_hdr));
    if (err < 0) {
        dbg_error(DBG_TCP, "seek failed.");
        return NET_ERR_SIZE;
    }

    // 以下几个状态，之前未接受过对方的报文，其不知道此次的序列号是否正确，因此不进行序号号检查
    if ((tcp->state != TCP_STATE_CLOSED)  && (tcp->state != TCP_STATE_SYN_SENT) && (tcp->state != TCP_STATE_LISTEN)) {
       if (!tcp_seq_acceptable(tcp, &seg)) {
            dbg_info(DBG_TCP, "seq incorrect: %d < %d", seg.seq, tcp->rcv.nxt);
            goto seg_drop;
        }
    }

    // 只对正确的包发关响应，错误的包就不处理了，就更新连接活跃时间
    tcp_keepalive_restart(tcp);

    // 交由不同的状态进行处理
    tcp_state_proc[tcp->state](tcp, &seg);
    tcp_show_info("after tcp in", tcp);
    //tcp_show_list();

    // 总是释放包，简化处理
seg_drop:
    pktbuf_free(buf);
    return NET_ERR_OK;
}

/*
一  TCP报文的处理过程：
1初始化：每当接收到一个TCP报文时，首先会通过tcp_seg_init函数对报文进行初始化。
2数据的接收与排序：由于TCP协议是面向连接的，数据包可能会乱序到达，因此需要对其进行排序。
copy_data_to_rcvbuf函数会根据序列号将数据存入接收缓存，并且检查是否出现数据空洞。
3窗口管理：在TCP中，接收方维护一个接收窗口，用于判断是否接收到正确的数据。tcp_seq_acceptable函数检查报文的序列号是否在接收窗口内。


二  TCP连接的状态管理：
TCP协议的每个连接都有不同的状态（例如，SYN_SENT、ESTABLISHED、FIN_WAIT_1等）。每种状态下，TCP如何处理接收到的报文是不同的。
tcp_state_proc数组定义了不同状态下如何处理接收到的TCP报文段（例如，在TCP_STATE_ESTABLISHED状态下如何处理）。
三  TCP报文段的处理：
tcp_data_in函数会处理输入的TCP数据，将数据从TCP报文中提取出来并放入接收缓冲区。同时，检查是否需要唤醒等待任务，或者是否收到了FIN标志，标志着连接关闭。

校验与错误处理：

校验和：tcp_in函数首先检查TCP报文的校验和是否正确，若错误则丢弃该报文。

数据大小：接收到的TCP报文必须满足一定的大小要求，否则也会被丢弃。*/