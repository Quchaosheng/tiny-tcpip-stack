#ifndef TCP_H
#define TCP_H

#include "sock.h"
#include "timer.h"
#include "exmsg.h"
#include "dbg.h"
#include "net_cfg.h"
#include "tcp_buf.h"

#pragma pack(1)

#define TCP_DEFAULT_MSS     536         // 缺省的MSS值  默认最大报文段大小
//TCP 头不一定只有固定 20 字节，还可能带选项
// TCP选项数据
#define TCP_OPT_END        0            // 选项结束
#define TCP_OPT_NOP        1            // 无操作，用于填充
#define TCP_OPT_MSS        2            // 最大段大小

/**
 * TCP数据包头结构      TCP 头的内存表示，对应真实网络里的 TCP 首部
 */
typedef struct _tcp_hdr_t {
    uint16_t sport;             // 源端口
    uint16_t dport;             // 目的端口

    // 全双工通信
    uint32_t seq;             // 自己的序列号
    uint32_t ack;             // 发给对方响应序列号

    union {
        uint16_t flags;
        //小端机机器（如 x86、ARM 默认模式）必须按位域“反着来”，大端机（如 PowerPC、网络处理器）可以直接按手册顺序来
        //在网络编程中，有一个铁律：网络字节序（Network Byte Order）强制规定为大端序。
#if NET_ENDIAN_LITTLE
        struct {
            uint16_t resv : 4;          // 保留
            uint16_t shdr : 4;          // 头部长度
            uint16_t f_fin : 1;           // 已经完成了向对方发送数据，结束整个发送
            uint16_t f_syn : 1;           // 同步，用于初始一个连接的同步序列号
            uint16_t f_rst : 1;           // 重置连接
            uint16_t f_psh : 1;           // 推送：接收方应尽快将数据传递给应用程序
            uint16_t f_ack : 1;           // 确认号字段有效
            uint16_t f_urg : 1;           // 紧急指针有效
            uint16_t f_ece : 1;           // ECN回显：发送方接收到了一个更早的拥塞通告
            uint16_t f_cwr : 1;           // 拥塞窗口减，发送方降低其发送速率
        };
#else
        struct {
            uint16_t shdr : 4;          // 头部长度
            uint16_t resv : 4;          // 保留
            uint16_t f_cwr : 1;           // 拥塞窗口减，发送方降低其发送速率
            uint16_t f_ece : 1;           // ECN回显：发送方接收到了一个更早的拥塞通告
            uint16_t f_urg : 1;           // 紧急指针有效
            uint16_t f_ack : 1;           // 确认号字段有效
            uint16_t f_psh : 1;           // 推送：接收方应尽快将数据传递给应用程序
            uint16_t f_rst : 1;           // 重置连接
            uint16_t f_syn : 1;           // 同步，用于初始一个连接的同步序列号
            uint16_t f_fin : 1;           // 已经完成了向对方发送数据，结束整个发送
        };
#endif
    };
    uint16_t win;                       // 窗口大小，实现流量控制, 窗口缩放选项可以提供更大值的支持
    uint16_t checksum;                  // 校验和
    uint16_t urgptr;                    // 紧急指针
}tcp_hdr_t;

/**
 * @brief TCP选项
 * 为什么单独定义？
因为 TCP 头中的“选项区”是变长的，不适合直接塞在固定头结构里 便于发送 SYN 时构造 收到 SYN 时解析
 */
typedef struct _tcp_opt_mss_t {
    uint8_t kind;
    uint8_t length;
    union {
        uint16_t mss;
    };
}tcp_opt_mss_t;

/**
 * TCP数据包
 */
typedef struct _tcp_pkt_t {
    tcp_hdr_t hdr;
    uint8_t data[1];  //不是说数据就 1 字节，而是把它当成“起始位置”
}tcp_pkt_t;

#pragma pack()

/**
 * TCP状态机中的各种状态
 */
typedef enum _tcp_state_t {
    //标准 TCP 规范里没有 FREE。  这里加它是因为这个项目不是只做“协议逻辑”，还要做“对象池管理”。
    TCP_STATE_FREE = 0,             // 空闲状态，非标准状态的一部分
    TCP_STATE_CLOSED,
    TCP_STATE_LISTEN,
    TCP_STATE_SYN_SENT,
    TCP_STATE_SYN_RECVD,
    TCP_STATE_ESTABLISHED,
    TCP_STATE_FIN_WAIT_1,
    TCP_STATE_FIN_WAIT_2,
    TCP_STATE_CLOSING,
    TCP_STATE_TIME_WAIT,
    TCP_STATE_CLOSE_WAIT,
    TCP_STATE_LAST_ACK,

    TCP_STATE_MAX,
}tcp_state_t;

/**
 * @brief TCP报文段结构
 * 表示“收到的或准备处理的一个 TCP 报文段”
 */
typedef struct _tcp_seg_t {
    ipaddr_t local_ip;               // 本地IP
    ipaddr_t remote_ip;              // 远端IP
    tcp_hdr_t * hdr;                // TCP包
    pktbuf_t * buf;                 // Buffer包
    uint32_t data_len;              // 数据长度
    uint32_t seq;                   // 起始序号
    uint32_t seq_len;               // 序列号空间长度
    //seq_len 为什么不是简单等于 data_len
    /*seq_len = 数据长度 + SYN占位 + FIN占位*/
}tcp_seg_t;

/**
 * @brief TCP输出状态
 * 表示 TCP 输出侧当前在干什么
 * 为什么除了 TCP 主状态机，还要单独一个发送状态机
 * TCP 的“连接状态”和“发送动作状态”是两套不同维度
 */
typedef enum _tcp_ostate_t {
    TCP_OSTATE_IDLE,                // 空闲状态，没有数据要发送
    TCP_OSTATE_SENDING,             // 正在发送报文
    TCP_OSTATE_REXMIT,              // 重发状态，正在重传数据

    TCP_OSTATE_MAX,                 //TCP 发送状态机中的最大状态值
}tcp_ostate_t;

/**
 * TCP连接块

 */
typedef struct _tcp_t {
    sock_t base;            // 基础sock结构      tcp_t 是建立在通用 sock_t 之上
    struct _tcp_t * parent; // 父tcp结构     用于监听 socket 与子连接的关系。  一个 listen 的 TCP socket 是父对象  accept 新连接会创建 child tcp  child 的 parent 指向监听 socket
    struct {
        //保存 TCP 连接的一些辅助控制标志
        uint32_t syn_out : 1;        // 输出SYN标志位
        uint32_t fin_in : 1;         // 收到FIN
        uint32_t fin_out : 1;        // 需要发送FIN
        uint32_t irs_valid : 1;      // 初始序列号IRS不可用
        uint32_t keep_enable : 1;     // 是否开启keepalive
        uint32_t inactive : 1;       // 非激活状态
   }flags;

    tcp_state_t state;      // TCP状态
    int mss;                // mss值

    struct {
        //管理“连接相关”行为，不是收发数据本身。
        //把“连接控制”相关参数单独放到 conn 子结构中，避免 tcp_t 顶层字段过于混乱。
        sock_wait_t wait;       // 连接等待结构
        int keep_idle;          // Keepalive空闲时间
        int keep_intvl;         // 超时间隔
        int keep_cnt;           // 最大检查次数
        int keep_retry;         // 当前重试次数
        int backlog;            // 接受队列的大小
        net_timer_t keep_timer; // 超时定时器
    }conn;

    struct {
        /*已确认       已发送未确认          未发送
----     -     |-----------------   -|-----------
              una                   nxt*/
        tcp_buf_t buf;      // 发送缓冲区
        uint8_t  data[TCP_SBUF_SIZE];
        uint32_t una;	    // 已发但未确认区域的起始序号
        uint32_t nxt;	    // 未发送的起始序号
        uint32_t iss;	    // 起始发送序号

        tcp_ostate_t ostate;  // 输出状态
        int rexmit_cnt;     // 重发次数
        int rexmit_max;     // 最大重发次数
        net_timer_t timer;    // 发送定时器
        int rto;            // 重传超时

        sock_wait_t wait;   // 发送等待结构
    }snd;

    struct {
        tcp_buf_t buf;      // 接收缓冲区
        uint8_t data[TCP_RBUF_SIZE];
        uint32_t nxt;	    // 下一个期望接受的序号
        //为什么接收侧也有 iss     在记录“对端发送的初始序号基准”，方便后续计算接收序号推进
        uint32_t iss;	    // 起始接收序号
        sock_wait_t wait;   // 接收等待结构
    }rcv;
}tcp_t;

/**
 * @brief 设置包头大小
 */
static inline void tcp_set_hdr_size (tcp_hdr_t * hdr, int size) {
    hdr->shdr = size / 4;  //TCP 头部长度字段 shdr 不是按字节存的，而是按4字节为单位
}

/**
 * @brief 获取包头大小
 */
static inline int tcp_hdr_size (tcp_hdr_t * hdr) {
    return hdr->shdr * 4;
}

#if DBG_DISP_ENABLED(DBG_TCP)       // 注意头文件要包含dbg.h和net_cfg.h
void tcp_show_info (char * msg, tcp_t * tcp);
void tcp_display_pkt (char * msg, tcp_hdr_t * tcp_hdr, pktbuf_t * buf);
void tcp_show_list (void);
#else
#define tcp_show_info(msg, tcp)
#define tcp_display_pkt(msg, hdr, buf)
#define tcp_show_list()
#endif

net_err_t tcp_init(void);

sock_t* tcp_find(ipaddr_t * local_ip, uint16_t local_port, ipaddr_t * remote_ip, uint16_t remote_port);
void tcp_free(tcp_t* tcp);

void tcp_read_options(tcp_t *tcp, tcp_hdr_t *tcp_hdr);
int tcp_rcv_window (tcp_t * tcp);

/*tcp_abort：异常终止连接
tcp_backlog_count：获取监听 backlog 中的连接数
tcp_create_child：服务端收到新连接时创建子连接对象*/

net_err_t tcp_abort (tcp_t * tcp, int err);
int tcp_backlog_count (tcp_t * tcp);
sock_t* tcp_create (int family, int protocol);
void tcp_kill_all_timers (tcp_t * tcp);

//TCP 版的 socket 操作实现
net_err_t tcp_close(struct _sock_t* sock);
net_err_t tcp_connect(struct _sock_t* sock, const struct x_sockaddr* addr, x_socklen_t len);
void tcp_destory (struct _sock_t * sock);
net_err_t tcp_recv (struct _sock_t* s, void* buf, size_t len, int flags, ssize_t * result_len);
net_err_t tcp_send (struct _sock_t* sock, const void* buf, size_t len, int flags, ssize_t * result_len);
net_err_t tcp_bind(struct _sock_t* sock, const struct x_sockaddr* addr, x_socklen_t len);
net_err_t tcp_listen (struct _sock_t* s, int backlog);
net_err_t tcp_accept (struct _sock_t *s, struct x_sockaddr* addr, x_socklen_t* len, struct _sock_t ** client);
tcp_t * tcp_create_child (tcp_t * parent, tcp_seg_t * seg);

void tcp_keepalive_start (tcp_t * tcp, int run);
void tcp_keepalive_restart (tcp_t * tcp);

//为什么 TCP 序号比较不能直接 a < b
/*TCP 序号是 uint32_t，会回绕。
也就是说序号走到最大值后会从 0 重新开始。*/
#define TCP_SEQ_LE(a, b)        ((int32_t)(a) - (int32_t)(b) <= 0)
#define TCP_SEQ_LT(a, b)        ((int32_t)(a) - (int32_t)(b) < 0)

#endif // TCP_H

