/**
 * @brief TCP收发缓存，使用环形缓存实现
 */
#include "net_cfg.h"
#include "sys.h"
#include "pktbuf.h"

/**
 * @brief TCP环形缓存
 */
typedef struct _tcp_sbuf_t {
    int count;                          // 缓存中已有的数据量
    int in, out;                        // 写入读取索引
    int size;                           // 整个缓存空间的
    uint8_t * data;                     // 缓存数据区
}tcp_buf_t;

void tcp_buf_init(tcp_buf_t* buf, uint8_t * data, int size);
//从接收缓冲区里读数据出来，拷贝到应用层的 buf中
/*问：为什么 TCP 接收缓冲区读取函数通常返回“实际读取字节数”？
因为 TCP 是面向字节流的，应用请求读取的长度和当前缓冲区实际可用数据量不一定一致，
所以读取操作通常返回实际读出的字节数，而不是固定等于请求长度。*/
int tcp_buf_read_rcv (tcp_buf_t * src, uint8_t * buf, int size);
//从 发送缓冲区 中，按照某个偏移 offset，读取 count 字节，写入到 pktbuf_t *dest，用于组装发送报文。
/*应用层调用 TCP send() 后，数据一定会立刻发出去吗？
不一定。通常会先写入 TCP 发送缓冲区，再由协议栈根据发送窗口、拥塞控制、分段策略和调度时机决定何时真正构造报文并发送。*/
void tcp_buf_read_send(tcp_buf_t * src, int offset, pktbuf_t * dest, int count);
void tcp_buf_write_send(tcp_buf_t * dest, const uint8_t * buffer, int len);
//收到的 TCP 数据，从 pktbuf_t *src 写入接收缓冲区 dest，写入位置带 offset。
int tcp_buf_write_rcv(tcp_buf_t * dest, int offset, pktbuf_t * src, int size);
//缓冲区中的有效数据窗口在不断向前推进 不能单独remove
int tcp_buf_remove(tcp_buf_t * buf, int cnt);

/**
 * @brief 获取缓存大小 
 */
static inline int tcp_buf_size (tcp_buf_t * buf) {
    return buf->size;
}

/**
 * @brief 计算空间单元的数量
 */
static inline int tcp_buf_free_cnt(tcp_buf_t * buf) {
    return buf->size - buf->count;
}

/**
 * @brief 返回缓存里的数据量
 */
static inline int tcp_buf_cnt (tcp_buf_t * buf) {
    return buf->count;
}
/*为什么 TCP 一定需要缓冲区？
因为 TCP 是面向字节流并且提供可靠传输的协议，应用层读写速度和网络收发速度不一致，同
时还涉及分段发送、重传、乱序接收和按序交付，所以必须使用发送缓冲区和接收缓冲区进行中间缓存和管理。

tcp_buf_write_rcv 为什么也需要 offset 参数？
因为 TCP 接收的数据段可能乱序到达，接收缓冲区需要根据序列号对应的相对偏移把数据写入正确位置，以支持乱序缓存和后续按序交付。

*/