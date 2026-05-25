
/**
 * @brief TCP环形缓冲区
 */
#include "tcp_buf.h"
#include "pktbuf.h"
#include "dbg.h"

/**
 * @brief 初始化tcp缓存
 * 缓存空间自己不分配，而是使用外部传输的空间
 */
void tcp_buf_init(tcp_buf_t* buf, uint8_t * data, int size) {
    buf->in = buf->out = 0;
    buf->count = 0;
    buf->size = size;
    buf->data = data;
}

/**
 * @brief 从缓存（环形缓冲区）中数据偏移为offset的位置开始读取指定数据的数据到指定的包中
 * 
这个函数会从 TCP 缓冲区 中读取指定位置 offset 开始的数据，直到 count 数据量，写入到目标包 pktbuf_t dest 中。
在读取数据时，考虑到缓冲区的回绕情况，即数据可能跨越缓冲区的尾部回绕到头部，所以需要处理两段数据的拷贝。
如果读取的数据量超过了有效数据量，调整 count。
 */
void tcp_buf_read_send(tcp_buf_t * buf, int offset, pktbuf_t * dest, int count) {
    // 超过要求的数据量，进行调整
    int free_for_us = buf->count - offset;      // 跳过offset之前的数据
    if (count > free_for_us) {
        //count > free_for_us：意味着请求的数据量（count）大于当前缓冲区可用的数据量
        dbg_warning(DBG_TCP, "resize for send: %d -> %d", count, free_for_us);
        count = free_for_us;
    }

    // 复制过程中要考虑buf中的数据回绕的问题
    int start = buf->out + offset;     // 注意拷贝的偏移
    if (start >= buf->size) {
        start -= buf->size;
    }

    while (count > 0) {
        // 当前超过末端，则只拷贝到末端的区域
        int end = start + count;
        if (end >= buf->size) {
            end = buf->size;
        }
        int copy_size = (int)(end - start);

        // 写入数据
        net_err_t err = pktbuf_write(dest, buf->data + start, (int)copy_size);
        dbg_assert(err >= 0, "write buffer failed.");

        // 更新start，处理回绕的问题
        start += copy_size;
        if (start >= buf->size) {
            start -= buf->size;
        }
        count -= copy_size;

        // 不调整buf中的count和out，因为只当被确认时才需要
    }
}

/**
 * @brief 从缓冲中移除指定数量的数据
 * 在缓冲中的数据被确认时，移除缓刑开头出指定字节的数据
 * 移除 TCP 缓冲区中已确认的数据。
cnt 是需要从缓冲区移除的数据量。它不能超过当前缓冲区中的数据量（即 count）。
移除数据后，更新 out 和 count。out 指示下一个要读取的位置。count 表示当前缓冲区中存储的数据量。
如果 out 超过了缓冲区大小，则执行回绕（即将 out 重置为 0）。
 */
int tcp_buf_remove(tcp_buf_t * buf, int cnt) {
    if (cnt > buf->count) {
        cnt = buf->count;
    }

    buf->out += cnt;
    if (buf->out >= buf->size) {
        buf->out -= buf->size;
    }
    buf->count -= cnt;
    return cnt;
}

/**
 * @brief 将待发送的数据写入发送缓存中，
 * 从 buffer 中逐字节读取数据，并将其写入到目标缓冲区 dest 中。
in 是写入的位置，写入后 in 会递增。如果 in 达到缓冲区大小，则回绕到缓冲区的开始位置（即 in = 0）。
每写入一个字节，count 自增，表示缓冲区中的数据量增加。
 */
void tcp_buf_write_send(tcp_buf_t * dest, const uint8_t * buffer, int len) {
    while (len > 0) {
        // 循环逐字节写入数据量
        dest->data[dest->in++] = *buffer++;
        if (dest->in >= dest->size) {
            dest->in = 0;
        }

        dest->count++;
        len--;
    }
}

/**
 * @brief 写接收缓存。当从网络上接收数据时，从src中提出数据写入dest中
 * 将接收数据写入接收缓冲区。
offset 是需要跳过的已处理数据的字节数，total 是要写入的总数据量。
该函数将数据从源 src 复制到接收缓冲区 dest，并处理可能存在的缓冲区回绕问题。
每次写入数据后，更新接收缓冲区中的 in 和 count，并确保数据的完整性。
 */
int tcp_buf_write_rcv(tcp_buf_t * dest, int offset, pktbuf_t * src, int total) {
    // 计算缓冲区中的起始索引，注意回绕
    int start = dest->in + offset;
    if (start >= dest->size) {
        start = start - dest->size;
    }

    // 计算实际可写的数据量
    int free_size = tcp_buf_free_cnt(dest) - offset;            // 跳过的一部分相当于是已经被写入了
    total = (total > free_size) ? free_size : total;

    int size = total;
    while (size > 0) {
        // 从start到缓存末端的单元数量，可能其中有数据也可能没有
        int free_to_end = dest->size - start;

        // 大小超过到尾部的空闲数据量，只拷贝一部分
        int curr_copy = size > free_to_end ? free_to_end : size;
        pktbuf_read(src, dest->data + start, (int)curr_copy);

        // 增加写索引，注意回绕
        start += curr_copy;
        if (start >= dest->size) {
            start = start - dest->size;
        }

        // 增加已写入的数据量
        dest->count += curr_copy;
        size -= curr_copy;
    }

    dest->in = start;
    return total;
}

/**
 * @brief 从接收缓冲区读取数据给应用程序。
size 是应用请求的读取数据量，实际读取的数据量为 min(size, src->count)，即不能超过缓冲区中实际存储的数据量。
每次从缓冲区读取一个字节，更新 out 和 count。
如果 out 达到缓冲区大小，执行回绕（即将 out 重置为 0）
 */
int tcp_buf_read_rcv (tcp_buf_t * src, uint8_t * buf, int size) {
    // 选实际能读取的量
    int total = size > src->count ? src->count : size;

    // 逐字节拷贝，慢一点但好理解
    int curr_size = 0;
    while (curr_size < total) {
        // 拷贝数据，位置前移
        *buf++ = src->data[src->out++];

        // 注意回绕
        if (src->out >= src->size) {
            src->out = 0;
        }

        // 调整字字量
        src->count--;
        curr_size++;
    }
    return total;
}
