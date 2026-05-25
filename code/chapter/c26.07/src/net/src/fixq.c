/**
 * 
 * 
 * fixq.c 实现的是 固定长度消息队列（fixed queue），在整个协议栈中主要用于：
数据包排队：UDP/TCP/网络层接收到的数据包暂存
线程/任务间通信：消息或事件传递
资源控制：通过固定长度限制队列容量，避免占用过多内存
 */
#include "fixq.h"
#include "nlocker.h"
#include "dbg.h"
#include "sys.h"

/**
 * @brief 初始化定长消息队列
 */
net_err_t fixq_init(fixq_t *q, void **buf, int size, nlocker_type_t type) {
    q->size = size;
    q->in = q->out = q->cnt = 0;
    q->buf = (void **)0;
    q->recv_sem = SYS_SEM_INVALID;
    q->send_sem = SYS_SEM_INVALID;

    // 初始化锁，根据类型（线程锁或中断锁）
    net_err_t err = nlocker_init(&q->locker, type);
    if (err < 0) {
        dbg_error(DBG_QUEUE, "init locker failed!");
        return err;
    }

    // 创建发送信号量
    //send_sem：控制队列空闲单元   recv_sem：控制可用消息
    q->send_sem = sys_sem_create(size);
    if (q->send_sem == SYS_SEM_INVALID)  {
        dbg_error(DBG_QUEUE, "create sem failed!");
        err = NET_ERR_SYS;
        goto init_failed;
    }

    q->recv_sem = sys_sem_create(0);
    if (q->recv_sem == SYS_SEM_INVALID) {
        dbg_error(DBG_QUEUE, "create sem failed!");
        err = NET_ERR_SYS;
        goto init_failed;
    }

    q->buf = buf;
    return NET_ERR_OK;
init_failed:
    if (q->recv_sem != SYS_SEM_INVALID) {
        sys_sem_free(q->recv_sem);
    }

    if (q->send_sem != SYS_SEM_INVALID) {
        sys_sem_free(q->send_sem);
    }

    nlocker_destroy(&q->locker);
    return err;
}

/**
 * @brief 向消息队列写入一个消息
 * 队列满时，如果 tmo < 0 → 非阻塞模式，立即返回错误
队列满时，如果 tmo >= 0 → 阻塞等待，直到有空位或超时
 */
net_err_t fixq_send(fixq_t *q, void *msg, int tmo) {
    nlocker_lock(&q->locker);
    if ((q->cnt >= q->size) && (tmo < 0)) {
        // 如果缓存已满，并且不需要等待，则立即退出
        nlocker_unlock(&q->locker);
        return NET_ERR_FULL;
    }
    nlocker_unlock(&q->locker);

    // 消耗掉一个空闲资源，如果为空则会等待
    if (sys_sem_wait(q->send_sem, tmo) < 0) {
        return NET_ERR_TMO;
    }

    // 有空闲单元写入缓存
    nlocker_lock(&q->locker);
    //将传入的消息指针 msg 放入队列数组          q->in 是数组索引 → 当前空闲槽  写入后in自增
    q->buf[q->in++] = msg;
    //当 in 到达末尾 → 回绕到数组开头  保证队列循环使用，不用移动元素
    if (q->in >= q->size) {
        q->in = 0;
    }
    q->cnt++;
    nlocker_unlock(&q->locker);

    // 通知其它进程有消息可用
    sys_sem_notify(q->recv_sem);
    return NET_ERR_OK;
}

/**
 * @brief 从数据包队列中取一个消息，如果无，则等待
 */
void *fixq_recv(fixq_t *q, int tmo) {
    // 如果缓存为空且不需要等，则立即退出
    nlocker_lock(&q->locker);
    if (!q->cnt && (tmo < 0)) {
        nlocker_unlock(&q->locker);
        return (void *)0;
    }
    nlocker_unlock(&q->locker);

    // 在信号量上等待数据包可用
    if (sys_sem_wait(q->recv_sem, tmo) < 0) {
        return (void *)0;
    }

    // 取消息
    nlocker_lock(&q->locker);
    void *msg = q->buf[q->out++];
    if (q->out >= q->size) {
        q->out = 0;
    }
    q->cnt--;
    nlocker_unlock(&q->locker);

    // 通知有空闲空间可用
    sys_sem_notify(q->send_sem);
    return msg;
}

/**
 * 销毁队列
 * @param list 待销毁的队列
 */
void fixq_destroy(fixq_t *q) {
    //销毁锁
    //unlock → 暂时释放临界区锁，队列还可以继续使用  destroy → 队列彻底不再使用，销毁锁对象，释放底层系统资源
    nlocker_destroy(&q->locker);
    sys_sem_free(q->send_sem);
    sys_sem_free(q->recv_sem);
}

/**
 * @brief 取缓冲中消息的数量
 */
int fixq_count (fixq_t *q) {
    nlocker_lock(&q->locker);
    int count = q->cnt;
    nlocker_unlock(&q->locker);
    return count;
}


/*1环形索引逻辑
in 和 out 指针循环使用，需要理解 wrap-around
队列满和队列空的判断逻辑
2并发安全
所有修改队列状态的操作必须加锁
注意锁的粒度，避免死锁
3信号量机制
send_sem 控制队列空闲空间
recv_sem 控制消息可用
理解阻塞/非阻塞模式和超时处理
4队列容量限制
队列满时根据 tmo 决定是否阻塞或立即返回
队列空时同理
5消息类型
队列存储的是 void*，通常指向 pktbuf 或消息对象
队列本身不管理消息内存，只管理指针*/