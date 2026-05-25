/**
 * @brief TCP/IP核心线程通信模块
 * 消息缓冲区和队列管理
接收网络接口消息
执行 API 函数消息
核心线程循环处理消息和定时器事件
*/
#include "net_plat.h"
#include "exmsg.h"
#include "fixq.h"
#include "mblock.h"
#include "dbg.h"
#include "nlocker.h"
#include "timer.h"
#include "ipv4.h"
#include "sys.h"

static void * msg_tbl[EXMSG_MSG_CNT];  // 消息缓冲区  存放消息指针
static fixq_t msg_queue;            // 消息队列
static exmsg_t msg_buffer[EXMSG_MSG_CNT];  // 消息块
static mblock_t msg_block;          // 消息分配器 管理 msg_buffer 的分配/释放  msg_buffer 是 静态内存池，存放所有可能使用的消息对象

net_err_t test_func (struct _func_msg_t* msg) {
    msg->err = 0x1234;
    printf("hello, 1234: %x", *(int *)msg->param);
    return NET_ERR_OK;
}

/**
 * @brief 收到来自网卡的消息
 * 当网卡收到数据时，生成消息放入核心队列
 * 分配一个 exmsg_t 消息块
设置消息类型为 NET_EXMSG_NETIF_IN
设置接口指针 msg->netif.netif = netif
发送到消息队列 (fixq_send)
队列满 → 回收消息，返回错误
 */
net_err_t exmsg_netif_in(netif_t* netif) {
    // 分配一个消息结构
    exmsg_t* msg = mblock_alloc(&msg_block, -1);
    if (!msg) {
        dbg_warning(DBG_MSG, "no free exmsg");
        return NET_ERR_MEM;
    }

    // 写消息内容
    msg->type = NET_EXMSG_NETIF_IN;
    msg->netif.netif = netif;

    // 发送消息
    net_err_t err = fixq_send(&msg_queue, msg, -1);
    if (err < 0) {
        dbg_warning(DBG_MSG, "fixq full");
        mblock_free(&msg_block, msg);
        return err;
    }

    return NET_ERR_OK;
}

/**
 * @brief 网络接口有数据到达时的消息处理
 * 循环从网卡接口取数据包 netif_get_in
如果网卡有链路层驱动 → 调用 netif->link_layer->in
否则 → 调用 ipv4_in
出错 → 释放 pktbuf 并打印警告
 */
static net_err_t do_netif_in(exmsg_t* msg) {
    netif_t* netif = msg->netif.netif;

    // 反复从接口中取出包，然后一次性处理
    pktbuf_t* buf;
    while ((buf = netif_get_in(netif, -1))) {
        dbg_info(DBG_MSG, "recv a packet");

        // 如果有链路层驱动，先将链路层进行处理
        net_err_t err;
        if (netif->link_layer) {
            err = netif->link_layer->in(netif, buf);

            // 发生错误，需要自己释放包。因为这个包是已经在队列中，由自己取出的
            // 因此，如果上层处理不了，需要自己进行释放
            if (err < 0) {
                // 暂不处理，只是回收
                pktbuf_free(buf);
                dbg_warning(DBG_MSG, "netif in failed. err=%d", err);
            }
        } else {
            err = ipv4_in(netif, buf);
            if (err < 0) {
                pktbuf_free(buf);
                dbg_warning(DBG_MSG, "netif in failed. err=%d", err);
            };
        }
    }

    return NET_ERR_OK;
}

/**
 * @brief 执行 API 函数消息：在核心线程上下文中执行一个函数消息
 * 流程如下
构造 func_msg_t 消息
包含线程 ID、回调函数、参数、信号量
分配 exmsg_t 消息块，类型 NET_EXMSG_FUN
发送到核心消息队列
当前线程等待信号量完成
核心线程执行函数 → 释放信号量 → 函数返回结果
 */
net_err_t exmsg_func_exec(exmsg_func_t func, void * param) {
    // 构造消息
    func_msg_t func_msg;
    //记录当前线程的 ID       实现线程间函数调用
    func_msg.thread = sys_thread_self();
    //保存要执行的函数指针
    func_msg.func = func;
    //保存函数执行所需的参数      类函数执行时可以访问调用者传入的上下文数据
    func_msg.param = param;
    //初始化错误码
    func_msg.err = NET_ERR_OK;
    //创建一个临时信号量，用于同步线程
    //参数为0：调用线程需要 等待核心线程执行完函数  核心线程执行完毕后会 sys_sem_notify(wait_sem)，释放等待的线程
    func_msg.wait_sem = sys_sem_create(0);
    if (func_msg.wait_sem == SYS_SEM_INVALID) {
        dbg_error(DBG_MSG, "error create wait sem");
        return NET_ERR_MEM;
    }

    // 分配消息结构
    exmsg_t* msg = (exmsg_t*)mblock_alloc(&msg_block, 0);
    msg->type = NET_EXMSG_FUN;
    msg->func = &func_msg;

    // 发消息给工作线程去执行
    dbg_info(DBG_MSG, "1.begin call func: %p", func);
    net_err_t err = fixq_send(&msg_queue, msg, 0);
    if (err < 0) {
        dbg_error(DBG_MSG, "send msg to queue ailed. err = %d", err);
        mblock_free(&msg_block, msg);
        sys_sem_free(func_msg.wait_sem);
        return err;
    }

    // 等待执行完成
    sys_sem_wait(func_msg.wait_sem, 0);
    dbg_info(DBG_MSG, "4.end call func: %p", func);

    // 释放信号量
    sys_sem_free(func_msg.wait_sem);
    return func_msg.err;
}

/**
 * @brief 执行工作函数
 */
static net_err_t do_func(func_msg_t* func_msg) {
    dbg_info(DBG_MSG, "2.calling func");
    //实现 线程安全 的函数调用，核心线程统一执行共享资源相关操作
    //func_msg->func 是调用者通过 exmsg_func_exec() 提交给核心线程的函数指针
    func_msg->err = func_msg->func(func_msg);
    //核心线程执行完函数后，释放等待的信号量
    sys_sem_notify(func_msg->wait_sem);
    dbg_info(DBG_MSG, "3.func exec complete");
    return NET_ERR_OK;
}

/**
 * @brief 核心线程通信初始化
 */
net_err_t exmsg_init(void) {
    dbg_info(DBG_MSG, "exmsg init");

    // 初始化消息队列
    net_err_t err = fixq_init(&msg_queue, msg_tbl, EXMSG_MSG_CNT, EXMSG_BLOCKER);
    if (err < 0) {
        dbg_error(DBG_MSG, "fixq init error");
        return err;
    }

    // 初始化消息分配器
    err = mblock_init(&msg_block, msg_buffer, sizeof(exmsg_t), EXMSG_MSG_CNT, EXMSG_BLOCKER);
    if (err < 0) {
        dbg_error(DBG_MSG,  "mblock init error");
        return err;
    }

    // 初始化完成
    dbg_info(DBG_MSG, "init done.");
    return NET_ERR_OK;
}

/**
 * @brief 核心线程功能体
 * 作用：消息调度循环 + 定时器处理
 * 逻辑：
1 等待消息到达队列，超时为下一个定时器触发时间
2 收到消息：
NET_EXMSG_NETIF_IN → 调用 do_netif_in
NET_EXMSG_FUN → 调用 do_func
3释放消息块
4计算时间差 → 调用 net_timer_check_tmo(diff_ms)
定时器事件和消息事件 统一调度
 */
static void work_thread (void * arg) {
    // 注意要加上\n。否则由于C库缓存的关系，字符串会被暂时缓存而不输出显示
    dbg_info(DBG_MSG, "exmsg is running....\n");

    // 先调用一下，以便获取初始时间
    net_time_t time;
    sys_time_curr(&time);

    int time_last = TIMER_SCAN_PERIOD;
    while (1) {
        // 有时间等待的等消息，这样就能够及时检查定时器也能同时检查定时消息
        int first_tmo = net_timer_first_tmo();
        exmsg_t* msg = (exmsg_t*)fixq_recv(&msg_queue, first_tmo);
        if (msg) {
            // 消息到了，打印提示
            dbg_info(DBG_MSG, "recieve a msg(%p): %d", msg, msg->type);
            switch (msg->type) {
            case NET_EXMSG_NETIF_IN:          // 网络接口消息
                do_netif_in(msg);
                break;
            case NET_EXMSG_FUN:               // API消息
                do_func(msg->func);
                break;
            }

            // 释放消息
            mblock_free(&msg_block, msg);
        }

        // 计算相比之前过去了多少时间
        int diff_ms = sys_time_goes(&time);
        time_last -= diff_ms;
        if (time_last < 0) {
            // 不准确，但是够用了，不需要那么精确
            net_timer_check_tmo(diff_ms);
            time_last = TIMER_SCAN_PERIOD;
       }
    }
}

/**
 * @brief 启动核心线程通信机制    初始化必须在协议栈开始前完成
 */
net_err_t exmsg_start(void) {
    // 创建核心线程
    sys_thread_t thread = sys_thread_create(work_thread, (void *)0);
    if (thread == SYS_THREAD_INVALID) {
        return NET_ERR_SYS;
    }

    return NET_ERR_OK;
}


/*
┌───────────────────────────┐
│       事件产生             │
│  1. 网卡收到数据           │
│  2. 上层 API 调用          │
└─────────────┬─────────────┘
              │
              ▼
┌───────────────────────────┐
│    分配消息结构 exmsg_t    │
│  mblock_alloc(&msg_block)  │
└─────────────┬─────────────┘
              │
              ▼
┌───────────────────────────┐
│       消息入队             │
│  fixq_send(&msg_queue, msg)│
└─────────────┬─────────────┘
              │
              ▼
┌───────────────────────────┐
│      核心线程循环          │
│  work_thread()             │
│  while(1)                  │
│  - 等待消息或定时器超时    │
└─────────────┬─────────────┘
              │
              ▼
┌───────────────────────────┐
│      消息处理              │
│  消息类型判断:             │
│  - NET_EXMSG_NETIF_IN → do_netif_in() │
│  - NET_EXMSG_FUN → do_func()         │
└─────────────┬─────────────┘
              │
              ▼
┌───────────────────────────┐
│      消息处理完成回收       │
│  mblock_free(&msg_block, msg) │
│  func_msg → sys_sem_notify(wait_sem) │
└─────────────┬─────────────┘
              │
              ▼
┌───────────────────────────┐
│  定时器检查与触发          │
│  net_timer_check_tmo(diff_ms) │
└───────────────────────────┘


1 事件产生：
网络数据到达或 API 调用产生消息
分配消息结构：
从 msg_buffer 池分配 exmsg_t 消息块
2 消息入队：
使用固定长度队列 fixq 安全入队
核心线程循环：
等待消息或定时器超时
轮询处理消息和触发定时器
3 消息处理：
网卡消息 → 处理数据包（链路层/IPv4）
API 消息 → 执行函数
4 消息回收：
消息处理完成 → 释放消息块
同步函数调用 → 释放等待信号量
5定时器触发：
每次循环根据时间差检查定时器，触发事件
*/