#include "nlocker.h"

/**
 * 初始化资源锁
 * 功能：创建底层互斥锁，并记录锁类型
重点：
type 决定使用哪种锁（目前线程锁）
错误处理：创建失败返回 NET_ERR_SYS

与 fixq 的关系：
fixq 在初始化时调用，用来保护队列操作的并发安全
 */
net_err_t nlocker_init(nlocker_t * locker, nlocker_type_t type) {
    if (type == NLOCKER_THREAD) {
        /*sys_mutex_t 是系统抽象层的互斥锁类型
返回值：有效锁对象 → 指针 失败 → SYS_MUTEX_INVALID*/
        sys_mutex_t mutex = sys_mutex_create();
        if (mutex == SYS_MUTEx_INVALID) {
            return NET_ERR_SYS;
        }
        //将创建的系统锁对象 保存到 nlocker_t 结构中
        locker->mutex = mutex;
    }

    locker->type = type;
    return NET_ERR_OK;
}

/**
 * @brief 销毁锁
 * 功能：释放底层互斥锁资源
注意：
必须在锁不再使用时调用
避免资源泄漏
 */
void nlocker_destroy(nlocker_t * locker) {
    if (locker->type == NLOCKER_THREAD) {
        sys_mutex_free(locker->mutex);
    }
}

/**
 * @brief 上锁
 */
void nlocker_lock(nlocker_t * locker) {
    if (locker->type == NLOCKER_THREAD) {
        sys_mutex_lock(locker->mutex);
    }
}

/**
 * @brief 解锁
 */
void nlocker_unlock(nlocker_t * locker) {
    if (locker->type == NLOCKER_THREAD) {
        sys_mutex_unlock(locker->mutex);
    } 
}

/*锁类型
目前只有线程锁 (NLOCKER_THREAD)
如果未来扩展，比如中断锁、轻量信号量，可以通过 type 增加实现
锁粒度
锁保护的资源必须尽量小，避免阻塞其他任务
fixq 中每次操作都加锁解锁，保证最小临界区
资源管理
初始化必须成功才能使用
销毁必须在不再使用锁时调用
配合其他模块
fixq、pktbuf 等多任务共享数据结构依赖 nlocker 保证安全*/