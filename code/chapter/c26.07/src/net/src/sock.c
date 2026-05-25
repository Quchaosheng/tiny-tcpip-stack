/**
 * 提供基本的sock结构，用于实现RAW/TCP/UDP等接口的操作的底层支持
 */
#include "sock.h"
#include "socket.h"
#include "dbg.h"
#include "raw.h"
#include "udp.h"
#include "tcp.h"

#define SOCKET_MAX_NR		(TCP_MAX_NR + UDP_MAX_NR + RAW_MAX_NR)
//SOCKET_MAX_NR：定义了最大支持的 socket 数量，计算为 TCP、UDP 和 RAW 协议的总和
static x_socket_t socket_tbl[SOCKET_MAX_NR];          // 空闲socket表

/**
 * @brief 将socket指针转换为socket索引
 */
static inline int get_index(x_socket_t* socket) {
    return (int)(socket - socket_tbl);
}

/**
 * @brief 将索引转换成结构
 */
static inline x_socket_t* get_socket(int idx) {
    // 做一些必要性的检查，以便参数不正确时，不用浪费消息传递
    if ((idx < 0) || (idx >= SOCKET_MAX_NR)) {
        return (x_socket_t*)0;
    }

    x_socket_t* s = socket_tbl + idx;
    return s;
}

/**
 * @brief 分配一个socket结构
 */
static x_socket_t * socket_alloc (void) {
    x_socket_t * s = (x_socket_t *)0;

    // 遍历整个列表，找空闲项
    for (int i = 0; i < SOCKET_MAX_NR; i++) {
        x_socket_t * curr = socket_tbl + i;
        if (curr->state == SOCKET_STATE_FREE) {
            s = curr;
            s->state = SOCKET_STATE_USED;
            break;
        }
    }

    return s;
}

/**
 * @brief 释放socket
 * 释放后会将 socket 状态重置为 SOCKET_STATE_FREE，确保后续可以再次使用该 slot
 */
static void socket_free(x_socket_t* s) {
    s->state = SOCKET_STATE_FREE;
}

/**
 * @brief socket层初始化
 */
net_err_t socket_init(void) {
    plat_memset(socket_tbl, 0, sizeof(socket_tbl));
    return NET_ERR_OK;
}

/**
 * @brief 初始化等待结构
 * 初始化等待结构，用来同步等待事件（如连接完成、数据发送完成等）
 */
net_err_t sock_wait_init (sock_wait_t * wait) {
    wait->waiting = 0;
    wait->sem = sys_sem_create(0);
    return wait->sem == SYS_SEM_INVALID ? NET_ERR_SYS : NET_ERR_OK;
}

/**
 * @brief 销毁等待结构
 */
void sock_wait_destroy (sock_wait_t * wait) {
    if (wait->sem != SYS_SEM_INVALID) {
        sys_sem_free(wait->sem);
    }
}

/**
 * @brief 进入等待状态
 */
net_err_t sock_wait_enter (sock_wait_t * wait, int tmo) {
    if (sys_sem_wait(wait->sem, tmo) < 0) {
	    return NET_ERR_TMO;
    }

    return wait->err;
}

/**
 * @brief 设置需要等待
 * @param wait
 */
void sock_wait_add (sock_wait_t * wait, int tmo, struct _sock_req_t * req) {
    req->wait = wait;
    req->wait_tmo = tmo;
    wait->waiting++;
}

/**
 * @brief 退出等待状态
 */
void sock_wait_leave (sock_wait_t * wait, net_err_t err) {
    if (wait->waiting > 0) {
        wait->waiting--;    // 减少等待计数
        wait->err = err;
        sys_sem_notify(wait->sem);// 用于通知等待中的任务或线程  
    }
}

/**
 * @brief 通知指定类型的任务某种事件发生(err指定)
 */
void sock_wakeup (sock_t * sock, int type, int err) {
    if (type & SOCK_WAIT_CONN) {
        sock_wait_leave(sock->conn_wait, err);
    }

    if (type & SOCK_WAIT_WRITE) {
        sock_wait_leave(sock->snd_wait, err);
    }

    if (type & SOCK_WAIT_READ) {
        sock_wait_leave(sock->rcv_wait, err);
    }
    sock->err = err;
}

/**
 * @brief 初始化sock结构
 * 根据不同的协议对sock做不同的初始化
 */
net_err_t sock_init(sock_t* sock, int family, int protocol, const sock_ops_t * ops) {
	sock->protocol = protocol;
	sock->ops = ops;

    sock->family = family;
	ipaddr_set_any(&sock->local_ip);
	ipaddr_set_any(&sock->remote_ip);
	sock->local_port = 0;
	sock->remote_port = 0;
	sock->err = NET_ERR_OK;
	sock->rcv_tmo = 0;
    sock->snd_tmo = 0;
	nlist_node_init(&sock->node);

    sock->conn_wait = (sock_wait_t *)0;
    sock->snd_wait = (sock_wait_t *)0;
    sock->rcv_wait = (sock_wait_t *)0;
	return NET_ERR_OK;
}

/**
 * @brief 回收释放sock相关资源，但不包含sock本身
 */
void sock_uninit (sock_t * sock) {
    if (sock->snd_wait) {
	    sock_wait_destroy(sock->snd_wait);
    }

    if (sock->rcv_wait) {
        sock_wait_destroy(sock->rcv_wait);
    }

    if (sock->conn_wait) {
        sock_wait_destroy(sock->conn_wait);
    }
}

/**
 * @brief 创建一个tcp socket
 * 根据不同的协议类型（RAW、UDP、TCP）来创建对应的 socket 并初始化
 */
net_err_t sock_create_req_in(func_msg_t* api_msg) {
    static const struct sock_info_t {
        int protocol;			// 缺省的协议
        sock_t* (*create) (int family, int protocol);
    }  sock_tbl[] = {
        [SOCK_RAW] = { .protocol = 0, .create = raw_create,},
        [SOCK_DGRAM] = { .protocol = IPPROTO_UDP, .create = udp_create,},
        [SOCK_STREAM] = {.protocol = IPPROTO_TCP,  .create = tcp_create,},
    };

	sock_req_t * req = (sock_req_t *)api_msg->param;
	sock_create_t * param = &req->create;

    // 分配socket结构，建立连接
    x_socket_t * socket = socket_alloc();
    if (socket == (x_socket_t *)0) {
        dbg_error(DBG_SOCKET, "no socket");
        return NET_ERR_MEM;
    }

    // 对type参数进行检查
    //param->type 表示传入的 socket类型  
    // param->type >= sizeof(sock_tbl) / sizeof(sock_tbl[0])：确保 type 不超过 sock_tbl 数组中元素的个数。
    //sock_tbl 是一个存储协议信息的数组。数组是按索引顺序存储协议处理信息的。超出范围会导致数组越界访问，可能导致程序崩溃或不稳定
    if ((param->type < 0) || (param->type >= sizeof(sock_tbl) / sizeof(sock_tbl[0]))) {
        dbg_error(DBG_SOCKET, "unknown type: %d", param->type);
        socket_free(socket);
        return NET_ERR_PARAM;
    }

    // 根据协议，创建底层sock, 未指定协议，使用缺省的
    const struct sock_info_t* info = sock_tbl + param->type;
    if (param->protocol == 0) {
        param->protocol = info->protocol;
    }

	// 根据类型创建不同的socket
	sock_t * sock = info->create(param->family, param->protocol);
	if (!sock) {
        dbg_error(DBG_SOCKET, "create sock failed, type: %d", param->type);
        socket_free(socket);
		return NET_ERR_MEM;
	}

    socket->sock = sock;
    req->sockfd = get_index(socket);
    return NET_ERR_OK;
}

/**
 * @brief 释放掉sock
 */
net_err_t sock_close_req_in (func_msg_t* api_msg) {
	sock_req_t * req = (sock_req_t *)api_msg->param;
    x_socket_t* s = get_socket(req->sockfd);
    if (!s) {
        dbg_error(DBG_SOCKET, "param error: socket = %d.", s);
        return NET_ERR_PARAM;
    }
    sock_t* sock = s->sock;

    // 等待结构有效时，调用者需要等待
    net_err_t err = sock->ops->close(sock);
    if (err == NET_ERR_NEED_WAIT) {
        sock_wait_add(sock->conn_wait, sock->rcv_tmo, req);
        return err;
    }

    // 注意释放掉socket
    socket_free(s);
    return err;
}

/**
 * @brief 强制销毁TCP
 */
net_err_t sock_destroy_req_in (func_msg_t* api_msg) {
	sock_req_t * req = (sock_req_t *)api_msg->param;
    x_socket_t* s = get_socket(req->sockfd);
    if (!s) {
        dbg_error(DBG_SOCKET, "param error: socket = %d.", s);
        return NET_ERR_PARAM;
    }
    sock_t* sock = s->sock;

    // 强制销毁
    sock->ops->destroy(sock);
    socket_free(s);
    return NET_ERR_OK;
}

/**
 * @breif 连接到远程主机
 * 缺省的实现函数
 */
net_err_t sock_connect(sock_t* sock, const struct x_sockaddr* addr, x_socklen_t len) {
    struct x_sockaddr_in* remote = (struct x_sockaddr_in*)addr;

    // 基本的方法是设置好IP地址和端口号
    ipaddr_from_buf(&sock->remote_ip, remote->sin_addr.addr_array);
    sock->remote_port = x_ntohs(remote->sin_port);
    return NET_ERR_OK;
}

/**
 * @breif 连接到远程主机
 * 关键性：处理 socket 连接请求。连接过程涉及到将远程 IP 地址和端口号配置到 socket，
 * 并根据需要进行等待操作（例如等待连接完成）。
标注：与远程主机建立连接时，这个函数会触发连接操作，并在需要时将任务加入等待队列。
 */
net_err_t sock_connect_req_in (func_msg_t* api_msg) {
	sock_req_t * req = (sock_req_t *)api_msg->param;
    x_socket_t* s = get_socket(req->sockfd);
    if (!s) {
        dbg_error(DBG_SOCKET, "param error: socket = %d.", s);
        return NET_ERR_PARAM;
    }
    sock_t* sock = s->sock;
	sock_conn_t * conn = &req->conn;

    net_err_t err = sock->ops->connect(sock, conn->addr, conn->len);
    if (err == NET_ERR_NEED_WAIT) {
        if (sock->conn_wait) {
            sock_wait_add(sock->conn_wait, sock->rcv_tmo, req);
        }
    }
    return err;
}

/**
 * @brief 绑定本地地址和端口
 * 这里只是提供基础的检查和设置功能
 */
net_err_t sock_bind(sock_t* sock, const struct x_sockaddr* addr, x_socklen_t len) {
    ipaddr_t local_ip;
    struct x_sockaddr_in* local = (struct x_sockaddr_in*)addr;
    ipaddr_from_buf(&local_ip, local->sin_addr.addr_array);

    if (!ipaddr_is_any(&local_ip)) {
        // 检查是否存在相应的本地接口
        rentry_t * rt = rt_find(&local_ip);
        if (!ipaddr_is_equal(&rt->netif->ipaddr, &local_ip)) {
            dbg_error(DBG_SOCKET, "addr error");
            return NET_ERR_PARAM;
        }
    }

    // 对于bind而言，其地址仅用于发送IP包时，填入IP包的源IP地址
    ipaddr_copy(&sock->local_ip, &local_ip);
	sock->local_port = x_ntohs(local->sin_port);
    return NET_ERR_OK;
}

/**
 * @brief 绑定事件处理
 */
net_err_t sock_bind_req_in(func_msg_t * api_msg) {
	sock_req_t * req = (sock_req_t *)api_msg->param;
    x_socket_t* s = get_socket(req->sockfd);
    if (!s) {
        dbg_error(DBG_SOCKET, "param error: socket = %d.", s);
        return NET_ERR_PARAM;
    }
    sock_t* sock = s->sock;
	sock_bind_t * bind = (sock_bind_t *)&req->bind;

    // 直接调用底层的
    return sock->ops->bind(sock, bind->addr, bind->len);
}

/**
 * @brief 发送数据包
 * 这样RAW和UDP就不用再实现自己的send接口，直接用这个就可以了
 */
net_err_t sock_sendto_req_in (func_msg_t * api_msg) {
	sock_req_t * req = (sock_req_t *)api_msg->param;
    x_socket_t* s = get_socket(req->sockfd);
    if (!s) {
        dbg_error(DBG_SOCKET, "param error: socket = %d.", s);
        return NET_ERR_PARAM;
    }
    sock_t* sock = s->sock;
	sock_data_t * data = (sock_data_t *)&req->data;

    // 判断是否已经实现
    //sock->ops->sendto 是当前协议（如 TCP、UDP 或 RAW）提供的发送数据的操作函数
    //sendto 函数用于将数据发送到指定的目标地址和端口。它是网络通信中的基础操作，常用于发送 UDP 数据包、RAW 包，或其他协议的数据
    if (!sock->ops->sendto) {
        dbg_error(DBG_SOCKET, "this function is not implemented");
        return NET_ERR_NOT_SUPPORT;
    }

    net_err_t err = sock->ops->sendto(sock, data->buf, data->len, data->flags,
                                data->addr, *data->addr_len, &req->data.comp_len);
    if (err == NET_ERR_NEED_WAIT) {
        if (sock->snd_wait) {
            sock_wait_add(sock->snd_wait, sock->snd_tmo, req);
        }
    }
    return err;
}

/**
 * @brief 接收数据包
 * 负责接收来自指定地址的数据，如果协议支持接收数据，就会调用协议的 recvfrom 函数。
 */
net_err_t sock_recvfrom_req_in(func_msg_t * api_msg) {
	sock_req_t * req = (sock_req_t *)api_msg->param;
    x_socket_t* s = get_socket(req->sockfd);
    if (!s) {
        dbg_error(DBG_SOCKET, "param error: socket = %d.", s);
        return NET_ERR_PARAM;
    }
    sock_t* sock = s->sock;
	sock_data_t * data = (sock_data_t *)&req->data;


    // 判断是否已经实现
    if (!sock->ops->recvfrom) {
        dbg_error(DBG_SOCKET, "this function is not implemented");
        return NET_ERR_NOT_SUPPORT;
    }

	net_err_t err = sock->ops->recvfrom(sock, data->buf, data->len, data->flags,
                        data->addr, data->addr_len, &req->data.comp_len);
    if (err == NET_ERR_NEED_WAIT) {
        if (sock->rcv_wait) {
            sock_wait_add(sock->rcv_wait, sock->rcv_tmo, req);
        }
    }
    return err;
}

/**
 * @brief 设置sock的选项
 * 负责设置 socket 的选项（如接收超时、发送超时）。这些选项对网络连接的超时控制非常重要，影响数据传输的时效性。
标注：主要关注 SO_RCVTIMEO 和 SO_SNDTIMEO，它们控制 socket 的接收和发送超时。
 */
net_err_t sock_setopt(struct _sock_t* sock,  int level, int optname, const char * optval, int optlen) {
	// 选项不支持
	if (level != SOL_SOCKET) {
		//dbg_error(DBG_SOCKET, "unknow level: %d", level);
        return NET_ERR_UNKNOW;
	}
//optname 代表了你要设置的 socket 选项，比如：SO_RCVTIMEO：接收超时，控制等待接收数据的最长时间。 SO_SNDTIMEO：发送超时，控制等待发送数据的最长时间。
    switch (optname) {
    case SO_RCVTIMEO:
    case SO_SNDTIMEO: {
        if (optlen != sizeof(struct x_timeval)) {
            dbg_error(DBG_SOCKET, "time size error");
            return NET_ERR_PARAM;
        }

        // 设置时间，只纪录下发送时间
        //将 optval 强制转换为 struct x_timeval * 类型，指向超时结构体，便于访问其中的 tv_sec 和 tv_usec 字段
        struct x_timeval * time = (struct x_timeval *)optval;
        //得到总超时时间
        int time_ms = time->tv_sec * 1000 + time->tv_usec / 1000;
        if (optname == SO_RCVTIMEO) {
            sock->rcv_tmo = time_ms;
            return NET_ERR_OK;
        } else if (optname == SO_SNDTIMEO) {
            sock->snd_tmo = time_ms;
            return NET_ERR_OK;
        } else {
            return NET_ERR_UNKNOW;
        }
    }
    default:
        break;
    }

    // 选项不支持
    return NET_ERR_UNKNOW;
}

/**
 * @brief 设置opt选项消息
 */
net_err_t sock_setsockopt_req_in(func_msg_t * api_msg) {
	sock_req_t * req = (sock_req_t *)api_msg->param;
    x_socket_t* s = get_socket(req->sockfd);
    if (!s) {
        dbg_error(DBG_SOCKET, "param error: socket = %d.", s);
        return NET_ERR_PARAM;
    }
    sock_t* sock = s->sock;
	sock_opt_t * opt = (sock_opt_t *)&req->opt;

    // 直接调用底层的
    return sock->ops->setopt(sock, opt->level, opt->optname, opt->optval, opt->optlen);
}

/**
 * @brief 发送数据包
 * 缺省的实现函数
 */
net_err_t sock_send (struct _sock_t * sock, const void* buf, size_t len, int flags, ssize_t * result_len) {
	// 目的IP地址不能为空，当然也可以做更多检查
	if (ipaddr_is_any(&sock->remote_ip)) {
		dbg_error(DBG_RAW, "dest ip is empty.");
        return NET_ERR_UNREACH;
	}

	struct x_sockaddr_in dest;
	dest.sin_family = sock->family;
	dest.sin_port = x_htons(sock->remote_port);
	ipaddr_to_buf(&sock->remote_ip, (uint8_t*)&dest.sin_addr);

	// 从之前绑定的地址中取地址和端口号，转换地址后，然后发往该地址
	return sock->ops->sendto(sock, buf, len, flags, (const struct x_sockaddr *)&dest, sizeof(dest), result_len);
}

/**
 * @brief 发送数据包
 * 这样RAW和UDP就不用再实现自己的send接口，直接用这个就可以了
 */
net_err_t sock_send_req_in (func_msg_t * api_msg) {
	sock_req_t * req = (sock_req_t *)api_msg->param;
    x_socket_t* s = get_socket(req->sockfd);
    if (!s) {
        dbg_error(DBG_SOCKET, "param error: socket = %d.", s);
        return NET_ERR_PARAM;
    }
    sock_t* sock = s->sock;
	sock_data_t * data = (sock_data_t *)&req->data;

    sock->err = NET_ERR_OK;
    net_err_t err = sock->ops->send(sock, data->buf, data->len, data->flags, &req->data.comp_len);
    if (err == NET_ERR_NEED_WAIT) {
        if (sock->snd_wait) {
            sock_wait_add(sock->snd_wait, sock->snd_tmo, req);
        }
    }
    return err;
}

/**
 * @brief 读取数据包
 * 缺省的实现函数
 */
net_err_t sock_recv (struct _sock_t * sock, void* buf, size_t len, int flags, ssize_t * result_len) {
	// 必须绑定
	if (ipaddr_is_any(&sock->remote_ip)) {
		dbg_error(DBG_RAW, "src ip is empty.socket is not connected");
		return NET_ERR_PARAM;
	}

    struct x_sockaddr src;
    x_socklen_t addr_len;
	return sock->ops->recvfrom(sock, buf, len, flags, &src, &addr_len, result_len);
}

/**
 * @brief 读取数据包
 * 这样RAW和UDP就不用再实现自己的recv接口，直接用这个就可以了
 */
net_err_t sock_recv_req_in(func_msg_t * api_msg) {
	sock_req_t * req = (sock_req_t *)api_msg->param;
    x_socket_t* s = get_socket(req->sockfd);
    if (!s) {
        dbg_error(DBG_SOCKET, "param error: socket = %d.", s);
        return NET_ERR_PARAM;
    }
    sock_t* sock = s->sock;
	sock_data_t * data = (sock_data_t *)&req->data;

	net_err_t err = sock->ops->recv(sock, data->buf, data->len, data->flags, &req->data.comp_len);
    if (err == NET_ERR_NEED_WAIT) {
        if (sock->rcv_wait) {
            sock_wait_add(sock->rcv_wait, sock->rcv_tmo, req);
        }
    }

    return err;
}

/**
 * @brief 绑定事件处理
 * sock_listen_req_in 使 socket 进入监听状态，等待客户端连接
 */
net_err_t sock_listen_req_in(func_msg_t * api_msg) {
	sock_req_t * req = (sock_req_t *)api_msg->param;
    x_socket_t* s = get_socket(req->sockfd);
    if (!s) {
        dbg_error(DBG_SOCKET, "param error: socket = %d.", s);
        return NET_ERR_PARAM;
    }
    sock_t* sock = s->sock;
	sock_listen_t * listen = (sock_listen_t *)&req->listen;

    // 直接调用底层的
    // 判断是否已经实现
    if (!sock->ops->listen) {
        dbg_error(DBG_SOCKET, "this function is not implemented");
        return NET_ERR_NOT_SUPPORT;
    }
    return sock->ops->listen(sock, listen->backlog);
}

/**
 * @brief 接收连接的处理
 * sock_accept_req_in 接受客户端连接并创建一个新的子 socket 来处理该连接
 * 1获取请求参数：
从 api_msg 中提取 sock_req_t 和 sock_accept_t，获取目标 socket 和客户端的地址信息。
2 检查 socket 是否有效：
如果 get_socket(req->sockfd) 返回空（无效），则输出错误并返回 NET_ERR_PARAM。
3 检查是否实现 accept 函数：
如果当前 socket 的协议层没有实现 accept 函数，返回 NET_ERR_NOT_SUPPORT。
4执行连接接受操作：
调用协议层的 accept 函数来接受连接请求。
如果 accept 返回错误，打印错误并返回该错误。
如果 accept 返回 NET_ERR_NEED_WAIT，表示需要等待连接完成，加入等待队列。
如果连接成功，分配一个新的子 socket 来处理该连接。
5返回结果：
将新的子 socket 的索引（child_socket）返回给客户端，完成连接建立。
分配 子 socket 是非常必要的，原因如下：

1. 每个连接都需要一个独立的 socket
在服务器端，每个客户端连接都需要一个独立的 socket 来进行后续的通信。
如果服务器同时处理多个客户端连接，使用子 socket是非常重要的。
每个子 socket 用于与特定客户端的通信，并且能够独立地处理数据的发送与接收。
原因：
并发处理：如果每个客户端连接共享同一个 socket，那么服务器将无法同时与多个客户端进行交互。这会导致 阻塞 和 效率低下。
独立通信：每个客户端都需要独立的 socket 来发送和接收数据。子 socket 可以专门用于与该客户端的通信，而不影响其他客户端。
2. 监听和处理不同的客户端
监听 socket：服务器会有一个监听用的 socket，负责等待客户端的连接请求。
子 socket：当客户端成功连接时，accept 操作会返回一个新的 socket，这个新的 socket 被称为 子 socket，专门用于和该客户端进行数据通信。
 */
net_err_t sock_accept_req_in(func_msg_t * api_msg) {
	sock_req_t * req = (sock_req_t *)api_msg->param;
    x_socket_t* s = get_socket(req->sockfd);
    if (!s) {
        dbg_error(DBG_SOCKET, "param error: socket = %d.", s);
        return NET_ERR_PARAM;
    }
    sock_t* sock = s->sock;
	sock_accept_t * accept = (sock_accept_t *)&req->accept;

    // 直接调用底层的
    // 判断是否已经实现
    if (!sock->ops->accept) {
        dbg_error(DBG_SOCKET, "this function is not implemented");
        return NET_ERR_NOT_SUPPORT;
    }

    // 取一个已经连接的块。如果没有，client不变，返回0
    sock_t * client = (sock_t *)0;
    net_err_t err = sock->ops->accept(sock, accept->addr, accept->len, &client);
    if (err < 0) {
        dbg_error(DBG_SOCKET, "accept error: %d", err);
        return err;
    } else if (err == NET_ERR_NEED_WAIT) {
        // 加入等待，方便任务等
        if (sock->conn_wait) {
            sock_wait_add(sock->conn_wait, sock->rcv_tmo, req);
        }
    } else {
        // 为子sock分配socket
        x_socket_t * child_socket = socket_alloc();
        if (child_socket == (x_socket_t *)0) {
            dbg_error(DBG_SOCKET, "no socket");
            return NET_ERR_NONE;
        }
        child_socket->sock = client;

        // 设置返回结果
        accept->client = get_index(child_socket);
    }
    return NET_ERR_OK;
}

/*以下是这段代码中需要特别注意的关键点，帮助你更好地理解其实现：

### 1. **Socket 管理的细节**

* **Socket 表 (`socket_tbl`) 的管理**：所有的 socket 被保存在一个固定大小的数组 `socket_tbl` 中。这个数组的大小是通过 `SOCKET_MAX_NR` 来定义的，它是所有协议类型的最大 socket 数量（TCP、UDP、RAW 协议的最大数量之和）。
* **`socket_alloc` 和 `socket_free`**：这两个函数用于动态管理 socket 的分配和释放。`socket_alloc` 会遍历 `socket_tbl` 查找一个空闲的 slot 来分配新 socket，`socket_free` 会释放已使用的 socket。

### 2. **异步等待机制**
* **等待结构 (`sock_wait_t`)**：用于处理异步操作，例如等待连接、发送或接收数据。每个 `sock_t` 可能有一个等待结构，管理这些操作的同步。
* **`sock_wait_init`、`sock_wait_add`、`sock_wait_enter`、`sock_wait_leave`**：这些函数用于管理等待的事件。具体来说，`sock_wait_add` 将请求添加到等待队列，`sock_wait_enter` 使调用线程进入等待状态，直到操作完成或超时，`sock_wait_leave` 用来通知线程操作完成，解除等待状态。

### 3. **Socket 操作的协议相关性**

* **协议类型的处理**：通过 `sock_create_req_in` 函数，根据不同的协议类型（RAW、UDP、TCP），动态创建不同类型的 socket。每个协议都有其特定的操作函数（如 `raw_create`、`udp_create`、`tcp_create`）。
* **协议创建的抽象**：通过 `sock_info_t` 结构体，统一了不同协议的创建函数，每种协议对应的 `create` 函数会根据协议类型初始化一个新的 socket。

### 4. **Socket 的关闭与销毁**

* **`sock_close_req_in`**：关闭 socket 时，如果需要等待某些操作完成（例如连接建立），则会将请求添加到等待队列中。关闭操作在执行时会调用协议层的 `close` 操作。
* **`sock_destroy_req_in`**：强制销毁 socket 时，会调用协议层的 `destroy` 操作并释放相关资源。
* **资源清理 (`sock_uninit`)**：在销毁 socket 时，会释放与其相关的等待结构（如连接等待、发送等待、接收等待）。

### 5. **Socket 的连接和绑定**

* **`sock_connect` 和 `sock_connect_req_in`**：连接远程主机时，主要是将远程主机的 IP 地址和端口号设置到 socket 中。`sock_connect_req_in` 处理连接请求，并支持等待（如果需要）。
* **`sock_bind` 和 `sock_bind_req_in`**：绑定本地地址和端口时，会检查本地网络接口是否存在，并将 socket 的本地 IP 地址和端口设置好。

### 6. **数据发送与接收**

* **`sock_sendto_req_in` 和 `sock_recvfrom_req_in`**：这两个函数处理数据的发送和接收。如果数据包发送或接收操作没有实现，代码会提示 `NET_ERR_NOT_SUPPORT` 错误。
* **`sock_send` 和 `sock_recv`**：这两个函数分别为发送和接收数据的默认实现。它们会先检查目标地址是否有效（如 `sock_send` 会检查目标 IP 是否为空）。

### 7. **Socket 选项的设置**

* **`sock_setopt`**：设置 socket 的各种选项（如接收超时、发送超时）。其中，接收超时和发送超时是通过 `struct x_timeval` 类型的参数来设置的，单位是毫秒。
* **`sock_setsockopt_req_in`**：处理设置 socket 选项的请求，调用 `sock_setopt` 完成实际的设置操作。

### 8. **事件通知机制**
* **`sock_wakeup`**：用于通知正在等待的任务，某个事件已经发生（如连接成功或数据准备好）。它会根据不同的事件类型（连接、写操作、读操作）唤醒相关的等待任务。

### 9. **错误处理**
* **错误码的使用**：错误通过返回的 `net_err_t` 错误码来表示。常见的错误有 `NET_ERR_OK`（成功），`NET_ERR_PARAM`（参数错误），`NET_ERR_MEM`（内存不足），`NET_ERR_TMO`（超时），`NET_ERR_UNKNOW`（未知错误）等。
* **超时处理**：在某些操作（如连接、发送、接收）时，可能需要等待外部事件完成，这时会使用超时机制（例如，`sock_wait_enter` 和 `sock_wait_leave` 配合使用）。

### 10. **内存与资源管理**

* **内存分配与释放**：通过 `socket_alloc` 和 `socket_free` 管理 socket 结构体的内存分配与释放，确保不会发生内存泄漏。
* **等待结构的内存管理**：每个等待结构（如连接、发送、接收）都需要在操作完成后销毁，避免资源泄漏。`sock_wait_destroy` 用于释放等待结构相关的资源。

### 11. **协议操作的具体实现**

* **协议层操作**：每个协议（TCP、UDP、RAW）都有自己特定的操作接口（如 `raw_create`、`udp_create`、`tcp_create` 等），这些操作是通过 `sock_ops_t` 结构体提供的。每个协议的 `ops` 都包含了相应的实现函数。

### 总结：

* **通用性与扩展性**：代码通过对 socket 操作的封装和抽象，支持多种协议（RAW、TCP、UDP），并且每种协议有自己独立的操作。
* **异步与同步机制**：代码采用了信号量和等待队列来实现任务的同步，支持异步操作（如连接、发送、接收等）。
* **资源管理**：重点注意 socket 和等待结构的内存管理，避免内存泄漏。

这些关键点涵盖了 socket 管理、协议操作、资源清理、等待机制、数据传输等方面，是理解和使用这段代码的基础。
*/