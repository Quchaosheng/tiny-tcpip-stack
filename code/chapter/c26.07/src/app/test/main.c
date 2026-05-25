
#include <string.h>
#include "netif_pcap.h"
#include "sys_plat.h"
#include "echo/tcp_echo_client.h"
#include "echo/tcp_echo_server.h"
#include "echo/udp_echo_client.h"
#include "echo/udp_echo_server.h"
#include "net.h"
#include "dbg.h"
#include "nlist.h"
#include "mblock.h"
#include "pktbuf.h"
#include "netif.h"
#include "tools.h"
#include "timer.h"
#include "ipv4.h"
#include "ping/ping.h"
#include "exmsg.h"


#include "netif_pcap.h"
//// pcap_data_t netdev0_data定义一个网卡设备对应的底层数据结构。
pcap_data_t netdev0_data = { .ip = netdev0_phy_ip, .hwaddr = netdev0_hwaddr };
//网卡设备真正怎么“打开、发送、接收”，由 netdev_ops 这组操作函数决定
extern const netif_ops_t netdev_ops;

/**
 * @brief 网络设备初始化
 */
net_err_t netdev_init(void) {    
    //帮我创建一个网卡对象，名字叫"netif 0"，这个网卡该怎么操作，由 netdev_ops 这套规则来决定，它的具体参数在 netdev0_data里
    netif_t* netif = netif_open("netif 0", &netdev_ops, &netdev0_data);
    if (!netif) {
        fprintf(stderr, "netif open failed.");
        exit(-1);
    }

    // 生成相应的地址
	//ipaddr_from_str(...)把字符串形式的 IP 地址（转换成协议栈内部使用的 IP 地址结构 ipaddr_t
	//网卡工作要知道三个信息ip 表示本机的ip 子网掩码用于判断 哪些 IP 在同一局域网 网关当访问 不在本局域网的地址时，要把包发给网关
    ipaddr_t ip, mask, gw;
    ipaddr_from_str(&ip, netdev0_ip);
    ipaddr_from_str(&mask, netdev0_mask);
    ipaddr_from_str(&gw, netdev0_gw);
	//把地址配置给网卡
    netif_set_addr(netif, &ip, &mask, &gw);

    // 激活网络接口
    netif_set_active(netif);

	// 测试发送
	// pktbuf_t * buf = pktbuf_alloc(131);		// 设置为奇数个
	// pktbuf_join(buf, pktbuf_alloc(45));
	// pktbuf_fill(buf, 0x34, buf->total_size);

	// ipaddr_t dest, src;
	// ipaddr_from_str(&dest, friend0_ip);
	// ipaddr_from_str(&src, netdev0_ip);
	// ipv4_out(0, &dest, &src, buf);

	// // 发送广播测试
	// ipaddr_from_str(&dest, "255.255.255.255");
	// buf = pktbuf_alloc(32);
	// pktbuf_fill(buf, 0xA5, buf->total_size);
	// netif_out(netif, &dest, buf);

    return NET_ERR_OK;
}

//tnode_t 和 nlist_test()：链表测试代码
typedef struct _tnode_t {
    int id;
    nlist_node_t node;
}tnode_t;

//测试链表操作是否正确 防止bug 需测试1.头插入2.尾插入3.删除节点4.遍历链表5.指定位置插入
void nlist_test (void) {
    #define NODE_CNT        8

    tnode_t node[NODE_CNT];
    nlist_t list;
    nlist_node_t * p;

    nlist_init(&list);

    // 头部插入
    for (int i = 0; i < NODE_CNT; i++) {
        node[i].id = i;
        nlist_insert_first(&list, &node[i].node);
    }

    // 遍历打印
    plat_printf("insert first\n");
    nlist_for_each(p, &list) {
		//已知 p 指向的是结构体里的 node 成员，反推出整个 tnode_t 对象的地址。
        tnode_t * tnode = nlist_entry(p, tnode_t, node);
        plat_printf("id:%d\n", tnode->id);
    }

    // 头部移除
    plat_printf("remove first\n");
    for (int i = 0; i < NODE_CNT; i++) {
        p = nlist_remove_first(&list);
        plat_printf("id:%d\n", nlist_entry(p, tnode_t, node)->id);
   }

    // 尾部插入
    for (int i = 0; i < NODE_CNT; i++) {
        nlist_insert_last(&list, &node[i].node);
    }

    // 遍历打印
    plat_printf("insert last\n");
    nlist_for_each(p, &list) {
        tnode_t * tnode = nlist_entry(p, tnode_t, node);
        plat_printf("id:%d\n", tnode->id);
    }

    // 尾部移除
    plat_printf("remove last\n");
    for (int i = 0; i < NODE_CNT; i++) {
        p = nlist_remove_last(&list);
        plat_printf("id:%d\n", nlist_entry(p, tnode_t, node)->id);
   }    

   // 插入到指定结点之后
    plat_printf("insert after\n");
    for (int i = 0; i < NODE_CNT; i++) {
        nlist_insert_after(&list, nlist_first(&list), &node[i].node);
    }

    // 遍历打印
    nlist_for_each(p, &list) {
        tnode_t * tnode = nlist_entry(p, tnode_t, node);
        plat_printf("id:%d\n", tnode->id);
    }
}

void mblock_test(void) {
	//固定块内存池好处：1.分配快 2.释放快 3.不容易产生内存碎片 4.行为可控
    static uint8_t buffer[10][100];
	mblock_t blist;

	mblock_init(&blist, buffer, 100, 10, NLOCKER_THREAD);
	void* temp[10];

	// 验证内存池的“申请 → 使用 → 释放”整个流程是否正确。
	for (int i = 0; i < 10; i++) {
		temp[i] = mblock_alloc(&blist, 0);
		printf("block: %p, free count:%d\n", temp[i], mblock_free_cnt(&blist));
	}
	for (int i = 0; i < 10; i++) {
		mblock_free(&blist, temp[i]);
		printf("free count:%d\n", mblock_free_cnt(&blist));
	}

	mblock_destroy(&blist);
}

//网络栈 
/*pktbuf   → 网络数据包
socket   → 套接字对象
tcp      → TCP连接控制块
udp      → UDP端口控制块
arp      → ARP缓存表
netif    → 网络接口（网卡）
timer    → 定时器*/
void pktbuf_test(void) {
	static uint16_t temp[1000];
	static uint16_t read_temp[1000];

    // 初始化数据空间
	for (int i = 0; i < 1024; i++) {
		temp[i] = i;
	}

    // 简单的分配和释放, 2000字节.注意打开pktbuf的显示，方便观察
	pktbuf_t * buf = pktbuf_alloc(2000);
	pktbuf_free(buf);

	// 添加头部空间
	buf = pktbuf_alloc(2000);

    // 要求连续的头部添加。最终可以到看，有些包的头部会有一些空间小于33
    // 由于空间不够，只能舍弃
	for (int i = 0; i < 16; i++) {
		pktbuf_add_header(buf, 33, 1);      // 连续的空间
	}
	for (int i = 0; i < 16; i++) {
		pktbuf_remove_header(buf, 33);      // 移除
	}

    // 与连续分配的要求相比，总的包数量小一些，且除第一个块外，其它
    // 块没有开头浪费的空间
	for (int i = 0; i < 16; i++) {
		pktbuf_add_header(buf, 33, 0);		// 非连续添加
	}
	for (int i = 0; i < 16; i++) {
		pktbuf_remove_header(buf, 33);
	}
	pktbuf_free(buf);

	// 大小的调整，先变大变小
	//变大：测试：1 是否能正确增加数据空间 2 是否能正确申请新的数据块 3 数据结构是否仍然正确
	//变小：测试：1 是否能正确释放多余的块 2链表结构是否正确更新 3 是否不会出现内存泄漏
	buf = pktbuf_alloc(0);  // 大小为0
	pktbuf_resize(buf, 32);
	pktbuf_resize(buf, 288);
	pktbuf_resize(buf, 4922);
	pktbuf_resize(buf, 1921);
	pktbuf_resize(buf, 288);
	pktbuf_resize(buf, 32);
	pktbuf_resize(buf, 0);
	pktbuf_free(buf);

	// 两个包的连接。在最终的显示结果中，可以看到两个包之间的连接交叉处
	buf = pktbuf_alloc(689);
	pktbuf_t * sbuf = pktbuf_alloc(892);
	//为什么不直接申请一个大的包？
	/*1.减少内存复制  避免大块连续内存   适合网络分段数据*/
	pktbuf_join(buf, sbuf);
	pktbuf_free(buf);

	// 小包的连接测试并调整连续性.先合并一些小的包，以形成很多个小包的连接
    // 然后再调整连续性，可以使链的连接在不断变短
	buf = pktbuf_alloc(32);
	pktbuf_join(buf, pktbuf_alloc(4));
	pktbuf_join(buf, pktbuf_alloc(16));
	pktbuf_join(buf, pktbuf_alloc(54));
	pktbuf_join(buf, pktbuf_alloc(32));
	pktbuf_join(buf, pktbuf_alloc(38));
	//尝试让前 44 字节变成连续内存。因为有些协议头解析时，需要前面若干字节是连续可直接访问的。
	//逐渐增加测试连续化能力的上限在哪里
	pktbuf_set_cont(buf, 44);			// 合并成功，簇变短
	pktbuf_set_cont(buf, 60);			// 合并成功，簇变短
	pktbuf_set_cont(buf, 64);			// 合并成功，簇变短
	pktbuf_set_cont(buf, 128);			// 合并成功，簇变短
	//协议栈里 单个数据块最大是 128 字节
	pktbuf_set_cont(buf, 135);			// 失败，超过128
	pktbuf_free(buf);

	// 准备一些不同大小的包链，方便后面读写测试
	buf = pktbuf_alloc(32);
	pktbuf_join(buf, pktbuf_alloc(4));
	pktbuf_join(buf, pktbuf_alloc(16));
	pktbuf_join(buf, pktbuf_alloc(54));
	pktbuf_join(buf, pktbuf_alloc(32));
	pktbuf_join(buf, pktbuf_alloc(38));
	pktbuf_join(buf, pktbuf_alloc(512));

    // 读写测试。写超过1包的数据，然后读取
	pktbuf_reset_acc(buf);
	//pktbuf_write pktbuf_read验证跨块写入、跨块读取后数据是否一致
	pktbuf_write(buf, (uint8_t *)temp, pktbuf_total(buf));      // 16位的读写
	plat_memset(read_temp, 0, sizeof(read_temp));
	pktbuf_reset_acc(buf);
	pktbuf_read(buf, (uint8_t*)read_temp, pktbuf_total(buf));
	if (plat_memcmp(temp, read_temp, pktbuf_total(buf)) != 0) {
		printf("not equal.");
		exit(-1);
	}

	// 定位读写，不超过1个块
	plat_memset(read_temp, 0, sizeof(read_temp));
	//pktbuf 有读写位置指针，能像流一样定位访问
	pktbuf_seek(buf, 18 * 2);
	pktbuf_read(buf, (uint8_t*)read_temp, 56);
	if (plat_memcmp(temp + 18, read_temp, 56) != 0) {
		printf("not equal.");
		exit(-1);
	}

    // 定位跨一个块的读写测试, 从170开始读，读56
	plat_memset(read_temp, 0, sizeof(read_temp));
	pktbuf_seek(buf, 85 * 2);
	pktbuf_read(buf, (uint8_t*)read_temp, 256);
	if (plat_memcmp(temp + 85, read_temp, 256) != 0) {
		printf("not equal.");
		exit(-1);
	}

	// 数据的复制
	pktbuf_t* dest = pktbuf_alloc(1024);
	pktbuf_seek(buf, 200);      // 从200处开始读
	pktbuf_seek(dest, 600);     // 从600处开始写
	pktbuf_copy(dest, buf, 122);    // 复制122个字节

    // 重新定位到600处开始读
	plat_memset(read_temp, 0, sizeof(read_temp));
	pktbuf_seek(dest, 600);
	pktbuf_read(dest, (uint8_t*)read_temp, 122);    // 读122个字节
	if (plat_memcmp(temp + 100, read_temp, 122) != 0) { // temp+100，实际定位到200字节偏移处
		printf("not equal.");
		exit(-1);
	}

	// 填充测试
	pktbuf_seek(dest, 0);
	pktbuf_fill(dest, 53, pktbuf_total(dest));

	plat_memset(read_temp, 0, sizeof(read_temp));
	pktbuf_seek(dest, 0);
	pktbuf_read(dest, (uint8_t*)read_temp, pktbuf_total(dest));
	for (int i = 0; i < pktbuf_total(dest); i++) {
		if (((uint8_t *)read_temp)[i] != 53) {
			printf("not equal.");
			exit(-1);
		}
	}

	pktbuf_free(dest);
	pktbuf_free(buf);       // 可以进去调试，在退出函数前看下所有块是否全部释放完毕
}

void timer0_proc(net_timer_t* timer, void * arg) {
	static int count = 1;
	printf("this is %s: %d\n", timer->name, count++);
}

void timer1_proc(net_timer_t* timer, void * arg) {
	static int count = 1;
	printf("this is %s: %d\n", timer->name, count++);
}

void timer2_proc(net_timer_t* timer, void * arg) {
	static int count = 1;
	printf("this is %s: %d\n", timer->name, count++);
}

void timer3_proc(net_timer_t* timer, void * arg) {
	static int count = 1;
	printf("this is %s: %d\n", timer->name, count++);
}

void timer_test(void) {
	static net_timer_t t0, t1, t2, t3;

	// 一次性定时器
	net_timer_add(&t0, "t0", timer0_proc, (void *)0, 200, 0);

	// 自动重载定时器
	net_timer_add(&t1, "t1", timer1_proc, (void *)0, 1000, NET_TIMER_RELOAD);
	net_timer_add(&t2, "t2", timer2_proc, (void *)0, 1000, NET_TIMER_RELOAD);
	net_timer_add(&t3, "t3", timer3_proc, (void *)0, 4000, NET_TIMER_RELOAD);
	net_timer_remove(&t1);
}

//在真正运行网络协议栈之前，先验证底层基础模块是否工作正常
void basic_test(void) {
    nlist_test();
    mblock_test();
    pktbuf_test();
//网络传输和计算机存储的字节顺序不同   网络协议规定：大端序   主机字节序 = 小端序 
//网络字节序 → 主机字节序
//ntohs = network to host short (16位) ntohl = network to host long  (32位)
	uint32_t v1 = x_ntohl(0x12345678);
	uint16_t v2 = x_ntohs(0x1234);

    timer_test();
}

void show_help (void) {
	printf("--------------- cmd list ------------------ \n");
	printf("1.ping dest(ip or name)\n");
}

void download_test (const char * filename, int port);



int main (void) {
    // 初始化协议栈
    net_init();

    // 基础测试
	//开发阶段会打开测试 功能稳定后就关闭
    //basic_test();

    // 初始化网络接口 注意顺序：先 net_init()再 netdev_init()
    netdev_init();
    
    // 启动协议栈
    net_start();

   // udp echo服务器  测试UDP 收发链路是否通了
   udp_echo_server_start(2000);

    // udp echo客户端     
    //udp_echo_client_start(friend0_ip, 1000);

	// TCP客户端 当前会主动作为 TCP 客户端，去连接对端 friend0_ip 的 1000 端口。
	tcp_echo_client_start(friend0_ip, 1000);

	// 下载测试，测试下载速度
	// download_test("hello.txt", 1000);

	// tcp server
	//tcp_echo_server_start(1000);

	//协议栈不只是支持直接 ping IP，还支持先解析域名再 ping
    ping_t p;
	//ping_run(&p, friend0_ip, 4, 64, 1000);    	// 邻居测试
	//ping_run(&p, "localhost", 1, 64, 1000);    	// google的DNS服务器
	//ping_run(&p, "8.8.8.8", 1, 64, 1000);    	// google的DNS服务器
	ping_run(&p, "baidu.com", 1, 64, 1000);    	// google的DNS服务器


	//把一个函数任务通过消息机制提交给协议栈核心线程执行
	int arg = 0x1234;
	exmsg_func_exec(test_func, (void *)&arg);

	char cmd[32], param[32];
    while (1) {
		show_help();
        printf(">>");
        scanf("%s %s", cmd, param);

        if (strcmp(cmd, "ping") == 0) {
            ping_run(&p, param, 4, 1000, 1000);
        }
    }
}
