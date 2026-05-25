/**
 * @file download.c
 * @author lishutong (527676163@qq.com)
 * @brief 简单的下载测试代码
 * @version 0.1
 * @date 2022-10-23
 *
 * @copyright Copyright (c) 2022
 * @note 该源码配套相应的视频课程，请见源码仓库下面的README.md
 */
#include <stdio.h>
#include <string.h>
#include "net_plat.h"
#include <WinSock2.h>
//#include "netapi.h"

/**
 * @brief 简单的从对方客户机进行下载，以便测试TCP接收
 */
void download_test (const char * filename, int port) {
    printf("try to download %s from %s: %d\n", filename, friend0_ip, port);

    // 创建服务器套接字，使用IPv4，数据流传输
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		printf("create socket error\n");
        goto failed;
	}

    FILE * file = fopen(filename, "wb");
    if (file == (FILE *)0) {
        printf("open file failed.\n");
        return;
    }

    // 绑定本地地址
    struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(friend0_ip);
    if (connect(sockfd, (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
		printf("connect error\n");
        goto failed;
    }

#ifdef WIN32
struct  tcp_keepalive  {
    u_long    onoff;
    u_long    keepalivetime;
    u_long    keepaliveinterval;
};
#define  SIO_KEEPALIVE_VALS          _WSAIOW(IOC_VENDOR,4)
    struct tcp_keepalive kavars;
    struct tcp_keepalive alive_out;
    kavars.onoff = TRUE;
    kavars.keepalivetime = 5*1000;
    kavars.keepaliveinterval = 1*1000;

    int alive = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, (const char *) &alive,sizeof(alive));
    unsigned long ulBytesReturn = 0;
    WSAIoctl(sockfd, SIO_KEEPALIVE_VALS, &kavars, sizeof(kavars),&alive_out, sizeof(alive_out), &ulBytesReturn, NULL, NULL);
#else
    int keepalive = 1;
    int keepidle = 5;           // 空间一段时间后
    int keepinterval = 1;       // 时间多长时间
    int keepcount = 10;         // 重发多少次keepalive包
    setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepalive , sizeof(keepalive ));
    setsockopt(sockfd, SOL_TCP, TCP_KEEPIDLE, (void*)&keepidle , sizeof(keepidle ));
    setsockopt(sockfd, SOL_TCP, TCP_KEEPINTVL, (void *)&keepinterval , sizeof(keepinterval ));
    setsockopt(sockfd, SOL_TCP, TCP_KEEPCNT, (void *)&keepcount , sizeof(keepcount ));
#endif

    char buf[8192];
    ssize_t total_size = 0;
    int rcv_size;
    while ((rcv_size = recv(sockfd, buf, sizeof(buf), 0)) > 0) {
        fwrite(buf, 1, rcv_size, file);
        fflush(file);
        printf(".");
        total_size += rcv_size;
    }
    if (rcv_size < 0) {
        // 接收完毕
        printf("rcv file size: %d\n", (int)total_size);
        goto failed;
    }
    printf("rcv file size: %d\n", (int)total_size);
    printf("rcv file ok\n");
    close(sockfd);
    fclose(file);
    return;

failed:
    printf("rcv file error\n");
    // close(sockfd);
    close(sockfd);
    if (file) {
        fclose(file);
    }
    return;
}