# net - 自研 TCP/IP 协议栈

## 项目简介

`net` 是一个使用 C 语言实现的 TCP/IP 协议栈实验工程，代码包含 PC 端测试工程、通用协议栈源码、STM32F407 移植工程、x86 OS 移植工程以及按课程章节拆分的演进版本。

项目采用“协议栈核心 + 平台适配层 + 应用测试层”的组织方式。PC 端工程通过 pcap/Npcap 收发以太网帧，可用于调试协议栈行为；嵌入式和 x86 OS 目录提供了不同平台的移植代码。

当前仓库更适合作为网络协议栈学习、协议实现验证和平台移植参考工程。README 中仅描述仓库内已经存在的代码和配置，不包含未实现功能的宣传。

## 功能特性

- 分层实现网络协议栈核心模块：Ethernet、ARP、IPv4、ICMPv4、RAW、UDP、TCP、DNS、Loopback。
- 提供类 BSD Socket 的自定义 API：`x_socket`、`x_bind`、`x_connect`、`x_send`、`x_recv`、`x_listen`、`x_accept`、`x_close` 等。
- `netapi.h` 可将常见 socket 名称映射到项目内实现，例如 `socket` -> `x_socket`、`send` -> `x_send`。
- PC 端测试工程基于 pcap/Npcap 驱动网络接口。
- PC 端测试入口会启动 UDP Echo、TCP Echo、TFTP Server、HTTP 静态文件服务，并提供命令行测试入口。
- 应用测试模块包含 `ping`、`tftp`、`httpd`、`ntp`、`echo`。
- 基础设施模块包含定长队列、内存块、链表、包缓存、定时器、平台锁与线程抽象。
- 包含 STM32F407 + LAN8720 的移植目录。
- 包含可在 QEMU 场景下运行的 x86 OS 网络移植目录，网卡驱动目标为 RTL8139。
- 包含 `chapter` 分章节源码，用于对照学习协议栈逐步演进过程。

## 技术栈

- 语言：C99
- 构建：CMake、Visual Studio 工程文件、Keil MDK 工程文件
- PC 网络接口：pcap / Npcap / libpcap
- PC 平台：Windows、Linux/macOS 适配代码
- 嵌入式平台：STM32F407、LAN8720、STM32 标准外设库
- x86 OS 平台：QEMU、RTL8139、交叉编译工具链、newlib 相关目录

## 项目结构

```text
.
|-- README.md
|-- 技术文档.md
|-- main.py                     # PyCharm 示例脚本，不属于协议栈主工程
|-- tools/
|   `-- tcp_server.py           # 占位/说明性质脚本
`-- code/
    |-- 目录说明.txt
    |-- pc/                     # PC 端测试工程，最适合本地调试
    |   |-- CMakeLists.txt
    |   |-- tcpip.sln
    |   |-- tcpip.vcxproj
    |   |-- npcap/              # Npcap 头文件与库
    |   |-- src/
    |   |   |-- app/            # echo/http/ntp/ping/test/tftp
    |   |   |-- net/            # 协议栈核心源码与头文件
    |   |   `-- plat/           # PC 平台适配、pcap 网卡驱动
    |   `-- work/
    |       `-- htdocs/         # HTTP 静态文件根目录
    |-- src/                    # 通用协议栈源码版本
    |   |-- app/
    |   |-- net/
    |   `-- plat/
    |-- start/                  # 开发起点工程
    |-- stm32/                  # STM32F407 移植工程
    |   |-- app/
    |   |-- net/
    |   |-- os/
    |   |-- plat/
    |   `-- USER/
    |       `-- tcpip.uvprojx
    |-- x86os-with-net/         # x86 OS + TCP/IP 协议栈移植
    |   |-- README.md
    |   `-- x86os/
    |       |-- CMakeLists.txt
    |       |-- script/
    |       `-- source/
    `-- chapter/                # 分章节源码
```

PC 端协议栈核心文件主要位于：

```text
code/pc/src/net/
|-- net/                        # 公开头文件与配置
`-- src/                        # 协议实现
    |-- arp.c
    |-- dns.c
    |-- ether.c
    |-- exmsg.c
    |-- icmpv4.c
    |-- ipv4.c
    |-- net.c
    |-- netapi.c
    |-- netif.c
    |-- raw.c
    |-- socket.c
    |-- tcp.c
    |-- tcp_in.c
    |-- tcp_out.c
    |-- tcp_state.c
    `-- udp.c
```

## 安装方式

### 1. 获取代码

```bash
git clone <repo-url>
cd <repo>
```

如果你已经在本地拥有该目录，可直接进入仓库根目录。

### 2. 安装 PC 端依赖

Windows 推荐环境：

- Visual Studio 或可用的 C/C++ 编译器
- CMake 3.7 或更高版本
- Npcap

Linux/macOS 推荐环境：

- CMake
- GCC 或 Clang
- libpcap 开发库
- pthread

Ubuntu/Debian 示例：

```bash
sudo apt update
sudo apt install -y build-essential cmake libpcap-dev
```

### 3. 确认网络参数

PC 端运行前需要根据本机网络环境修改：

```text
code/pc/src/plat/sys_plat.h
```

重点配置项：

```c
static const char netdev0_ip[] = "192.168.74.2";
static const char netdev0_gw[] = "192.168.74.1";
static const char friend0_ip[] = "192.168.74.3";
static const char netdev0_phy_ip[] = "192.168.74.1";
static const char netdev0_mask[] = "255.255.255.0";
static const uint8_t netdev0_hwaddr[] = { 0x00, 0x50, 0x56, 0xc0, 0x00, 0x11 };
```

其中 `netdev0_phy_ip` 用于 pcap 查找本机真实网卡，需要改成本机实际网卡 IP。

## 环境变量

当前 C 代码未发现通过 `getenv` 或类似方式读取运行时环境变量。协议栈配置主要通过头文件常量和 CMake 预处理宏完成。

如果你希望为本地脚本、CI 或部署说明保存配置，可以参考下面的 `.env.example`。注意：这些变量不会被当前 C 程序自动读取，需要同步写入 `sys_plat.h`、`net_cfg.h` 或你的外部脚本中。

```dotenv
# .env.example
# 当前项目源码不会自动读取这些变量，仅作为自动化脚本或环境说明参考。

NETDEV0_IP=192.168.74.2
NETDEV0_GW=192.168.74.1
NETDEV0_MASK=255.255.255.0
NETDEV0_PHY_IP=192.168.74.1
NETDEV0_HWADDR=00:50:56:c0:00:11
FRIEND0_IP=192.168.74.3

HTTPD_ROOT=htdocs
HTTPD_PORT=80

TFTP_ROOT=tftp
TFTP_PORT=69
```

真实源码配置位置：

```text
code/pc/src/plat/sys_plat.h       # PC 端 IP、网关、掩码、MAC、对端地址
code/pc/src/net/net/net_cfg.h     # 协议栈缓存、队列、调试、TCP/UDP/ARP/DNS 参数
code/pc/CMakeLists.txt            # 平台宏、pcap/Npcap 链接配置
```

## 本地运行

PC 端主入口：

```text
code/pc/src/app/test/main.c
```

该入口执行的主要流程：

```text
net_init()
-> netdev_init()
-> net_start()
-> udp_echo_server_start(2000)
-> tftpd_start("tftp", 69)
-> tcp_echo_server_start(2000)
-> httpd_start("htdocs", 80)
-> 命令循环
```

Windows PowerShell 示例：

```powershell
cd code/pc
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Debug

# HTTP 服务默认从当前工作目录下的 htdocs 读取静态文件，因此建议从 work 目录启动。
New-Item -ItemType Directory -Force .\work\tftp | Out-Null
cd work
..\build\Debug\net.exe
```

如果使用 Ninja、MinGW 或 Makefile 生成器，输出路径可能是 `build/net.exe` 或 `build/net`：

```powershell
cd code/pc
cmake -S . -B build
cmake --build build
cd work
..\build\net.exe
```

Linux/macOS 示例：

```bash
cd code/pc
cmake -S . -B build
cmake --build build

mkdir -p work/tftp
cd work
sudo ../build/net
```

运行后命令行会显示可用命令：

```text
ping <dest>
tftp-get <file_path>
tftp-put <file_path>
tftp
time any
get <filename>
```

示例：

```text
ping 192.168.74.3
tftp-get test.bin
tftp-put test.bin
time any
get index.html
```

HTTP 静态文件服务默认端口为 `80`，默认根目录为 `code/pc/work/htdocs`。如果 `netdev0_ip` 配置为 `192.168.74.2`，可在浏览器或命令行中访问：

```bash
curl http://192.168.74.2/
```

## 构建方式

### PC 端 CMake 构建

```bash
cd code/pc
cmake -S . -B build
cmake --build build
```

Windows Visual Studio 指定生成器：

```powershell
cd code/pc
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Debug
```

PC 端 CMake 配置会：

- 设置 C 标准为 C99。
- 递归编译 `src/*.c` 和 `src/*.h`。
- 定义 `NET_DRIVER_PCAP`。
- Windows 下定义 `SYS_PLAT_WINDOWS` 并链接 `wpcap`、`packet`、`Ws2_32`。
- 非 Windows 下定义 `SYS_PLAT_LINUX` 并链接 `pthread`、`pcap`。

### STM32 构建

STM32 工程入口：

```text
code/stm32/USER/tcpip.uvprojx
```

使用 Keil MDK 打开该工程后，根据目标开发板、调试器和网卡硬件环境进行编译、下载与调试。

### x86 OS 构建

x86 OS 工程入口：

```text
code/x86os-with-net/x86os/CMakeLists.txt
```

该工程使用交叉编译工具链，CMake 中默认配置了 `NET_DRIVER_RTL8139` 和 `SYS_PLAT_X86OS`。调试脚本位于：

```text
code/x86os-with-net/x86os/script/
```

脚本示例：

```text
qemu-debug-win.bat
qemu-debug-linux.sh
qemu-debug-osx.sh
```

## 部署方式

### PC 端部署

1. 安装 Npcap 或 libpcap。
2. 修改 `code/pc/src/plat/sys_plat.h` 中的网卡和 IP 参数。
3. 构建 `code/pc`。
4. 从 `code/pc/work` 目录运行生成的 `net` 可执行文件。
5. 使用 `ping`、TFTP、HTTP、Echo 服务验证链路。

Windows 下如果 pcap 无法枚举或打开网卡，可以尝试使用管理员权限运行终端。

### STM32 部署

1. 使用 Keil MDK 打开 `code/stm32/USER/tcpip.uvprojx`。
2. 确认开发板为 STM32F407，并连接 LAN8720 网络硬件。
3. 配置编译器、调试器、下载器和网络环境。
4. 编译并下载到开发板。
5. 根据 `code/stm32/readme.txt` 中的按键、LCD、串口和网络说明进行测试。

### x86 OS 部署

1. 准备 x86 交叉编译工具链和 QEMU 环境。
2. 进入 `code/x86os-with-net/x86os`。
3. 使用 CMake 构建系统镜像和应用程序。
4. 使用 `script/` 下对应平台的 QEMU 调试脚本启动。
5. 网络测试依赖 RTL8139 相关驱动和 QEMU 网络配置。

## API 示例

项目不是 REST API 服务。这里的 API 主要指协议栈初始化接口、Socket 风格接口以及测试应用接口。

初始化接口：

```c
#include "net.h"

net_err_t net_init(void);
net_err_t net_start(void);
```

Socket 风格接口：

```c
#include "netapi.h"

int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
if (s < 0) {
    return -1;
}

struct sockaddr_in addr;
memset(&addr, 0, sizeof(addr));
addr.sin_family = AF_INET;
addr.sin_port = htons(2000);
addr.sin_addr.s_addr = inet_addr("192.168.74.3");

if (connect(s, (const struct sockaddr *)&addr, sizeof(addr)) == 0) {
    const char msg[] = "hello";
    send(s, msg, sizeof(msg) - 1, 0);
}

close(s);
```

UDP 示例：

```c
#include "netapi.h"

int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

struct sockaddr_in remote;
memset(&remote, 0, sizeof(remote));
remote.sin_family = AF_INET;
remote.sin_port = htons(2000);
remote.sin_addr.s_addr = inet_addr("192.168.74.3");

const char data[] = "udp payload";
sendto(s, data, sizeof(data) - 1, 0, (const struct sockaddr *)&remote, sizeof(remote));

close(s);
```

测试应用接口：

```c
void ping_run(ping_t *ping, const char *dest, int count, int size, int interval);
int tftp_start(const char *ip, uint16_t port);
int tftp_get(const char *ip, uint16_t port, int block_size, const char *filename);
int tftp_put(const char *ip, uint16_t port, int block_size, const char *filename);
int httpd_start(const char *dir, uint16_t port);
int tcp_echo_server_start(int port);
int tcp_echo_client_start(const char *ip, int port);
int udp_echo_server_start(int port);
int udp_echo_client_start(const char *ip, int port);
struct tm *ntp_time(void);
```

HTTP 服务能力边界：

- 当前 HTTP 服务主要用于静态文件测试。
- 已实现 `GET` 请求处理。
- 非 `GET` 方法会返回 `501 Not Implemented`。
- URL 中包含 `..` 会被拒绝，避免访问静态根目录之外的文件。

## 配置说明

核心协议栈配置：

```text
code/pc/src/net/net/net_cfg.h
```

常见配置项：

```c
#define EXMSG_MSG_CNT          10
#define PKTBUF_BLK_SIZE        1024
#define PKTBUF_BLK_CNT         2048
#define PKTBUF_BUF_CNT         1024

#define NETIF_DEV_CNT          4
#define NETIF_INQ_SIZE         50
#define NETIF_OUTQ_SIZE        50

#define ARP_CACHE_SIZE         2
#define IP_RTABLE_SIZE         16

#define RAW_MAX_NR             5
#define UDP_MAX_NR             4
#define TCP_MAX_NR             10

#define TCP_SBUF_SIZE          10240
#define TCP_RBUF_SIZE          10240
```

PC 平台网络配置：

```text
code/pc/src/plat/sys_plat.h
```

默认服务配置：

```c
#define HTTPD_DEFAULT_ROOT     "htdocs"
#define HTTPD_DEFAULT_PORT     80

#define TFTP_DEF_PORT          69
#define TFTP_DEF_BLKSIZE       512
```

CMake 平台宏：

```cmake
add_definitions(-DNET_DRIVER_PCAP)

# Windows
add_definitions(-DSYS_PLAT_WINDOWS)

# Linux/macOS 分支
add_definitions(-DSYS_PLAT_LINUX)
```

## 开发规范

- 使用 C99，PC 端 CMake 已设置 `set(CMAKE_C_STANDARD 99)`。
- 协议栈内部模块不要包含 `netapi.h`；该头文件用于应用层映射 socket 名称，源码注释中也明确说明不应被协议栈内部其它文件包含。
- 新增协议模块建议放在 `code/pc/src/net/src` 和 `code/pc/src/net/net`，保持 `.c` 与 `.h` 分层。
- 平台相关逻辑放在 `plat` 目录，不直接侵入协议栈核心。
- 应用测试逻辑放在 `app` 目录，不与核心协议实现混杂。
- 网络参数、缓存数量、超时和调试等级优先通过 `net_cfg.h` 或平台配置头文件调整。
- 修改 PC 端网络参数后，优先使用 `ping`、Echo、TFTP、HTTP 进行回归验证。
- 提交前建议清理本地构建产物，例如 `build/`、`.vs/`、`Debug/`、`Objects/`、`Listings/`。

## 常见问题

### pcap 找不到网卡

检查 `code/pc/src/plat/sys_plat.h` 中的 `netdev0_phy_ip` 是否为本机真实网卡 IP。Windows 下还需要确认已安装 Npcap。

### 程序启动后 HTTP 访问不到页面

HTTP 默认根目录是 `htdocs`，建议从 `code/pc/work` 目录启动可执行文件：

```powershell
cd code/pc/work
..\build\Debug\net.exe
```

### TFTP Server 创建或读取文件失败

PC 端入口默认调用：

```c
tftpd_start("tftp", TFTP_DEF_PORT);
```

因此建议在 `code/pc/work` 下创建 `tftp` 目录：

```powershell
cd code/pc
New-Item -ItemType Directory -Force .\work\tftp
```

### Windows 下运行缺少 DLL 或无法打开 pcap

确认已安装 Npcap，并检查 `code/pc/npcap/Lib/x64` 是否与当前编译架构一致。必要时使用管理员权限启动终端。

### DNS 或 NTP 查询失败

DNS 和 NTP 依赖路由、网关、DNS 服务器和外网连通性。先确认 ARP、IPv4、ICMP 和默认网关配置正常。

### TCP 发送后没有立刻看到数据

TCP 发送走发送缓冲、输出状态机、ACK、重传和定时器逻辑；不是简单的同步直发。可结合日志等级和抓包工具排查。

### 当前是否包含数据库

仓库内未发现 SQL、ORM、数据库连接或数据库表结构。ARP 缓存、路由表、DNS 缓存、Socket 表和 TCP/UDP 控制块均为内存数据结构。

## Roadmap

- [ ] 补充明确的开源许可证文件。
- [ ] 增加 PC 端一键构建脚本。
- [ ] 增加最小化自动化测试或冒烟测试脚本。
- [ ] 补充 pcap/Npcap 网卡选择和抓包调试说明。
- [ ] 整理 `chapter` 目录索引，降低首次阅读成本。
- [ ] 为核心 API 生成 Doxygen 或同类文档。
- [ ] 进一步说明 STM32 与 x86 OS 的完整构建链路。

## License

当前仓库根目录未发现 `LICENSE` 或等价许可证文件。

在正式作为开源项目发布前，请补充明确的开源许可证，例如 MIT、Apache-2.0、BSD-3-Clause 或 GPL 系列。未添加许可证前，外部用户不能默认获得复制、修改、分发或商用授权。
