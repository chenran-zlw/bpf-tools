# ebpf-tools-share

一套基于 eBPF 的系统诊断工具集合，用于系统性能分析和故障排查。

## 概述

本仓库包含一组专为 Linux 系统诊断设计的 eBPF 程序。这些工具利用 eBPF 的强大功能，提供低开销的动态追踪能力，用于分析系统行为，而无需修改内核或加载内核模块。

## 工具介绍

### bpftrace-demo/show_process_cmdline.bt

通过捕获进程执行 exec 系统调用时的命令行参数来追踪进程创建。

特点：
- 实时监控进程创建
- 完整捕获命令行参数
- 使用 eBPF uprobes 实现最小开销

使用方法：
```bash
sudo bpftrace bpftrace-demo/show_process_cmdline.bt
```

### show_process_cmdline.py

基于 BCC 的 Python 实现，用于追踪进程执行。它是 `show_process_cmdline.bt` 在使用 BCC 环境下的替代方案。

特点：
- 监控 `execve` 系统调用
- 捕获 PID、命令名称和参数
- 支持 PID 过滤
- 显示带日期和时间的时间戳

使用方法：
```bash
sudo python3 show_process_cmdline.py
```

### bpftrace-demo/show_tcp_latency.bt

监控 TCP 数据包在网络堆栈各阶段的延迟。

特点：
- 追踪 TCP 数据包通过不同内核函数的过程
- 测量数据包处理各阶段的延迟
- 过滤特定目标端口（当前配置为端口 7617 和 5001）

追踪的关键函数：
- `netif_receive_skb`: 网络接口接收
- `ip_rcv_finish`: IP 层处理
- `tcp_v4_do_rcv`: TCP 接收处理
- `tcp_queue_rcv`: TCP 队列管理
- `sock_def_readable`: Socket 就绪通知
- `tcp_cleanup_rbuf`: TCP 接收缓冲区清理
- `ip_output`: IP 输出处理
- `dev_hard_start_xmit`: 硬件传输发起

使用方法：
```bash
sudo bpftrace bpftrace-demo/show_tcp_latency.bt
```

### show_tcp_latency

基于 libbpf 的 TCP 延迟监控工具，是 `show_tcp_latency.bt` 的高性能替代品。基于5.10内核版本开发。

特点：
- 使用 libbpf 和 CO-RE 技术实现更高性能
- 分别追踪接收和发送方向的不同端口
- 支持自定义接收端口和发送端口过滤
- 使用 Ring Buffer 提高数据传输效率

使用方法：
```bash
# 编译工具
cd show_tcp_latency && bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h&& make

# 追踪默认端口（Rx: 7617, Tx: 5001）
sudo ./show_tcp_latency

# 自定义端口
sudo ./show_tcp_latency -r 8080 -t 9090
```

### show_udp_runtime_irq.py

分析 UDP 网络输出模式，关联传输队列与中断请求及 CPU 亲和性。

特点：
- 追踪 UDP 数据包传输过程
- 映射硬件传输队列到 IRQ 编号
- 显示网络中断的 CPU 亲和性
- 展示网络活动的进程信息
- 支持 IPv4 和 IPv6
- 优化的性能缓存机制

使用方法：
```bash
# 追踪所有 UDP 网络输出
sudo python3 show_udp_runtime_irq.py

# 仅追踪特定 PID
sudo python3 show_udp_runtime_irq.py -p [PID]

# 仅追踪特定端口（接收方向）
sudo python3 show_udp_runtime_irq.py --port [PORT]

# 仅追踪特定 CPU
sudo python3 show_udp_runtime_irq.py -c [CPU]

# 选择追踪方向（tx/rx/all）
sudo python3 show_udp_runtime_irq.py --mode tx
```

## 环境要求

- Linux 内核版本 4.1+
- bpftrace（用于 `.bt` 文件）
- 安装了 BCC 库的 Python（用于 `.py` 文件）
- libbpf-dev、clang、llvm、libelf-dev（用于编译 libbpf 工具）

## 安装说明

无需安装。只需克隆仓库并直接运行所需工具。

## 使用注意事项

- 所有工具都需要 root 权限，因为 eBPF 的限制
- 某些工具可能有硬编码的端口过滤器，需要根据环境进行调整
- 在生产系统上，始终在非关键环境中测试工具

## 相关项目

受以下基于 eBPF 的诊断套件启发：
- [BCC](https://github.com/iovisor/bcc) - 用于 BPF 的 Linux IO 分析工具
- [bpftrace](https://github.com/iovisor/bpftrace) - Linux eBPF 的高级追踪语言# ebpf-tools-share
