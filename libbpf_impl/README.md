# Libbpf eBPF Monitor Demo

这是一个基于 `libbpf` + `CO-RE` 的现代 eBPF 监控程序示例。
相比 BCC 版本，它编译出的二进制文件体积小、无运行时依赖，适合生产环境。

## 目录结构
- `monitor.bpf.c`: 内核态 eBPF 代码 (RingBuffer, Tracepoints)
- `monitor.c`: 用户态 C 代码 (加载器, 事件处理)
- `monitor.h`: 公共结构体定义
- `Makefile`: 编译脚本

## 前置要求 (WSL/Ubuntu)

在编译之前，你需要安装工具链：

```bash
# 1. 安装 Clang 和依赖
sudo apt update
sudo apt install clang libelf-dev zlib1g-dev make

# 2. 安装 libbpf 开发库 (Ubuntu 20.04+)
sudo apt install libbpf-dev

# 3. 安装 bpftool (用于生成 vmlinux.h 和 skeleton)
# 方法 A: 直接安装 (推荐)
sudo apt install linux-tools-$(uname -r) linux-tools-common linux-tools-generic

# 方法 B: 如果 apt 找不到，可以从源码编译 bpftool
# git clone --recurse-submodules https://github.com/libbpf/bpftool.git
# cd bpftool/src && make && sudo make install
```

## 编译与运行

1. **生成 vmlinux.h 并编译**
   ```bash
   # 确保你在 libbpf_impl 目录下
   cd libbpf_impl
   
   # 如果你的系统支持 BTF (/sys/kernel/btf/vmlinux 存在)
   make vmlinux
   
   # 编译整个项目
   make
   ```

   > **注意**: 如果 `make vmlinux` 失败（提示找不到文件），说明你的 WSL 内核不支持 BTF。
   > 这种情况下 CO-RE 无法正常工作。你需要升级 WSL 内核或使用支持 BTF 的发行版。
   > 检查命令: `ls -l /sys/kernel/btf/vmlinux`

2. **运行程序**
   ```bash
   sudo ./monitor
   ```

3. **预期输出**
   ```text
   [EXEC ] PID: 1234   PPID: 1000   COMM: ls               FD: 0   SIZE: 0      FILE: /bin/ls
   [WRITE] PID: 1234   PPID: 1000   COMM: ls               FD: 1   SIZE: 1024   FILE: 
   ```

## 常见问题

**Q: 报错 `fatal error: 'vmlinux.h' file not found`**
A: 请先运行 `make vmlinux`。如果报错，说明你的系统没有 BTF 支持。

**Q: 报错 `libbpf: failed to find BTF for kernel`**
A: 同样是因为内核太老或未开启 CONFIG_DEBUG_INFO_BTF。WSL2 的较新版本（Win11 更新后）通常默认开启。

**Q: 为什么没有文件名？**
A: 在 `monitor.bpf.c` 中，`sys_enter_write` 等 tracepoint 只能拿到 `fd`。要拿到文件名，需要维护一个 `fd -> filename` 的 Map，或者在 `sys_enter_openat` 时记录。为了保持 Demo 简单，这里只在 `EXEC` 事件中读取了文件名。
