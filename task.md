这是一道非常经典的高级系统工程师 / SRE / 安全研发面试题。
这道题的“含金量”和“含坑量”都极高。如果用普通的开发思维（比如 Java/Python 业务逻辑）去解，基本就挂了。
核心考点： Linux 内核机制、高性能系统编程、eBPF 技术、数据处理流水线。
一、 题目里的“坑”在哪里？（面试时的加分项）
性能黑洞（最大陷阱）：
题目要求监控 read/write 系统调用。
坑： read 和 write 是 Linux 中最高频的系统调用。一个高并发服务每秒可能产生几十万次 IO 操作。如果每一个 read/write 都去拦截、记录、写入数据库，机器会瞬间卡死（CPU 爆炸），或者数据库直接崩盘。
对策： 必须说明需要**“采样”、“过滤”（只监控特定进程）或者“聚合”**（比如每秒统计一次读写量，而不是记录每一次调用）。
文件名获取的复杂性：
题目要求：在 read/write 时记录“读取的文件路径”。
坑： read(fd, buffer, count) 和 write(fd, buffer, count) 系统调用的参数里，只有文件描述符 (FD)，没有文件名。
对策：
方案A（笨办法）： 在用户态通过 /proc/<pid>/fd/<fd> 去解析软链接获取路径（有竞态条件，慢）。
方案B（eBPF硬核）： 需要在内核里维护一个 Map，在 open/openat 时记录 FD -> Filename 的映射，然后在 read/write 时查表。或者使用 bpf_d_path（受限）。
数据库的写入瓶颈：
坑： 实时将高频系统调用写入 PostgreSQL 是不可行的。
对策： 必须实现批量写入（Batch Insert）或异步缓冲队列。
技术选型陷阱：
不要用 strace 或 ptrace！虽然它们能做，但会让目标进程慢几百倍，生产环境不可用。
唯一正解：eBPF (BCC 或 libbpf)。
二、 解决方案：基于 Python + BCC (eBPF) + PostgreSQL
考虑到 120 分钟的时间限制，使用 BCC (BPF Compiler Collection) 是最快能出原型的方案。C 语言写 eBPF 内核态代码，Python 写用户态加载和入库逻辑。
1. 架构设计
Kernel Space (C): 使用 Kprobe 或 Tracepoint 挂载到 sys_execve, sys_fork, sys_read, sys_write。将数据写入 BPF_PERF_OUTPUT。
User Space (Python): 轮询 perf buffer，获取事件，进行清洗（解析 FD 对应的路径），放入 Buffer。
Storage: 当 Buffer 满或定时器触发，批量写入 PostgreSQL。
2. 代码实现 (MVP 版本)
这是核心逻辑代码，面试时写出这个骨架就稳了。
code
Python
#!/usr/bin/python3
from bcc import BPF
import os
import psycopg2
import time
from collections import deque

# --- 1. eBPF 内核代码 (C语言) ---
# 这是一个简化版，重点展示 execve 和 write 的捕获
bpf_source = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

// 定义传给用户态的数据结构
struct data_t {
    u32 pid;
    u32 type; // 1=exec, 2=fork, 3=read, 4=write
    char comm[TASK_COMM_LEN];
    char filename[256]; // 简化处理，只存一部分路径
    u64 timestamp;
};

BPF_PERF_OUTPUT(events);

// 1. 监控 execve (获取二进制路径)
int trace_execve(struct pt_regs *ctx, const char __user *filename) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.type = 1;
    data.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename);
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// 2. 监控 write (注意：这里直接获取路径很难，通常只拿FD回用户态解析)
// 真正的生产环境应该在 open 时建立 fd->filename 映射，这里为了面试简化
int trace_write(struct pt_regs *ctx, unsigned int fd, const char __user *buf, size_t count) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.type = 4;
    data.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // 把 FD 转成字符串存这就行，去用户态 /proc 解析
    // 真正的路径解析在内核态做极其复杂
    snprintf(data.filename, sizeof(data.filename), "%d", fd);
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# --- 2. 数据库连接 ---
def get_db_conn():
    return psycopg2.connect(
        dbname="monitor_db", user="user", password="password", host="localhost"
    )

# --- 3. 用户态处理逻辑 ---
batch_buffer = []
BATCH_SIZE = 100

def resolve_fd_path(pid, fd_str):
    """
    面试时的权宜之计：去 /proc 解析 FD
    注意：这有性能开销，且有竞态条件（进程可能已经退出了）
    """
    try:
        path = os.readlink(f"/proc/{pid}/fd/{fd_str}")
        return path
    except:
        return f"fd:{fd_str} (closed/unknown)"

def flush_to_db(conn):
    global batch_buffer
    if not batch_buffer:
        return
    
    cursor = conn.cursor()
    args_str = ','.join(cursor.mogrify("(%s,%s,%s,%s,%s)", x).decode('utf-8') for x in batch_buffer)
    cursor.execute("INSERT INTO audit_log (pid, type, comm, path, timestamp) VALUES " + args_str)
    conn.commit()
    cursor.close()
    batch_buffer = []
    print(f"Flushed {BATCH_SIZE} records to DB")

def print_event(cpu, data, size):
    event = b["events"].event(data)
    
    path = event.filename.decode('utf-8', 'ignore')
    
    # 如果是 write/read (type 3 or 4)，filename 字段存的是 FD，需要解析
    if event.type in [3, 4]:
        path = resolve_fd_path(event.pid, path)

    # 存入 Buffer
    record = (event.pid, event.type, event.comm.decode('utf-8', 'ignore'), path, event.timestamp)
    batch_buffer.append(record)

    if len(batch_buffer) >= BATCH_SIZE:
        flush_to_db(conn)

# --- 4. 主程序 ---
b = BPF(text=bpf_source)
# 挂载 execve
execve_fn = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_fn, fn_name="trace_execve")
# 挂载 write
write_fn = b.get_syscall_fnname("write")
b.attach_kprobe(event=write_fn, fn_name="trace_write")
# 还可以继续挂载 fork, read...

conn = get_db_conn()
print("Tracing... Ctrl-C to stop.")

try:
    b["events"].open_perf_buffer(print_event)
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    exit()
