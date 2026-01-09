#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
系统调用监控程序 - 优化版
基于 eBPF (BCC) 实现 exec/fork/read/write 系统调用监控

功能：
1. 监控 execve (进程执行)
2. 监控 clone/fork (进程创建)
3. 监控 read/write (文件 IO)
4. 批量写入 PostgreSQL

依赖安装：
- Ubuntu: sudo apt install bpfcc-tools python3-bpfcc
- pip install psycopg2-binary

运行方式：
- sudo python3 syscall_monitor.py [--pid PID] [--filter-path PATH]
"""

from bcc import BPF
import os
import argparse
import time
import signal
import sys
from datetime import datetime
from collections import deque
from threading import Lock

# 尝试导入 psycopg2，如果没有则使用模拟模式
try:
    import psycopg2
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False
    print("[警告] psycopg2 未安装，将使用控制台输出模式")


# --- eBPF 内核代码 (C语言) ---
BPF_SOURCE = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

// 事件类型枚举
#define EVENT_EXEC  1
#define EVENT_FORK  2
#define EVENT_READ  3
#define EVENT_WRITE 4

// 传给用户态的数据结构
struct data_t {
    u32 pid;           // 进程 ID
    u32 ppid;          // 父进程 ID
    u32 uid;           // 用户 ID
    u32 event_type;    // 事件类型
    u32 fd;            // 文件描述符 (read/write 时使用)
    u64 size;          // 读写大小
    u64 timestamp;     // 时间戳 (纳秒)
    char comm[TASK_COMM_LEN];  // 进程名
    char filename[256];        // 文件名/路径
};

// Perf 输出缓冲区
BPF_PERF_OUTPUT(events);

// 可选：PID 过滤 Map (用于只监控特定进程)
BPF_HASH(target_pids, u32, u32);

// 辅助函数：检查是否需要过滤此进程
static inline int should_filter(u32 pid) {
    // 如果 map 为空，监控所有进程
    // 如果 map 非空，只监控 map 中的进程
    u32 *val = target_pids.lookup(&pid);
    // 这里简化处理：暂时监控所有进程
    // 生产环境应该根据业务需求设置过滤规则
    return 0;
}

// 1. 监控 execve (进程执行)
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    data.pid = pid_tgid >> 32;
    if (should_filter(data.pid)) return 0;
    
    data.event_type = EVENT_EXEC;
    data.timestamp = bpf_ktime_get_ns();
    
    // 获取父进程 ID
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read_kernel(&data.ppid, sizeof(data.ppid), &task->real_parent->tgid);
    
    // 获取用户 ID
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    // 获取进程名
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // 获取执行的文件路径
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), args->filename);
    
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

// 2. 监控 clone (fork 的底层实现)
TRACEPOINT_PROBE(syscalls, sys_exit_clone) {
    // 只在子进程返回 0 或父进程返回子进程 PID 时触发
    if (args->ret < 0) return 0;  // 忽略失败的 clone
    
    struct data_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    data.pid = pid_tgid >> 32;
    if (should_filter(data.pid)) return 0;
    
    data.event_type = EVENT_FORK;
    data.timestamp = bpf_ktime_get_ns();
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read_kernel(&data.ppid, sizeof(data.ppid), &task->real_parent->tgid);
    
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // 子进程 PID 存入 fd 字段 (复用)
    data.fd = args->ret;
    
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

// 3. 监控 write
TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    struct data_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    data.pid = pid_tgid >> 32;
    if (should_filter(data.pid)) return 0;
    
    data.event_type = EVENT_WRITE;
    data.timestamp = bpf_ktime_get_ns();
    data.fd = args->fd;
    data.size = args->count;
    
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

// 4. 监控 read
TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    struct data_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    data.pid = pid_tgid >> 32;
    if (should_filter(data.pid)) return 0;
    
    data.event_type = EVENT_READ;
    data.timestamp = bpf_ktime_get_ns();
    data.fd = args->fd;
    data.size = args->count;
    
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""


class SyscallMonitor:
    """系统调用监控器"""
    
    EVENT_TYPES = {
        1: "EXEC",
        2: "FORK",
        3: "READ",
        4: "WRITE"
    }
    
    def __init__(self, db_config=None, batch_size=100, flush_interval=5.0):
        """
        初始化监控器
        
        Args:
            db_config: 数据库配置字典，None 则使用控制台输出
            batch_size: 批量写入大小
            flush_interval: 刷新间隔（秒）
        """
        self.db_config = db_config
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        
        self.batch_buffer = []
        self.buffer_lock = Lock()
        self.last_flush_time = time.time()
        
        self.bpf = None
        self.conn = None
        self.running = False
        
        # 统计计数器
        self.stats = {
            "exec": 0,
            "fork": 0,
            "read": 0,
            "write": 0,
            "flushed": 0
        }
    
    def _init_db(self):
        """初始化数据库连接"""
        if not self.db_config or not HAS_PSYCOPG2:
            return None
        
        try:
            conn = psycopg2.connect(**self.db_config)
            print(f"[信息] 数据库连接成功: {self.db_config.get('host', 'localhost')}")
            return conn
        except Exception as e:
            print(f"[错误] 数据库连接失败: {e}")
            return None
    
    def _resolve_fd_path(self, pid, fd):
        """
        解析 FD 对应的文件路径
        
        注意：这种方法有竞态条件，进程可能已经退出
        生产环境应该在内核态维护 fd->path 映射
        """
        if fd < 3:
            # 标准输入/输出/错误
            return ["stdin", "stdout", "stderr"][fd]
        
        try:
            path = os.readlink(f"/proc/{pid}/fd/{fd}")
            return path
        except (FileNotFoundError, PermissionError):
            return f"fd:{fd}"
        except Exception:
            return f"fd:{fd} (unknown)"
    
    def _convert_timestamp(self, ktime_ns):
        """
        将内核时间戳转换为 UNIX 时间戳
        
        bpf_ktime_get_ns() 返回的是系统启动后的纳秒数
        需要结合启动时间转换
        """
        # 简化处理：使用当前时间
        # 生产环境应该读取 /proc/uptime 精确计算
        return datetime.now()
    
    def _flush_to_db(self):
        """批量写入数据库"""
        with self.buffer_lock:
            if not self.batch_buffer:
                return
            
            records = self.batch_buffer.copy()
            self.batch_buffer = []
        
        if self.conn:
            try:
                cursor = self.conn.cursor()
                # 使用 executemany 批量插入
                cursor.executemany(
                    """
                    INSERT INTO audit_log 
                    (pid, ppid, uid, event_type, fd, size, path, comm, timestamp)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    records
                )
                self.conn.commit()
                cursor.close()
                self.stats["flushed"] += len(records)
                print(f"[DB] 写入 {len(records)} 条记录，累计 {self.stats['flushed']}")
            except Exception as e:
                print(f"[错误] 数据库写入失败: {e}")
                self.conn.rollback()
        else:
            # 控制台输出模式
            for r in records[-5:]:  # 只显示最后 5 条
                print(f"[LOG] PID={r[0]} TYPE={r[3]} PATH={r[6]} COMM={r[7]}")
            if len(records) > 5:
                print(f"      ... 还有 {len(records) - 5} 条")
        
        self.last_flush_time = time.time()
    
    def _handle_event(self, cpu, data, size):
        """处理来自内核的事件"""
        event = self.bpf["events"].event(data)
        
        event_type = self.EVENT_TYPES.get(event.event_type, "UNKNOWN")
        
        # 更新统计
        if event_type == "EXEC":
            self.stats["exec"] += 1
        elif event_type == "FORK":
            self.stats["fork"] += 1
        elif event_type == "READ":
            self.stats["read"] += 1
        elif event_type == "WRITE":
            self.stats["write"] += 1
        
        # 解析路径
        if event.event_type in [3, 4]:  # READ/WRITE
            path = self._resolve_fd_path(event.pid, event.fd)
        else:
            path = event.filename.decode('utf-8', 'replace').rstrip('\x00')
        
        # 构建记录
        record = (
            event.pid,
            event.ppid,
            event.uid,
            event_type,
            event.fd,
            event.size,
            path,
            event.comm.decode('utf-8', 'replace').rstrip('\x00'),
            self._convert_timestamp(event.timestamp)
        )
        
        with self.buffer_lock:
            self.batch_buffer.append(record)
        
        # 检查是否需要刷新
        should_flush = (
            len(self.batch_buffer) >= self.batch_size or
            (time.time() - self.last_flush_time) >= self.flush_interval
        )
        
        if should_flush:
            self._flush_to_db()
    
    def start(self):
        """启动监控"""
        print("[信息] 正在加载 eBPF 程序...")
        
        try:
            self.bpf = BPF(text=BPF_SOURCE)
        except Exception as e:
            print(f"[错误] eBPF 加载失败: {e}")
            print("[提示] 请确保：")
            print("       1. 以 root 权限运行")
            print("       2. 内核版本 >= 4.15")
            print("       3. 已安装 bcc-tools")
            sys.exit(1)
        
        self.conn = self._init_db()
        self.running = True
        
        print("[信息] eBPF 程序加载成功，开始监控...")
        print("[信息] 按 Ctrl+C 停止")
        print("-" * 60)
        
        # 设置信号处理
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        # 打开 perf buffer
        self.bpf["events"].open_perf_buffer(self._handle_event)
        
        # 主循环
        while self.running:
            try:
                self.bpf.perf_buffer_poll(timeout=1000)
            except Exception as e:
                if self.running:
                    print(f"[错误] Poll 异常: {e}")
        
        self._cleanup()
    
    def _signal_handler(self, signum, frame):
        """信号处理"""
        print("\n[信息] 收到停止信号，正在清理...")
        self.running = False
    
    def _cleanup(self):
        """清理资源"""
        # 刷新剩余数据
        self._flush_to_db()
        
        # 关闭数据库连接
        if self.conn:
            self.conn.close()
            print("[信息] 数据库连接已关闭")
        
        # 打印统计信息
        print("-" * 60)
        print("[统计]")
        print(f"  EXEC 事件: {self.stats['exec']}")
        print(f"  FORK 事件: {self.stats['fork']}")
        print(f"  READ 事件: {self.stats['read']}")
        print(f"  WRITE 事件: {self.stats['write']}")
        print(f"  已入库: {self.stats['flushed']}")


def main():
    parser = argparse.ArgumentParser(
        description="基于 eBPF 的系统调用监控程序",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例：
  sudo python3 syscall_monitor.py
  sudo python3 syscall_monitor.py --db-host localhost --db-name monitor_db
  sudo python3 syscall_monitor.py --batch-size 50 --flush-interval 3
        """
    )
    
    parser.add_argument("--db-host", default="localhost", help="数据库主机")
    parser.add_argument("--db-port", type=int, default=5432, help="数据库端口")
    parser.add_argument("--db-name", default="monitor_db", help="数据库名称")
    parser.add_argument("--db-user", default="postgres", help="数据库用户")
    parser.add_argument("--db-password", default="", help="数据库密码")
    parser.add_argument("--batch-size", type=int, default=100, help="批量写入大小")
    parser.add_argument("--flush-interval", type=float, default=5.0, help="刷新间隔（秒）")
    parser.add_argument("--no-db", action="store_true", help="不使用数据库，仅控制台输出")
    
    args = parser.parse_args()
    
    # 配置数据库
    db_config = None
    if not args.no_db and HAS_PSYCOPG2:
        db_config = {
            "host": args.db_host,
            "port": args.db_port,
            "dbname": args.db_name,
            "user": args.db_user,
            "password": args.db_password
        }
    
    # 创建并启动监控器
    monitor = SyscallMonitor(
        db_config=db_config,
        batch_size=args.batch_size,
        flush_interval=args.flush_interval
    )
    
    monitor.start()


if __name__ == "__main__":
    main()
