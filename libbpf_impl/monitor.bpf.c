#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "monitor.h"

char LICENSE[] SEC("license") = "GPL";

// 定义 Ring Buffer (比 Perf Buffer 更高效)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB
} rb SEC(".maps");

// ==================== FD -> Path 映射相关 ====================

// fd_key: 用于 fd -> path 映射的 key (pid + fd)
struct fd_key {
    u32 pid;
    u32 fd;
};

// fd_info: 存储文件路径
struct fd_info {
    char path[MAX_FILENAME_LEN];
};

// BPF Hash Map: 存储 (pid, fd) -> path 映射
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);  // 最多缓存 10K 个 fd
    __type(key, struct fd_key);
    __type(value, struct fd_info);
} fd_path_map SEC(".maps");

// 临时存储 openat 参数 (用于在 enter 和 exit 之间传递)
struct openat_args {
    char filename[MAX_FILENAME_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);  // pid_tgid
    __type(value, struct openat_args);
} openat_args_map SEC(".maps");

// 临时存储 fd_info，避免栈溢出 (Per-CPU Array)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct fd_info);
} tmp_fd_info_map SEC(".maps");

// 辅助函数：获取父进程 PID
static __always_inline int get_ppid(struct task_struct *task)
{
    struct task_struct *parent;
    // 使用 CO-RE 读取 real_parent
    parent = BPF_CORE_READ(task, real_parent);
    return BPF_CORE_READ(parent, tgid);
}

// 过滤自身的 PID (由用户态注入)
// [FIX] 移除 const，将其放入 .data 段，避免某些编译器版本的 .rodata 问题
volatile int filter_pid = 0;

// 辅助函数：检查是否需要过滤
static __always_inline int should_trace(u32 pid) {
    if (filter_pid != 0 && pid == filter_pid) {
        return 0;
    }
    
    // [FIX] 双重保险：如果 PID 过滤失败，检查进程名
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // 简单的字符串比较 "monitor"
    // 注意：BPF 中没有 strcmp，需要手动比较
    if (comm[0] == 'm' && comm[1] == 'o' && comm[2] == 'n' && 
        comm[3] == 'i' && comm[4] == 't' && comm[5] == 'o' && comm[6] == 'r') {
        return 0;
    }
    
    return 1;
}

// 1. 监控 execve
SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (!should_trace(pid)) return 0;
    
    // 预留 Ring Buffer 空间
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    
    e->pid = pid;
    e->ppid = get_ppid(task);
    e->uid = bpf_get_current_uid_gid();
    e->event_type = EVENT_EXEC;
    e->timestamp = bpf_ktime_get_ns();
    
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    // 读取文件名 (第一个参数)
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (const char *)ctx->args[0]);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// 2. 监控 exit (用于 fork/clone 返回)
SEC("tp/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    struct event *e;
    u32 pid = ctx->parent_pid;

    if (!should_trace(pid)) return 0;
    
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    
    e->pid = pid; 
    e->ppid = ctx->parent_pid; 
    e->uid = bpf_get_current_uid_gid();
    e->event_type = EVENT_FORK;
    e->timestamp = bpf_ktime_get_ns();
    e->fd = ctx->child_pid; 
    
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->filename[0] = '\0'; 
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// 3. 监控 write (使用 fd_path_map 查询路径)
SEC("tp/syscalls/sys_enter_write")
int handle_write(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (!should_trace(pid)) return 0;
    
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    
    e->pid = pid;
    e->ppid = get_ppid(task);
    e->uid = bpf_get_current_uid_gid();
    e->event_type = EVENT_WRITE;
    e->timestamp = bpf_ktime_get_ns();
    e->fd = ctx->args[0];
    e->size = ctx->args[2];
    
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    // 从 fd_path_map 查询文件路径
    struct fd_key key = { .pid = pid, .fd = e->fd };
    struct fd_info *info = bpf_map_lookup_elem(&fd_path_map, &key);
    if (info) {
        __builtin_memcpy(e->filename, info->path, MAX_FILENAME_LEN);
    } else {
        e->filename[0] = '\0';
    }
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// 4. 监控 read (使用 fd_path_map 查询路径)
SEC("tp/syscalls/sys_enter_read")
int handle_read(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (!should_trace(pid)) return 0;
    
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    
    e->pid = pid;
    e->ppid = get_ppid(task);
    e->uid = bpf_get_current_uid_gid();
    e->event_type = EVENT_READ;
    e->timestamp = bpf_ktime_get_ns();
    e->fd = ctx->args[0];
    e->size = ctx->args[2];
    
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    // 从 fd_path_map 查询文件路径
    struct fd_key key = { .pid = pid, .fd = e->fd };
    struct fd_info *info = bpf_map_lookup_elem(&fd_path_map, &key);
    if (info) {
        __builtin_memcpy(e->filename, info->path, MAX_FILENAME_LEN);
    } else {
        e->filename[0] = '\0';
    }
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ==================== openat/close 监控 ====================

// 5. 监控 openat 入口 (记录文件名参数)
SEC("tp/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    if (!should_trace(pid)) return 0;
    
    struct openat_args args = {};
    // args[1] 是 filename (args[0] 是 dirfd)
    bpf_probe_read_user_str(&args.filename, sizeof(args.filename), (const char *)ctx->args[1]);
    
    bpf_map_update_elem(&openat_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

// 6. 监控 openat 返回 (获取返回的 fd，建立映射)
SEC("tp/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    long ret = ctx->ret;
    
    // 忽略失败的 openat
    if (ret < 0) {
        bpf_map_delete_elem(&openat_args_map, &pid_tgid);
        return 0;
    }
    
    // 从临时 map 获取 filename
    struct openat_args *args = bpf_map_lookup_elem(&openat_args_map, &pid_tgid);
    if (!args) return 0;
    
    // 建立 fd -> path 映射
    struct fd_key key = { .pid = pid, .fd = (u32)ret };
    
    // 使用 Per-CPU Array Map 作为临时存储，避免栈溢出
    u32 zero = 0;
    struct fd_info *info = bpf_map_lookup_elem(&tmp_fd_info_map, &zero);
    if (!info) return 0;
    
    __builtin_memcpy(info->path, args->filename, MAX_FILENAME_LEN);
    
    bpf_map_update_elem(&fd_path_map, &key, info, BPF_ANY);
    
    // 清理临时存储
    bpf_map_delete_elem(&openat_args_map, &pid_tgid);
    return 0;
}

// 7. 监控 close (清理 fd -> path 映射)
SEC("tp/syscalls/sys_enter_close")
int handle_close(struct trace_event_raw_sys_enter *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 fd = ctx->args[0];
    
    // 从映射中删除
    struct fd_key key = { .pid = pid, .fd = fd };
    bpf_map_delete_elem(&fd_path_map, &key);
    
    return 0;
}
