#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "monitor.h"
#include "monitor.skel.h"

// 路径解析缓存，避免重复 readlink
#define PATH_CACHE_SIZE 1024
struct path_cache_entry {
    int pid;
    int fd;
    char path[256];
};
static struct path_cache_entry path_cache[PATH_CACHE_SIZE];
static int cache_idx = 0;

// 通过 /proc/<pid>/fd/<fd> 解析文件路径
static const char* resolve_fd_path(int pid, int fd, char *buf, size_t bufsize)
{
    // 标准 FD 直接返回
    if (fd == 0) return "stdin";
    if (fd == 1) return "stdout";
    if (fd == 2) return "stderr";
    
    // 检查缓存
    for (int i = 0; i < PATH_CACHE_SIZE; i++) {
        if (path_cache[i].pid == pid && path_cache[i].fd == fd) {
            return path_cache[i].path;
        }
    }
    
    // 构建 /proc/<pid>/fd/<fd> 路径
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/fd/%d", pid, fd);
    
    ssize_t len = readlink(proc_path, buf, bufsize - 1);
    if (len > 0) {
        buf[len] = '\0';
        
        // 缓存结果
        path_cache[cache_idx].pid = pid;
        path_cache[cache_idx].fd = fd;
        strncpy(path_cache[cache_idx].path, buf, sizeof(path_cache[cache_idx].path) - 1);
        cache_idx = (cache_idx + 1) % PATH_CACHE_SIZE;
        
        return buf;
    }
    
    // 解析失败，返回 fd:N 格式
    snprintf(buf, bufsize, "fd:%d", fd);
    return buf;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;
static FILE *log_fp = NULL;

static void sig_handler(int sig)
{
    exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    const char *type_str = "UNKNOWN";
    const char *file_path;
    char path_buf[256];
    
    switch (e->event_type) {
        case EVENT_EXEC: type_str = "EXEC"; break;
        case EVENT_FORK: type_str = "FORK"; break;
        case EVENT_READ: type_str = "READ"; break;
        case EVENT_WRITE: type_str = "WRITE"; break;
    }
    
    // 根据事件类型决定路径来源
    if (e->event_type == EVENT_EXEC) {
        // EXEC 事件：直接使用内核传来的 filename
        file_path = e->filename;
    } else if (e->event_type == EVENT_FORK) {
        // FORK 事件：fd 字段存的是子进程 PID
        snprintf(path_buf, sizeof(path_buf), "child_pid:%d", e->fd);
        file_path = path_buf;
    } else {
        // READ/WRITE 事件：优先使用内核态填充的路径
        if (e->filename[0] != '\0') {
            file_path = e->filename;
        } else {
            // 内核态未找到映射，回退到 /proc 解析
            file_path = resolve_fd_path(e->pid, e->fd, path_buf, sizeof(path_buf));
        }
    }
    
    // 输出到 stdout
    printf("[%-5s] PID: %-6d PPID: %-6d COMM: %-16s FD: %-3d SIZE: %-6llu FILE: %s\n",
           type_str, e->pid, e->ppid, e->comm, e->fd, e->size, file_path);
    
    // 输出到日志文件
    if (log_fp) {
        fprintf(log_fp, "[%-5s] PID: %-6d PPID: %-6d COMM: %-16s FD: %-3d SIZE: %-6llu FILE: %s\n",
               type_str, e->pid, e->ppid, e->comm, e->fd, e->size, file_path);
    }
           
    return 0;
}

int main(int argc, char **argv)
{
    struct monitor_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    // 打开日志文件
    log_fp = fopen("monitor.log", "w");
    if (log_fp) {
        // 设置行缓冲，确保实时写入
        setlinebuf(log_fp);
        printf("Logging to monitor.log...\n");
    } else {
        fprintf(stderr, "Failed to open monitor.log: %s\n", strerror(errno));
    }

    // 设置 libbpf 调试输出
    libbpf_set_print(libbpf_print_fn);

    // 1. 加载并验证 BPF 程序
    skel = monitor_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // [FIX] 注入当前进程 PID，防止监控自己产生死循环
    // 注意：变量初始化为 0 会被放入 .bss 段
    skel->bss->filter_pid = getpid();
    printf("Filtering PID: %d\n", getpid());

    // 2. 加载进内核
    err = monitor_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    // 3. 挂载 Tracepoints
    err = monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    // 4. 设置 Ring Buffer 回调
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Successfully started! Logs are being written to monitor.log\n");
    printf("Ctrl+C to stop.\n");

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 5. 循环轮询
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout ms */);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    if (log_fp) fclose(log_fp);
    ring_buffer__free(rb);
    monitor_bpf__destroy(skel);
    return -err;
}
