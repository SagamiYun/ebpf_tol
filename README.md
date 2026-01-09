# 系统调用监控程序 (eBPF)

基于 eBPF 技术的 Linux 系统调用监控工具，用于审计 `exec/fork/read/write` 系统调用。

## 📋 功能特性

- ✅ 监控 `execve` (进程执行)
- ✅ 监控 `clone/fork` (进程创建)  
- ✅ 监控 `read/write` (文件 IO)
- ✅ 批量写入 PostgreSQL
- ✅ 低开销的 eBPF 实现

## 🔧 环境要求

- **操作系统**: Linux (内核版本 >= 4.15)
- **权限**: root
- **依赖**:
  - bcc-tools (eBPF 编译器集合)
  - Python 3.6+
  - psycopg2 (可选，用于数据库)

## 📦 安装依赖

### Ubuntu/Debian
```bash
# 安装 BCC
sudo apt update
sudo apt install -y bpfcc-tools python3-bpfcc

# 安装 Python 依赖
pip3 install psycopg2-binary
```

### CentOS/RHEL
```bash
sudo yum install -y bcc-tools python3-bcc
pip3 install psycopg2-binary
```

## 🚀 快速开始

### 1. 初始化数据库（可选）
```bash
# 创建 PostgreSQL 数据库和表
sudo -u postgres psql -f init_db.sql
```

### 2. 运行快速验证
```bash
sudo python3 test_monitor.py --quick
```

### 3. 启动监控
```bash
# 控制台输出模式（无数据库）
sudo python3 syscall_monitor.py --no-db

# 连接数据库模式
sudo python3 syscall_monitor.py \
    --db-host localhost \
    --db-name monitor_db \
    --db-user postgres \
    --db-password your_password
```

## 📊 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--db-host` | localhost | 数据库主机 |
| `--db-port` | 5432 | 数据库端口 |
| `--db-name` | monitor_db | 数据库名称 |
| `--db-user` | postgres | 数据库用户 |
| `--db-password` | | 数据库密码 |
| `--batch-size` | 100 | 批量写入大小 |
| `--flush-interval` | 5.0 | 刷新间隔（秒）|
| `--no-db` | | 不使用数据库 |

## 🧪 运行测试

```bash
# 单元测试（不需要 root）
python3 test_monitor.py

# 所有测试（需要 root）
sudo python3 test_monitor.py --all

# 详细输出
sudo python3 test_monitor.py --all -v
```

## 📁 文件结构

```
.
├── syscall_monitor.py  # 主程序
├── init_db.sql         # 数据库初始化脚本
├── test_monitor.py     # 测试脚本
├── README.md           # 本文件
└── task.md             # 原始题目分析
```

## 🔍 数据库查询示例

```sql
-- 查看最近的进程执行
SELECT * FROM v_exec_history LIMIT 10;

-- 查看文件访问统计
SELECT * FROM v_file_access_stats;

-- 查看特定进程的活动
SELECT * FROM audit_log WHERE comm = 'nginx' ORDER BY timestamp DESC;

-- 查看敏感文件访问
SELECT * FROM audit_log 
WHERE path LIKE '/etc/passwd%' OR path LIKE '/root/.ssh%';
```

## ⚠️ 注意事项

1. **性能考虑**: `read/write` 是高频系统调用，生产环境建议：
   - 仅监控特定进程
   - 仅监控敏感文件路径
   - 增大 `batch-size` 和 `flush-interval`

2. **FD 解析**: 通过 `/proc` 解析 FD 有竞态条件，短命进程可能解析失败

3. **数据库**: 大量数据建议使用 ClickHouse 替代 PostgreSQL

## 📝 面试要点

- 技术选型：eBPF 是唯一正解，避免 strace/ptrace
- 性能陷阱：了解 read/write 的高频特性
- FD→Path 映射：知道两种方案（/proc 和内核 Map）
- 批量写入：理解为什么不能逐条写入数据库

## 📄 License

MIT
