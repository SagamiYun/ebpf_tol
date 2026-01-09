-- PostgreSQL 数据库初始化脚本
-- 使用方式: psql -U postgres -f init_db.sql

-- 创建数据库
CREATE DATABASE monitor_db;

-- 连接到数据库
\c monitor_db

-- 创建审计日志表
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    pid INTEGER NOT NULL,
    ppid INTEGER DEFAULT 0,
    uid INTEGER DEFAULT 0,
    event_type VARCHAR(16) NOT NULL,
    fd INTEGER DEFAULT 0,
    size BIGINT DEFAULT 0,
    path TEXT,
    comm VARCHAR(64),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 创建索引以加速查询
CREATE INDEX idx_audit_log_pid ON audit_log(pid);
CREATE INDEX idx_audit_log_event_type ON audit_log(event_type);
CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX idx_audit_log_path ON audit_log(path) WHERE path IS NOT NULL;
CREATE INDEX idx_audit_log_comm ON audit_log(comm);

-- 创建复合索引用于常见查询模式
CREATE INDEX idx_audit_log_pid_type ON audit_log(pid, event_type);
CREATE INDEX idx_audit_log_time_range ON audit_log(timestamp DESC);

-- 创建分区表（可选，用于大量数据场景）
-- 按天分区示例：
-- CREATE TABLE audit_log_partitioned (
--     LIKE audit_log INCLUDING ALL
-- ) PARTITION BY RANGE (timestamp);

-- 创建视图：进程执行历史
CREATE VIEW v_exec_history AS
SELECT 
    pid,
    ppid,
    uid,
    path AS binary_path,
    comm AS process_name,
    timestamp AS exec_time
FROM audit_log
WHERE event_type = 'EXEC'
ORDER BY timestamp DESC;

-- 创建视图：文件访问统计
CREATE VIEW v_file_access_stats AS
SELECT 
    path,
    event_type,
    COUNT(*) AS access_count,
    SUM(size) AS total_bytes,
    MIN(timestamp) AS first_access,
    MAX(timestamp) AS last_access
FROM audit_log
WHERE event_type IN ('READ', 'WRITE')
  AND path NOT LIKE 'fd:%'
GROUP BY path, event_type
ORDER BY access_count DESC;

-- 创建视图：进程活动摘要
CREATE VIEW v_process_summary AS
SELECT 
    comm AS process_name,
    COUNT(CASE WHEN event_type = 'EXEC' THEN 1 END) AS exec_count,
    COUNT(CASE WHEN event_type = 'FORK' THEN 1 END) AS fork_count,
    COUNT(CASE WHEN event_type = 'READ' THEN 1 END) AS read_count,
    COUNT(CASE WHEN event_type = 'WRITE' THEN 1 END) AS write_count
FROM audit_log
GROUP BY comm
ORDER BY exec_count + fork_count + read_count + write_count DESC;

-- 授权（根据实际用户名修改）
-- GRANT ALL PRIVILEGES ON DATABASE monitor_db TO your_user;
-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO your_user;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO your_user;

-- 插入测试数据（可选）
-- INSERT INTO audit_log (pid, ppid, uid, event_type, path, comm) 
-- VALUES (1234, 1, 0, 'EXEC', '/usr/bin/bash', 'bash');

COMMENT ON TABLE audit_log IS '系统调用审计日志表';
COMMENT ON COLUMN audit_log.pid IS '进程 ID';
COMMENT ON COLUMN audit_log.ppid IS '父进程 ID';
COMMENT ON COLUMN audit_log.uid IS '用户 ID';
COMMENT ON COLUMN audit_log.event_type IS '事件类型: EXEC, FORK, READ, WRITE';
COMMENT ON COLUMN audit_log.fd IS '文件描述符 (仅 READ/WRITE)';
COMMENT ON COLUMN audit_log.size IS '读写大小 (字节)';
COMMENT ON COLUMN audit_log.path IS '文件路径或二进制路径';
COMMENT ON COLUMN audit_log.comm IS '进程名';
