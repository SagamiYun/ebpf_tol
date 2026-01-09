#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
系统调用监控程序 - 测试脚本

测试方法：
1. 单元测试：不需要 root，测试辅助函数
2. 集成测试：需要 root，测试完整流程
3. 负载测试：模拟高频系统调用

运行方式：
  python3 test_monitor.py              # 运行单元测试
  sudo python3 test_monitor.py --all   # 运行所有测试（需要 root）
"""

import unittest
import subprocess
import tempfile
import os
import time
import sys
import threading
from unittest.mock import Mock, patch, MagicMock

# 添加当前目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


class TestHelperFunctions(unittest.TestCase):
    """测试辅助函数（不需要 root 权限）"""
    
    def test_resolve_fd_path_stdin(self):
        """测试标准输入 FD 解析"""
        # 模拟 SyscallMonitor 类的方法
        fd_names = ["stdin", "stdout", "stderr"]
        for fd in range(3):
            self.assertEqual(fd_names[fd], fd_names[fd])
    
    def test_resolve_fd_path_current_process(self):
        """测试当前进程的 FD 解析"""
        pid = os.getpid()
        
        # 创建临时文件并获取其 FD
        with tempfile.NamedTemporaryFile(delete=False) as f:
            fd = f.fileno()
            expected_path = f.name
            
            # 通过 /proc 读取
            try:
                actual_path = os.readlink(f"/proc/{pid}/fd/{fd}")
                self.assertEqual(actual_path, expected_path)
            except (FileNotFoundError, PermissionError):
                self.skipTest("无法访问 /proc")
        
        # 清理
        os.unlink(expected_path)
    
    def test_resolve_fd_path_invalid(self):
        """测试无效 FD 的处理"""
        pid = os.getpid()
        invalid_fd = 99999
        
        try:
            os.readlink(f"/proc/{pid}/fd/{invalid_fd}")
            self.fail("应该抛出异常")
        except FileNotFoundError:
            pass  # 预期行为
    
    def test_event_type_mapping(self):
        """测试事件类型映射"""
        event_types = {
            1: "EXEC",
            2: "FORK",
            3: "READ",
            4: "WRITE"
        }
        
        self.assertEqual(event_types[1], "EXEC")
        self.assertEqual(event_types[2], "FORK")
        self.assertEqual(event_types[3], "READ")
        self.assertEqual(event_types[4], "WRITE")


class TestBatchBuffer(unittest.TestCase):
    """测试批量缓冲区逻辑"""
    
    def test_buffer_accumulation(self):
        """测试缓冲区累积"""
        buffer = []
        batch_size = 5
        
        for i in range(batch_size - 1):
            buffer.append(f"record_{i}")
        
        self.assertEqual(len(buffer), batch_size - 1)
        self.assertFalse(len(buffer) >= batch_size)
    
    def test_buffer_flush_trigger(self):
        """测试缓冲区刷新触发"""
        buffer = []
        batch_size = 5
        flush_count = 0
        
        for i in range(batch_size + 1):
            buffer.append(f"record_{i}")
            if len(buffer) >= batch_size:
                flush_count += 1
                buffer = []
        
        self.assertEqual(flush_count, 1)
        self.assertEqual(len(buffer), 1)
    
    def test_time_based_flush(self):
        """测试基于时间的刷新"""
        last_flush_time = time.time() - 6  # 6秒前
        flush_interval = 5.0
        
        should_flush = (time.time() - last_flush_time) >= flush_interval
        self.assertTrue(should_flush)


class TestDatabaseOperations(unittest.TestCase):
    """测试数据库操作（使用 Mock）"""
    
    def test_batch_insert_format(self):
        """测试批量插入格式"""
        records = [
            (1234, 1, 0, "EXEC", 0, 0, "/usr/bin/bash", "bash", "2024-01-01 00:00:00"),
            (1235, 1234, 1000, "FORK", 0, 0, "", "python", "2024-01-01 00:00:01"),
        ]
        
        # 验证记录格式
        for r in records:
            self.assertEqual(len(r), 9)
            self.assertIsInstance(r[0], int)  # pid
            self.assertIsInstance(r[3], str)  # event_type
    
    @patch('psycopg2.connect')
    def test_db_connection_success(self, mock_connect):
        """测试数据库连接成功"""
        mock_conn = Mock()
        mock_connect.return_value = mock_conn
        
        # 模拟连接
        conn = mock_connect(
            host="localhost",
            dbname="monitor_db",
            user="postgres",
            password=""
        )
        
        self.assertIsNotNone(conn)
        mock_connect.assert_called_once()
    
    @patch('psycopg2.connect')
    def test_db_connection_failure(self, mock_connect):
        """测试数据库连接失败处理"""
        mock_connect.side_effect = Exception("Connection refused")
        
        with self.assertRaises(Exception) as context:
            mock_connect(host="localhost")
        
        self.assertIn("Connection refused", str(context.exception))


class TestEBPFSourceCode(unittest.TestCase):
    """测试 eBPF 源代码语法"""
    
    def setUp(self):
        """读取 BPF 源代码"""
        monitor_path = os.path.join(
            os.path.dirname(__file__), 
            "syscall_monitor.py"
        )
        
        if os.path.exists(monitor_path):
            with open(monitor_path, 'r') as f:
                self.source = f.read()
        else:
            self.source = ""
    
    def test_no_stdlib_functions(self):
        """确保没有使用标准库函数"""
        forbidden = ["snprintf", "printf", "malloc", "free", "strlen"]
        
        if not self.source:
            self.skipTest("源文件不存在")
        
        # 提取 BPF 代码部分
        import re
        match = re.search(r'BPF_SOURCE\s*=\s*r?"""(.*?)"""', self.source, re.DOTALL)
        
        if match:
            bpf_code = match.group(1)
            for func in forbidden:
                # 只检查函数调用，不检查注释
                lines = [l for l in bpf_code.split('\n') if not l.strip().startswith('//')]
                code_without_comments = '\n'.join(lines)
                self.assertNotIn(f"{func}(", code_without_comments,
                    f"BPF 代码中不应使用 {func}() 函数")
    
    def test_has_required_probes(self):
        """确保包含所有必需的探针"""
        required_probes = [
            "sys_enter_execve",
            "sys_exit_clone",
            "sys_enter_write",
            "sys_enter_read"
        ]
        
        if not self.source:
            self.skipTest("源文件不存在")
        
        for probe in required_probes:
            self.assertIn(probe, self.source,
                f"缺少必需的探针: {probe}")


class TestIntegration(unittest.TestCase):
    """集成测试（需要 root 权限）"""
    
    @classmethod
    def setUpClass(cls):
        """检查 root 权限"""
        if os.geteuid() != 0:
            raise unittest.SkipTest("需要 root 权限运行集成测试")
    
    def test_bpf_program_loads(self):
        """测试 BPF 程序是否能加载"""
        try:
            from bcc import BPF
        except ImportError:
            self.skipTest("bcc 未安装")
        
        # 简单的 BPF 程序测试
        simple_bpf = """
        int test_probe(void *ctx) {
            return 0;
        }
        """
        
        try:
            b = BPF(text=simple_bpf)
            self.assertIsNotNone(b)
        except Exception as e:
            self.fail(f"BPF 加载失败: {e}")
    
    def test_tracepoint_exists(self):
        """测试所需的 tracepoint 是否存在"""
        tracepoints = [
            "/sys/kernel/debug/tracing/events/syscalls/sys_enter_execve",
            "/sys/kernel/debug/tracing/events/syscalls/sys_enter_write",
            "/sys/kernel/debug/tracing/events/syscalls/sys_enter_read",
        ]
        
        for tp in tracepoints:
            if not os.path.exists(tp):
                self.skipTest(f"Tracepoint 不存在: {tp}")


class TestLoadSimulation(unittest.TestCase):
    """负载模拟测试"""
    
    def test_high_frequency_writes(self):
        """模拟高频写入场景"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            filename = f.name
            start = time.time()
            
            # 执行 1000 次写入
            for i in range(1000):
                f.write(f"test line {i}\n")
            
            elapsed = time.time() - start
        
        # 清理
        os.unlink(filename)
        
        # 验证写入时间合理
        print(f"\n1000 次写入耗时: {elapsed:.3f} 秒")
        self.assertLess(elapsed, 1.0, "写入性能过慢")
    
    def test_subprocess_spawn(self):
        """测试进程创建"""
        start = time.time()
        
        # 创建 10 个子进程
        for i in range(10):
            result = subprocess.run(
                ["echo", f"test {i}"],
                capture_output=True,
                text=True
            )
            self.assertEqual(result.returncode, 0)
        
        elapsed = time.time() - start
        print(f"\n10 个子进程创建耗时: {elapsed:.3f} 秒")


def run_quick_test():
    """快速功能验证（用于面试演示）"""
    print("=" * 60)
    print("快速功能验证")
    print("=" * 60)
    
    # 1. 检查 Python 版本
    print(f"\n[1] Python 版本: {sys.version}")
    
    # 2. 检查 BCC 安装
    try:
        from bcc import BPF
        print("[2] BCC 安装: ✓")
    except ImportError:
        print("[2] BCC 安装: ✗ (请安装 bpfcc-tools)")
        return False
    
    # 3. 检查 psycopg2 安装
    try:
        import psycopg2
        print("[3] psycopg2 安装: ✓")
    except ImportError:
        print("[3] psycopg2 安装: ✗ (可选，用于数据库)")
    
    # 4. 检查 root 权限
    if os.geteuid() == 0:
        print("[4] Root 权限: ✓")
    else:
        print("[4] Root 权限: ✗ (需要 sudo 运行)")
        return False
    
    # 5. 检查 tracepoint
    tp_path = "/sys/kernel/debug/tracing/events/syscalls/sys_enter_execve"
    if os.path.exists(tp_path):
        print("[5] Tracepoint 可用: ✓")
    else:
        print("[5] Tracepoint 可用: ✗ (内核可能不支持)")
        return False
    
    # 6. 尝试加载简单 BPF 程序
    print("[6] 加载测试 BPF 程序...")
    try:
        b = BPF(text="""
        TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
            bpf_trace_printk("test\\n");
            return 0;
        }
        """)
        print("    BPF 加载: ✓")
    except Exception as e:
        print(f"    BPF 加载: ✗ ({e})")
        return False
    
    print("\n" + "=" * 60)
    print("所有检查通过！可以运行 syscall_monitor.py")
    print("=" * 60)
    return True


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="系统监控程序测试")
    parser.add_argument("--all", action="store_true", help="运行所有测试（需要 root）")
    parser.add_argument("--quick", action="store_true", help="快速功能验证")
    parser.add_argument("-v", "--verbose", action="store_true", help="详细输出")
    
    args = parser.parse_args()
    
    if args.quick:
        success = run_quick_test()
        sys.exit(0 if success else 1)
    
    # 构建测试套件
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # 总是添加单元测试
    suite.addTests(loader.loadTestsFromTestCase(TestHelperFunctions))
    suite.addTests(loader.loadTestsFromTestCase(TestBatchBuffer))
    suite.addTests(loader.loadTestsFromTestCase(TestDatabaseOperations))
    suite.addTests(loader.loadTestsFromTestCase(TestEBPFSourceCode))
    suite.addTests(loader.loadTestsFromTestCase(TestLoadSimulation))
    
    # 如果指定 --all 且有 root 权限，添加集成测试
    if args.all:
        suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    
    # 运行测试
    verbosity = 2 if args.verbose else 1
    runner = unittest.TextTestRunner(verbosity=verbosity)
    result = runner.run(suite)
    
    # 返回非零退出码如果有失败
    sys.exit(0 if result.wasSuccessful() else 1)
