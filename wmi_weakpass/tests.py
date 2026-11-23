# -*- coding: utf-8 -*-
"""
核心逻辑单元测试（不依赖真实网络，只测解析与数据结构）。
运行：python -m wmi_weakpass.tests
"""

import sys
import os

# 支持「python tests.py」直接运行：把项目根目录加入 path
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from wmi_weakpass.core import Credential, Target
from wmi_weakpass.gui import expand_targets, parse_credentials
from wmi_weakpass.executor import is_command_safe


def assert_eq(name, got, expect):
    if got == expect:
        print(f"  ✓ {name}")
    else:
        print(f"  ✗ {name}\n    期望: {expect!r}\n    实际: {got!r}")
        sys.exit(1)


def test_expand_targets():
    print("[测试] 目标解析")
    r = expand_targets("192.168.1.10")
    assert_eq("单个 IP", r, [("192.168.1.10", 445)])

    r = expand_targets("10.0.0.1, 10.0.0.2\nWIN-01")
    hosts = [h for h, _ in r]
    assert_eq("多主机+主机名", set(hosts), {"10.0.0.1", "10.0.0.2", "WIN-01"})

    r = expand_targets("192.168.1.0/30")
    hosts = [h for h, _ in r]
    assert_eq("CIDR 展开", hosts, ["192.168.1.1", "192.168.1.2"])

    r = expand_targets("8.8.8.8\n8.8.8.8")
    assert_eq("重复去重", len(r), 1)


def test_parse_credentials():
    print("[测试] 凭据解析")
    r = parse_credentials("admin:123456")
    assert_eq("冒号分隔", r, [Credential("admin", "123456", "")])

    r = parse_credentials("admin 123456")
    assert_eq("空格分隔", r, [Credential("admin", "123456", "")])

    r = parse_credentials("CORP/admin:Pass@123")
    assert_eq("域账号", r, [Credential("admin", "Pass@123", "CORP")])

    r = parse_credentials("admin@corp.com:Pass")
    assert_eq("UPN 格式", r, [Credential("admin", "Pass", "corp.com")])

    r = parse_credentials("testuser")
    assert_eq("空密码", r, [Credential("testuser", "", "")])

    text = """admin:123
# 这是注释
guest:
CORP/root:pwd"""
    r = parse_credentials(text)
    assert_eq("混合+注释", len(r), 3)
    assert_eq("混合内容", r[1], Credential("guest", "", ""))


def test_target_model():
    print("[测试] 数据模型")
    t = Target(host="10.0.0.1")
    assert_eq("默认端口", t.port, 445)
    c = Credential(username="a", password="b", domain="D")
    assert_eq("凭据属性", c.domain, "D")


def test_command_safety():
    print("[测试] 命令安全检查")
    ok, _ = is_command_safe("whoami")
    assert_eq("普通命令放行", ok, True)

    ok, _ = is_command_safe("ipconfig /all")
    assert_eq("ipconfig 放行", ok, True)

    ok, reason = is_command_safe("rm -rf /")
    assert_eq("rm 被拦截", ok, False)

    ok, reason = is_command_safe("net user admin 123 /add")
    assert_eq("net user 被拦截", ok, False)

    ok, reason = is_command_safe("cmd /c whoami")
    assert_eq("cmd 包壳放行", ok, True)

    # 放行模式下不过滤
    ok, _ = is_command_safe("rm -rf /", allow_dangerous=True)
    assert_eq("放行模式不过滤", ok, True)


if __name__ == "__main__":
    test_expand_targets()
    test_parse_credentials()
    test_target_model()
    test_command_safety()
    print("\n✅ 全部测试通过")
