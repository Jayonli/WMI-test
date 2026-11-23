# -*- coding: utf-8 -*-
"""
WMI 远程命令执行模块
====================
在「凭据已通过验证」的前提下，对目标主机执行远程命令并取回输出。

执行方式：通过 WMI `Win32_Process.Create` 创建进程，命令输出重定向到
目标本地临时文件，再通过 SMB 读取回传（与 impacket wmiexec.py 思路一致）。

⚠ 安全约束：
  本模块要求调用方显式传入「已授权」标记。默认情况下 execute() 拒绝执行，
  必须在 GUI/脚本里明确确认目标已获授权后才能开启。
"""

import os
import re
import time
import uuid
import logging
import threading
from dataclasses import dataclass
from typing import Optional, Callable

try:
    from impacket.dcerpc.v5.dcomrt import DCOMConnection
    from impacket.dcerpc.v5.dcom import wmi
    from impacket.dcerpc.v5.dtypes import NULL
    from impacket.smbconnection import SMBConnection
except ImportError:
    DCOMConnection = None
    wmi = None
    NULL = None
    SMBConnection = None


# 高危命令黑名单：默认禁止执行，防止误操作。需要放行时由调用方显式配置。
DANGEROUS_PATTERNS = [
    r"\brm\s", r"\bdel\s", r"\bformat\s", r"\bshutdown\b", r"\breboot\b",
    r"\bnet\s+user\b", r"\bnet\s+group\b", r"\bnet\s+localgroup\b",
    r"\breg\s+delete\b", r"\breg\s+add\b", r"\bwevtutil\s+cl\b",
    r"\bcipher\s+/w\b", r"\bdd\s+if=", r"\bmkfs\b", r"\b>nul\b",
    r">\s*/dev/", r"\bpowershell\b.+-enc\b", r"\bwhoami\s+/priv\b",
]


@dataclass
class ExecResult:
    """一次命令执行的结果"""
    host: str
    command: str
    success: bool
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    error: str = ""
    duration: float = 0.0       # 耗时（秒）
    method: str = "WMI+TempFile"  # 执行方式


def is_command_safe(command: str, allow_dangerous: bool = False) -> tuple:
    """
    检查命令是否安全。
    返回 (is_safe, reason)。allow_dangerous=True 时跳过黑名单。
    """
    if not command.strip():
        return False, "命令为空"
    if allow_dangerous:
        return True, ""
    lowered = command.lower()
    for pat in DANGEROUS_PATTERNS:
        if re.search(pat, lowered):
            return False, f"命中高危命令规则：{pat}"
    # 禁止明显的多语句串联与重定向破坏
    if "&&" in command and not allow_dangerous:
        return False, "不支持多语句串联（&&），请逐条执行"
    if ";" in command and not allow_dangerous:
        return False, "不支持多语句串联（;），请逐条执行"
    return True, ""


class WMIExecutor:
    """
    WMI 远程命令执行器。

    典型用法：
        exe = WMIExecutor(
            host="192.168.1.10",
            username="admin", password="123456",
            domain="",
            authorized=True,            # 必须显式声明授权
            share="ADMIN$",
        )
        with exe:
            r = exe.execute("whoami")
            print(r.stdout)
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str = "",
        domain: str = "",
        authorized: bool = False,
        share: str = "ADMIN$",
        timeout: int = 30,
        allow_dangerous: bool = False,
        use_kerberos: bool = False,
        kdc_host: str = "",
        output_codec: str = "utf-8",
    ):
        self.host = host
        self.username = username
        self.password = password
        self.domain = domain
        self.authorized = authorized
        self.share = share
        self.timeout = timeout
        self.allow_dangerous = allow_dangerous
        self.use_kerberos = use_kerberos
        self.kdc_host = kdc_host
        self.output_codec = output_codec

        self._dcom = None
        self._smb = None
        self._win32_process = None
        self._remote_ip = ""
        self._pwd = "C:\\Windows\\System32"

    # ------------------------------------------------------------------
    # 生命周期
    # ------------------------------------------------------------------
    def connect(self) -> tuple:
        """
        建立 DCOM + SMB 连接并拿到 Win32_Process 接口。
        返回 (ok, msg)。连接失败时可据此提示。
        """
        if not self.authorized:
            return False, "未授权：必须显式声明目标已获合法授权"

        if DCOMConnection is None:
            return False, "未安装 impacket，请先 pip install -r requirements.txt"

        try:
            self._remote_ip = self._resolve(self.host)
        except Exception as e:
            return False, f"主机名解析失败: {e}"

        try:
            # SMB 连接用于回传输出文件
            self._smb = SMBConnection(self._remote_ip, self.host, timeout=self.timeout)
            if self.use_kerberos:
                self._smb.kerberosLogin(
                    self.username, self.password, self.domain, "", "", "",
                    kdcHost=self.kdc_host or None,
                )
            else:
                self._smb.login(self.username, self.password, self.domain, "", "")
        except Exception as e:
            return False, f"SMB 登录失败: {e}"

        try:
            self._dcom = DCOMConnection(
                self._remote_ip, self.username, self.password, self.domain,
                "", "", "",
                oxidResolver=True,
                doKerberos=self.use_kerberos,
                kdcHost=self.kdc_host or None,
                remoteHost=self.host,
            )
            iinterface = self._dcom.CoCreateInstanceEx(
                wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login
            )
            wbem_login = wmi.IWbemLevel1Login(iinterface)
            wbem_services = wbem_login.NTLMLogin("//./root/cimv2", NULL, NULL)
            wbem_login.RemRelease()
            self._win32_process, _ = wbem_services.GetObject("Win32_Process")
            return True, "连接成功"
        except Exception as e:
            self._cleanup()
            return False, f"DCOM/WMI 登录失败: {e}"

    def close(self):
        self._cleanup()

    def __enter__(self):
        ok, msg = self.connect()
        if not ok:
            raise RuntimeError(msg)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    # ------------------------------------------------------------------
    # 核心：执行命令
    # ------------------------------------------------------------------
    def execute(self, command: str) -> ExecResult:
        """在远程主机执行一条命令并返回结果。"""
        t0 = time.time()
        result = ExecResult(
            host=self.host, command=command, success=False,
            duration=0.0, method="WMI+TempFile",
        )

        # 1. 授权 + 安全检查
        if not self.authorized:
            result.error = "未授权：必须显式声明目标已获合法授权"
            return result
        safe, reason = is_command_safe(command, self.allow_dangerous)
        if not safe:
            result.error = f"命令被拦截：{reason}"
            return result

        # 2. 确保连接就绪
        if self._win32_process is None:
            ok, msg = self.connect()
            if not ok:
                result.error = msg
                result.duration = time.time() - t0
                return result

        # 3. 生成唯一临时文件名，避免并发冲突
        token = uuid.uuid4().hex[:8]
        out_file = f"__wmi_{token}.txt"
        remote_out = f"\\\\127.0.0.1\\{self.share}\\{out_file}"

        # 命令包成 cmd /c，输出重定向到临时文件
        wrapped = (
            f'cmd.exe /Q /c {command} > "{remote_out}" 2>&1'
        )

        try:
            resp = self._win32_process.Create(wrapped, self._pwd, None)
            # Impacket 的 Create 返回对象：字段为 ReturnValue / ProcessId
            # 兼容两种形式：对象属性、或元组 (return_value, process_id)
            return_value = None
            process_id = None
            if isinstance(resp, tuple):
                return_value, process_id = resp[0], resp[1]
            else:
                return_value = getattr(resp, "ReturnValue", None)
                process_id = getattr(resp, "ProcessId", None)
                if return_value is None:
                    # 部分版本返回 dict 结构
                    try:
                        return_value = resp["ReturnValue"]
                        process_id = resp.get("ProcessId", None)
                    except (TypeError, KeyError):
                        return_value = None
                # 兜底：有些版本把结果放在 resp.get() 里
                if return_value is None and hasattr(resp, "get"):
                    return_value = resp.get("ReturnValue", 0)

            # Win32_Process.Create 返回 0 表示创建成功（进程已启动）
            if return_value not in (0, None):
                result.error = (
                    f"进程创建失败，ReturnValue={return_value} "
                    f"（0=成功；2=拒绝访问；3=权限不足；8=内存不足；"
                    f"9=路径/共享无效；21=参数无效；{process_id})"
                )
                return result

            # 4. 等待进程写完输出并回读
            output = self._fetch_output(out_file, timeout=self.timeout)
            result.success = True
            result.stdout = output
            result.exit_code = 0
            result.stderr = ""
        except Exception as e:
            result.error = f"{type(e).__name__}: {e}"
        finally:
            result.duration = time.time() - t0

        return result

    def execute_safe_probe(self) -> ExecResult:
        """
        安全探活：只执行一条只读命令（whoami），用于确认凭据具备远程执行能力。
        不走黑名单检查，专供「验证命令执行是否可用」使用。
        """
        probe = 'echo WMI-EXEC-OK & whoami'
        # 临时绕过黑名单
        saved = self.allow_dangerous
        self.allow_dangerous = True
        try:
            return self.execute(probe)
        finally:
            self.allow_dangerous = saved

    # ------------------------------------------------------------------
    # 内部
    # ------------------------------------------------------------------
    def _fetch_output(self, filename: str, timeout: int = 30) -> str:
        """通过 SMB 读取远程临时输出文件，带重试与超时。"""
        if self._smb is None:
            return ""
        deadline = time.time() + timeout
        chunks = []

        def _writer(data):
            chunks.append(data)

        while time.time() < deadline:
            try:
                self._smb.getFile(self.share, filename, _writer)
                break
            except Exception as e:
                if "STATUS_SHARING_VIOLATION" in str(e):
                    # 远端进程还没写完，稍等重试
                    time.sleep(0.5)
                    continue
                if "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                    # 文件还没生成，稍等
                    time.sleep(0.3)
                    continue
                break

        # 清理远端临时文件
        try:
            self._smb.deleteFile(self.share, filename)
        except Exception:
            pass

        raw = b"".join(chunks)
        for enc in (self.output_codec, "utf-8", "gbk", "utf-16le"):
            try:
                return raw.decode(enc)
            except Exception:
                continue
        return raw.decode("utf-8", errors="replace")

    def _resolve(self, host: str) -> str:
        import socket
        try:
            socket.inet_aton(host)
            return host
        except OSError:
            return socket.gethostbyname(host)

    def _cleanup(self):
        if self._smb is not None:
            try:
                self._smb.logoff()
            except Exception:
                pass
            self._smb = None
        if self._dcom is not None:
            try:
                self._dcom.disconnect()
            except Exception:
                pass
            self._dcom = None
        self._win32_process = None


# ---------------------------------------------------------------------------
# 便捷函数
# ---------------------------------------------------------------------------
def quick_execute(
    host: str, username: str, password: str = "", domain: str = "",
    command: str = "whoami", authorized: bool = False, **kwargs,
) -> ExecResult:
    """一次性执行单条命令（自动连接/断开）。"""
    exe = WMIExecutor(
        host=host, username=username, password=password,
        domain=domain, authorized=authorized, **kwargs,
    )
    with exe:
        return exe.execute(command)
