# -*- coding: utf-8 -*-
"""
WMI 弱口令测试核心引擎
======================
仅做「凭据能否通过 WMI/DCOM 登录」的连通性验证，**不执行任何远程命令**。

判定逻辑：
  1. 建立 SMB 连接并 login（验证 SMB 身份）
  2. 建立 DCOM 连接并通过 IWbemLevel1Login.NTLMLogin 登录 root/cimv2
  两个环节都成功，才算「弱口令存在」。

依赖：impacket
兼容：Python 3.8+
"""

import socket
from dataclasses import dataclass
from typing import Optional, Callable

try:
    from impacket.dcerpc.v5.dcomrt import DCOMConnection
    from impacket.dcerpc.v5.dcom import wmi
    from impacket.dcerpc.v5.dtypes import NULL
except ImportError:
    DCOMConnection = None
    wmi = None
    NULL = None


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------

@dataclass
class Credential:
    """一条凭据"""
    username: str
    password: str = ""
    domain: str = ""          # 空字符串表示使用 username 本身（本地账户）


@dataclass
class Target:
    """一个目标主机"""
    host: str                 # IP 或主机名
    port: int = 445           # SMB 端口，WMI 走 SMB/DCOM，通常 445


@dataclass
class TestResult:
    """单次测试结果"""
    host: str
    username: str
    domain: str
    password: str
    success: bool
    error: str = ""
    method: str = ""          # NTLM / Kerberos


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

def resolve_host(host: str) -> str:
    """把主机名解析为 IP；已经是 IP 则原样返回。DCOM 需要 IP。"""
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        return socket.gethostbyname(host)


def split_domain_user(account: str) -> tuple:
    """把 DOMAIN/user 或 user@domain 拆成 (user, domain)"""
    account = account.strip()
    if "/" in account:
        domain, user = account.split("/", 1)
        return user.strip(), domain.strip()
    if "\\" in account:
        domain, user = account.split("\\", 1)
        return user.strip(), domain.strip()
    if "@" in account and "/" not in account:
        user, domain = account.rsplit("@", 1)
        return user.strip(), domain.strip()
    return account, ""


# ---------------------------------------------------------------------------
# 核心测试逻辑
# ---------------------------------------------------------------------------

def test_credential(
    target: Target,
    cred: Credential,
    timeout: int = 10,
    use_kerberos: bool = False,
    kdc_host: str = "",
) -> TestResult:
    """
    测试单条凭据对单个目标是否可用。
    返回 TestResult。
    """
    host = target.host
    username = cred.username
    password = cred.password
    domain = cred.domain

    result = TestResult(
        host=host, username=username, domain=domain,
        password=password, success=False, method="Kerberos" if use_kerberos else "NTLM",
    )

    if DCOMConnection is None:
        result.error = "未安装 impacket，请先 pip install -r requirements.txt"
        return result

    dcom = None
    smb = None
    try:
        remote_ip = resolve_host(host)
    except Exception as e:
        result.error = f"主机名解析失败: {e}"
        return result

    try:
        # ---- 第一步：SMB 身份校验 ----
        from impacket.smbconnection import SMBConnection
        smb = SMBConnection(remote_ip, host, timeout=timeout)
        if use_kerberos:
            smb.kerberosLogin(username, password, domain, "", "", "",
                              kdcHost=kdc_host or None)
        else:
            smb.login(username, password, domain, "", "")

        # ---- 第二步：DCOM / WMI 登录校验 ----
        dcom = DCOMConnection(
            remote_ip, username, password, domain, "", "", "",
            oxidResolver=True,
            doKerberos=use_kerberos,
            kdcHost=kdc_host or None,
            remoteHost=host,
        )
        iinterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,
                                             wmi.IID_IWbemLevel1Login)
        wbem_login = wmi.IWbemLevel1Login(iinterface)
        wbem_services = wbem_login.NTLMLogin("//./root/cimv2", NULL, NULL)
        wbem_login.RemRelease()

        result.success = True
        result.error = ""
        return result

    except Exception as e:
        msg = str(e)
        lowered = msg.lower()
        if "status_logon_failure" in lowered or "login failure" in lowered or "拒绝访问" in msg:
            result.error = "登录失败（账号或密码错误）"
        elif "timed out" in lowered or "timeout" in lowered or "10060" in msg:
            result.error = "连接超时"
        elif "no route" in lowered or "network is unreachable" in lowered:
            result.error = "网络不可达"
        elif "refused" in lowered:
            result.error = "连接被拒绝（目标端口未开放）"
        elif "not found" in lowered and ("kdc" in lowered or "kerberos" in lowered):
            result.error = "Kerberos KDC 未找到"
        else:
            result.error = msg
        return result

    finally:
        try:
            if smb:
                smb.logoff()
        except Exception:
            pass
        try:
            if dcom:
                dcom.disconnect()
        except Exception:
            pass
