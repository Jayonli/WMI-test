# WMI 弱口令测试工具 v1.1

已知账号密码，批量验证目标主机是否存在 **WMI 弱口令**（凭据能否通过 SMB + DCOM/WMI 登录），
并支持对已验证成功的目标**执行远程命令**。

> ⚠️ **仅限在拥有合法授权的目标上测试。** 使用本工具产生的任何后果由使用者自行承担。

---

## 目录结构

```
wmi_weakpass/
├── run_gui.py                 # 启动脚本（python run_gui.py）
├── requirements.txt           # Python 依赖
├── README.md
└── wmi_weakpass/              # 包目录（必须与 run_gui.py 同级）
    ├── __init__.py
    ├── core.py                # 凭据验证核心（SMB + DCOM 两步验证）
    ├── runner.py              # 多线程并发调度
    ├── executor.py            # 【命令执行】远程命令执行模块
    ├── gui.py                 # Tkinter 图形界面
    └── tests.py               # 单元测试
```

> 注意：目录下必须存在 `wmi_weakpass/` 这个**同名子包**，否则会报
> `ModuleNotFoundError: No module named 'wmi_weakpass'`。
> 如果解压后 `.py` 文件都平铺在根目录，说明解压丢了顶层目录，需手动归位。

---

## 环境准备

1. 安装 **Python 3.8 ~ 3.11**（推荐 3.10）。
   Windows 版下载：https://www.python.org/downloads/ ，安装时勾选
   `Add Python to PATH`。

2. 安装依赖：

   ```bat
   pip install -r requirements.txt
   ```

   国内网络慢可换源：

   ```bat
   pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
   ```

3. 启动：

   ```bat
   python run_gui.py
   ```

---

## 使用流程

### 一、弱口令验证

1. 在「目标主机」填写 IP / 主机名 / CIDR 网段（一行一个）。
2. 在「凭据」填写 `用户名:密码`，支持 `DOMAIN/用户:密码`、`用户@域:密码`。
3. 设置并发线程数、超时、认证方式（NTLM / Kerberos）。
4. 点「开始测试」，绿色行=凭据可用，橙色行=失败。
5. 点「导出成功凭据」把结果存成 CSV。

### 二、命令执行（v1.1 新增）

1. 先完成扫描，让「扫描结果」出现成功项。
2. 切到「命令执行」标签页。
3. **勾选授权确认**（必选，未勾选无法执行）。
4. 选择目标（自动列出已验证成功的凭据）。
5. 输入命令点「执行」，结果实时显示在下方。
6. 可先用「安全探活」跑一条只读 `whoami`，确认远程执行通道可用。

**安全约束：**

- 高危命令（`rm` / `format` / `shutdown` / `net user` / `reg delete` 等）
  默认**拦截**，需在授权确认下方勾选「放行高危命令」才执行。
- 命令通过 `Win32_Process.Create` 执行，输出重定向到 `ADMIN$` 下的临时文件，
  回读后**自动清理**，不在目标留下持久化文件。
- 执行器会**复用已建立的连接**，避免每次执行都重新认证。

---

## 常见问题

**Q：`ModuleNotFoundError: No module named 'wmi_weakpass'`**
A：目录结构不对。确认 `run_gui.py` 与 `wmi_weakpass/` 文件夹在同一层，
且 `wmi_weakpass/` 下有 `__init__.py`、`core.py` 等文件。

**Q：`No module named 'impacket'`**
A：没装依赖。先 `pip install -r requirements.txt`。

**Q：扫描全失败 / 连不上**
A：目标需开放 **445 端口**；WMI 要求操作用户具有**管理员权限**；
防火墙需放行 SMB（445）与 DCOM（135 + 随机高端口）。

---

## 许可

本工具基于合法安全测试用途提供，使用者须确保对目标拥有充分授权。
