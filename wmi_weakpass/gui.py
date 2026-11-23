# -*- coding: utf-8 -*-
"""
WMI 弱口令测试工具 - GUI 主程序
===============================
功能：
  - 批量导入目标主机（IP/段/文件）
  - 批量导入凭据（用户名/密码 双列表格）
  - 多线程并发测试
  - 实时显示进度与结果
  - 一键导出成功的弱口令
  - 【命令执行】对已验证成功的凭据，执行远程命令（默认禁用，需显式授权）
  - 【交互终端】仿 cmd 的交互式执行终端

启动：
    python run_gui.py
"""

import os
import sys
import csv
import ipaddress
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

try:
    from .core import Credential, Target, TestResult
    from .runner import ScanConfig, ScanRunner
    from .executor import WMIExecutor, ExecResult
    from .interactive import InteractiveConsole
except ImportError:
    from core import Credential, Target, TestResult
    from runner import ScanConfig, ScanRunner
    from executor import WMIExecutor, ExecResult
    from interactive import InteractiveConsole


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

def expand_targets(text: str) -> list:
    """解析目标文本，支持：
        - 单行一个 IP
        - 逗号 / 空格 / 换行分隔
        - CIDR 网段（如 192.168.1.0/24）
      返回 [(host, port), ...]
    """
    hosts = []
    seen = set()
    tokens = set()
    for line in text.splitlines():
        for sep in (",", " ", "\t", ";"):
            line = line.replace(sep, "\n")
        for tok in line.splitlines():
            tok = tok.strip()
            if tok:
                tokens.add(tok)

    for tok in tokens:
        if "/" in tok and "." in tok.split("/")[0]:
            try:
                net = ipaddress.ip_network(tok, strict=False)
                for ip in net.hosts():
                    h = str(ip)
                    if h not in seen:
                        seen.add(h)
                        hosts.append((h, 445))
                continue
            except ValueError:
                pass
        h = tok
        if h not in seen:
            seen.add(h)
            hosts.append((h, 445))
    return hosts


def parse_credentials(text: str) -> list:
    """解析凭据文本，支持 user:pass / DOMAIN/user:pass / user@domain:pass / 空密码"""
    creds = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            user, pwd = line.rsplit(":", 1)
        elif " " in line:
            parts = line.split(None, 1)
            user, pwd = parts[0], (parts[1] if len(parts) > 1 else "")
        else:
            user, pwd = line, ""
        user = user.strip()
        pwd = pwd.strip()
        domain = ""
        for sep in ("/", "\\"):
            if sep in user:
                domain, user = user.split(sep, 1)
                domain, user = domain.strip(), user.strip()
                break
        if "@" in user and "/" not in user and "\\" not in user:
            u, d = user.rsplit("@", 1)
            user, domain = u.strip(), d.strip()
        creds.append(Credential(username=user, password=pwd, domain=domain))
    return creds


def _is_success(r) -> bool:
    """统一判断一条结果是否成功，兼容 success / result 两种字段。"""
    s = getattr(r, "success", None)
    if isinstance(s, bool):
        return s
    return str(getattr(r, "result", "")).lower() in ("ok", "success", "true", "1")


# ---------------------------------------------------------------------------
# 主界面
# ---------------------------------------------------------------------------

class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("WMI 弱口令测试工具  v1.1@默默提升实验室🧪")
        self.root.geometry("980x720")
        self.root.minsize(820, 640)

        self.runner: ScanRunner = None
        self.results: list = []
        self.success_results: list = []      # 成功验证的凭据（供命令执行复用）
        self._executor: WMIExecutor = None   # 当前命令执行会话
        self._build_ui()

    # ----------------- 界面 -----------------
    def _build_ui(self):
        tip = tk.Label(
            self.root,
            text="? 仅限在拥有合法授权的目标上测试。使用本工具产生的任何后果由使用者自行承担。",
            fg="#c0392b", bg="#fdecea", anchor="w", padx=10,
        )
        tip.pack(side="top", fill="x")

        main = ttk.Frame(self.root, padding=8)
        main.pack(fill="both", expand=True)
        main.columnconfigure(0, weight=1)
        main.columnconfigure(1, weight=2)

        left = ttk.Frame(main)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        self._build_target_panel(left)
        self._build_cred_panel(left)
        self._build_scan_option_panel(left)

        right = ttk.Frame(main)
        right.grid(row=0, column=1, sticky="nsew")
        right.rowconfigure(0, weight=1)
        self.notebook = ttk.Notebook(right)
        self.notebook.pack(fill="both", expand=True)
        self._build_scan_result_tab()
        self._build_exec_tab()
        self._build_terminal_tab()

        self._build_toolbar()

    # ---------- 左侧：目标 ----------
    def _build_target_panel(self, parent):
        frm = ttk.LabelFrame(parent, text="目标主机", padding=6)
        frm.pack(fill="both", expand=True, pady=(0, 6))
        ttk.Label(
            frm, text="支持 IP / 主机名 / CIDR 网段，一行一个，可用空格、逗号分隔",
            foreground="#888", font=("TkDefaultFont", 8),
        ).pack(anchor="w")
        self.target_text = scrolledtext.ScrolledText(frm, height=7, wrap="none")
        self.target_text.pack(fill="both", expand=True, pady=(4, 4))
        btns = ttk.Frame(frm)
        btns.pack(anchor="e")
        ttk.Button(btns, text="从文件导入", command=self._import_targets).pack(side="right")

    # ---------- 左侧：凭据（双列表格） ----------
    def _build_cred_panel(self, parent):
        frm = ttk.LabelFrame(parent, text="凭据（弱口令字典）", padding=6)
        frm.pack(fill="both", expand=True, pady=(0, 6))

        ttk.Label(
            frm,
            text="两列输入：用户名 / 密码。支持 administrator、DOMAIN/admin、user@domain。",
            foreground="#888", font=("TkDefaultFont", 8),
        ).pack(anchor="w")

        table_frame = ttk.Frame(frm)
        table_frame.pack(fill="both", expand=True, pady=(4, 4))

        cols = ("username", "password")
        self.cred_tree = ttk.Treeview(
            table_frame, columns=cols, show="headings", height=7, selectmode="extended",
        )
        self.cred_tree.heading("username", text="用户名 / 账号")
        self.cred_tree.heading("password", text="密码")
        self.cred_tree.column("username", width=170, anchor="w")
        self.cred_tree.column("password", width=170, anchor="w")

        sb = ttk.Scrollbar(table_frame, orient="vertical", command=self.cred_tree.yview)
        self.cred_tree.configure(yscrollcommand=sb.set)
        self.cred_tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        self.cred_tree.bind("<Double-1>", self._on_edit_cred_cell)
        self.cred_tree.bind("<Delete>", lambda e: self._delete_cred_row())

        input_frame = ttk.Frame(frm)
        input_frame.pack(fill="x", pady=(2, 0))

        ttk.Label(input_frame, text="用户：").pack(side="left")
        self.cred_user_var = tk.StringVar()
        e1 = ttk.Entry(input_frame, textvariable=self.cred_user_var, width=16)
        e1.pack(side="left", padx=(2, 6))

        ttk.Label(input_frame, text="密码：").pack(side="left")
        self.cred_pass_var = tk.StringVar()
        e2 = ttk.Entry(input_frame, textvariable=self.cred_pass_var, width=16)
        e2.pack(side="left", padx=(2, 6))

        ttk.Button(input_frame, text="添加", command=self._add_cred_row).pack(side="left", padx=2)
        ttk.Button(input_frame, text="删除", command=self._delete_cred_row).pack(side="left", padx=2)
        ttk.Button(input_frame, text="清空", command=self._clear_cred_rows).pack(side="left", padx=2)

        e1.bind("<Return>", lambda ev: e2.focus_set())
        e2.bind("<Return>", lambda ev: self._add_cred_row())

        btns = ttk.Frame(frm)
        btns.pack(anchor="e", pady=(4, 0))
        ttk.Button(btns, text="从文件导入", command=self._import_creds).pack(side="right")

    def _build_scan_option_panel(self, parent):
        frm = ttk.LabelFrame(parent, text="扫描选项", padding=6)
        frm.pack(fill="x", pady=(0, 6))
        frm.columnconfigure(1, weight=1)

        ttk.Label(frm, text="并发线程数：").grid(row=0, column=0, sticky="w")
        self.threads_var = tk.IntVar(value=10)
        ttk.Spinbox(frm, from_=1, to=200, textvariable=self.threads_var, width=8).grid(
            row=0, column=1, sticky="w", padx=6)

        ttk.Label(frm, text="连接超时(秒)：").grid(row=0, column=2, sticky="w")
        self.timeout_var = tk.IntVar(value=5)
        ttk.Spinbox(frm, from_=1, to=60, textvariable=self.timeout_var, width=8).grid(
            row=0, column=3, sticky="w", padx=6)

        ttk.Label(frm, text="认证方式：").grid(row=1, column=0, sticky="w", pady=4)
        self.auth_var = tk.StringVar(value="NTLM")
        ttk.Combobox(frm, textvariable=self.auth_var, values=["NTLM", "Kerberos"],
                     width=10, state="readonly").grid(row=1, column=1, sticky="w", padx=6, pady=4)
        ttk.Label(frm, text="Kerberos 时填 KDC：").grid(row=1, column=2, sticky="w", pady=4)
        self.kdc_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.kdc_var, width=16).grid(row=1, column=3, sticky="w", padx=6, pady=4)

    # ---------- 右侧标签页：扫描结果 ----------
    def _build_scan_result_tab(self):
        frm = ttk.Frame(self.notebook, padding=6)
        self.notebook.add(frm, text="扫描结果")
        frm.columnconfigure(0, weight=1)
        frm.rowconfigure(1, weight=1)

        self.stat_var = tk.StringVar(value="就绪")
        ttk.Label(frm, textvariable=self.stat_var, foreground="#555").pack(anchor="w")

        cols = ("status", "host", "username", "domain", "password", "method", "error")
        self.tree = ttk.Treeview(frm, columns=cols, show="headings", height=12)
        headings = {
            "status": "状态", "host": "主机", "username": "用户名",
            "domain": "域", "password": "密码", "method": "认证方式", "error": "说明",
        }
        widths = {"status": 90, "host": 120, "username": 80, "domain": 60,
                  "password": 80, "method": 70, "error": 160}
        for c in cols:
            self.tree.heading(c, text=headings[c])
            self.tree.column(c, width=widths[c], anchor="w")
        self.tree.tag_configure("ok", background="#d5f5e3")
        self.tree.tag_configure("fail", background="#fdebd0")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._on_result_select)

        filter_frm = ttk.Frame(frm)
        filter_frm.pack(anchor="e", pady=(4, 0))
        self.filter_var = tk.StringVar(value="全部")
        ttk.Label(filter_frm, text="显示：").pack(side="left")
        cb = ttk.Combobox(
            filter_frm, textvariable=self.filter_var,
            values=["全部", "仅成功", "仅失败"], width=10, state="readonly",
        )
        cb.pack(side="left", padx=4)
        cb.bind("<<ComboboxSelected>>", lambda e: self._refresh_table())

    # ---------- 右侧标签页：命令执行 ----------
    def _build_exec_tab(self):
        frm = ttk.Frame(self.notebook, padding=6)
        self.notebook.add(frm, text="命令执行")
        frm.columnconfigure(0, weight=1)
        frm.rowconfigure(3, weight=1)

        sel = ttk.LabelFrame(frm, text="选择已验证成功的目标", padding=6)
        sel.pack(fill="x")
        sel.columnconfigure(1, weight=1)
        ttk.Label(sel, text="目标：").grid(row=0, column=0, sticky="w")
        self.exec_target_var = tk.StringVar()
        self.exec_combo = ttk.Combobox(sel, textvariable=self.exec_target_var, state="readonly")
        self.exec_combo.grid(row=0, column=1, sticky="ew", padx=6)
        ttk.Button(sel, text="刷新列表", command=self._refresh_exec_targets).grid(row=0, column=2, padx=6)
        ttk.Button(sel, text="安全探活", command=self._exec_probe).grid(row=0, column=3, padx=6)

        auth = ttk.LabelFrame(frm, text="授权与安全", padding=6)
        auth.pack(fill="x", pady=(6, 0))
        self.exec_authorized_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            auth, text="我已确认目标已获合法授权，允许执行远程命令",
            variable=self.exec_authorized_var,
        ).pack(anchor="w")
        self.exec_danger_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            auth, text="放行高危命令（rm / format / shutdown 等，默认拦截）",
            variable=self.exec_danger_var,
        ).pack(anchor="w")
        ttk.Label(
            auth, text="? 高危命令默认拦截；命令通过 Win32_Process.Create 执行，输出经临时文件回传后自动清理。",
            foreground="#c0392b", font=("TkDefaultFont", 8),
        ).pack(anchor="w", pady=(4, 0))

        cmd_frm = ttk.LabelFrame(frm, text="命令", padding=6)
        cmd_frm.pack(fill="x", pady=(6, 0))
        cmd_frm.columnconfigure(0, weight=1)
        self.exec_cmd_var = tk.StringVar(value="whoami")
        cmd_entry = ttk.Entry(cmd_frm, textvariable=self.exec_cmd_var)
        cmd_entry.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        cmd_entry.bind("<Return>", lambda e: self._exec_run())
        ttk.Button(cmd_frm, text="执行", command=self._exec_run).grid(row=0, column=1)
        ttk.Button(cmd_frm, text="清空输出", command=self._exec_clear).grid(row=0, column=2, padx=6)

        out = ttk.LabelFrame(frm, text="输出", padding=6)
        out.pack(fill="both", expand=True, pady=(6, 0))
        out.columnconfigure(0, weight=1)
        out.rowconfigure(0, weight=1)
        self.exec_output = scrolledtext.ScrolledText(out, wrap="word", height=14)
        self.exec_output.pack(fill="both", expand=True)
        self.exec_output.configure(bg="#1e1e1e", fg="#dcdcdc", insertbackground="#dcdcdc")
        self.exec_output.tag_configure("err", foreground="#ff6b6b")
        self.exec_status_var = tk.StringVar(value="未执行")
        ttk.Label(out, textvariable=self.exec_status_var, foreground="#555").pack(anchor="w")

    # ---------- 右侧标签页：交互式终端 ----------
    def _build_terminal_tab(self):
        frm = ttk.Frame(self.notebook, padding=6)
        self.notebook.add(frm, text="交互终端")
        frm.columnconfigure(0, weight=1)
        frm.rowconfigure(1, weight=1)

        tip = ttk.Label(
            frm,
            text="在下方终端输入命令回车即可执行（仿 cmd）。需先在「命令执行」页勾选授权并刷新目标。",
            foreground="#888", font=("TkDefaultFont", 8),
        )
        tip.pack(anchor="w", pady=(0, 4))

        term_frame = ttk.Frame(frm)
        term_frame.pack(fill="both", expand=True)
        term_frame.columnconfigure(0, weight=1)
        term_frame.rowconfigure(0, weight=1)

        sb = ttk.Scrollbar(term_frame, orient="vertical")

        self.terminal = InteractiveConsole(
            term_frame, prompt="$ ", on_submit=self._term_submit, yscrollcommand=sb.set,
        )
        sb.config(command=self.terminal.yview)

        sb.grid(row=0, column=1, sticky="ns")
        self.terminal.grid(row=0, column=0, sticky="nsew")

        self.terminal.start()

    def _term_submit(self, command, console):
        """交互终端回车回调：复用现有执行逻辑执行命令。"""
        if not self.exec_authorized_var.get():
            self.root.after(0, lambda: self._term_show_error(
                console, "请先在「命令执行」页勾选授权确认"))
            return

        target, cred = self._current_exec_credential()
        if target is None:
            self.root.after(0, lambda: self._term_show_error(
                console, "请先选择已验证成功的目标（在「命令执行」页刷新列表）"))
            return

        console.lock()

        def worker():
            try:
                is_new = self._ensure_executor(target, cred)
                if is_new:
                    ok, msg = self._executor.connect()
                    if not ok:
                        self.root.after(0, lambda: self._term_show_error(console, msg))
                        return

                result = self._executor.execute(command)

                def done():
                    if result.success:
                        if command.strip().lower() == "whoami" and result.stdout.strip():
                            console.set_prompt(result.stdout.strip() + "> ")
                            console.writeln(result.stdout.rstrip("\r\n"), "output")
                        elif result.stdout.strip():
                            console.writeln(result.stdout.rstrip("\r\n"), "output")
                        else:
                            console.writeln("(无输出)", "output")
                        console.writeln(
                            "[完成] 耗时 %.2fs" % result.duration +
                            ("  PID=%s" % result.pid if getattr(result, "pid", None) else ""),
                            "info",
                        )
                    else:
                        console.writeln("[错误] " + result.error, "error")
                    console.writeln("")
                    console.unlock()
                    console.show_prompt()

                self.root.after(0, done)

            except Exception as e:
                self.root.after(0, lambda: self._term_show_error(console, str(e)))

        threading.Thread(target=worker, daemon=True).start()

    def _term_show_error(self, console, msg):
        console.writeln("[错误] " + msg, "error")
        console.writeln("")
        console.unlock()
        console.show_prompt()

    # ---------- 底部工具栏 ----------
    def _build_toolbar(self):
        bar = ttk.Frame(self.root, padding=(8, 4))
        bar.pack(fill="x", side="bottom")
        self.start_btn = ttk.Button(bar, text="开始测试", command=self._start)
        self.start_btn.pack(side="left", padx=4)
        self.stop_btn = ttk.Button(bar, text="停止", command=self._stop, state="disabled")
        self.stop_btn.pack(side="left", padx=4)
        ttk.Button(bar, text="清空结果", command=self._clear).pack(side="left", padx=4)
        ttk.Button(bar, text="导出成功凭据", command=self._export).pack(side="left", padx=4)
        ttk.Button(bar, text="帮助", command=self._show_help).pack(side="right", padx=4)

    # ----------------- 凭据表格操作 -----------------
    def _add_cred_row(self):
        user = self.cred_user_var.get().strip()
        pwd = self.cred_pass_var.get()
        if not user:
            messagebox.showwarning("提示", "用户名不能为空")
            return
        self.cred_tree.insert("", "end", values=(user, pwd))
        self.cred_user_var.set("")
        self.cred_pass_var.set("")

    def _delete_cred_row(self):
        selected = self.cred_tree.selection()
        if not selected:
            messagebox.showwarning("提示", "请先选择要删除的凭据")
            return
        for item in selected:
            self.cred_tree.delete(item)

    def _clear_cred_rows(self):
        if not self.cred_tree.get_children():
            return
        if messagebox.askyesno("确认", "确定清空所有凭据吗？"):
            self.cred_tree.delete(*self.cred_tree.get_children())

    def _on_edit_cred_cell(self, event):
        region = self.cred_tree.identify("region", event.x, event.y)
        if region != "cell":
            return
        row_id = self.cred_tree.identify_row(event.y)
        col_id = self.cred_tree.identify_column(event.x)
        if not row_id or not col_id:
            return
        col_index = int(col_id.replace("#", "")) - 1
        values = list(self.cred_tree.item(row_id, "values"))
        if col_index >= len(values):
            return
        bbox = self.cred_tree.bbox(row_id, col_id)
        if not bbox:
            return
        x, y, width, height = bbox
        editor = tk.Entry(self.cred_tree)
        editor.insert(0, values[col_index])
        editor.place(x=x, y=y, width=width, height=height)
        editor.focus_set()
        editor.select_range(0, "end")

        def save_edit(ev=None):
            new_value = editor.get()
            if col_index == 0:
                new_value = new_value.strip()
            values[col_index] = new_value
            self.cred_tree.item(row_id, values=values)
            editor.destroy()

        editor.bind("<Return>", save_edit)
        editor.bind("<FocusOut>", save_edit)
        editor.bind("<Escape>", lambda e: editor.destroy())

    def _read_credentials_from_table(self) -> list:
        creds = []
        for item in self.cred_tree.get_children():
            values = self.cred_tree.item(item, "values")
            if len(values) < 2:
                continue
            user = str(values[0]).strip()
            pwd = str(values[1])
            if not user:
                continue
            domain = ""
            if "\\" in user:
                domain, user = user.split("\\", 1)
                domain, user = domain.strip(), user.strip()
            elif "/" in user:
                domain, user = user.split("/", 1)
                domain, user = domain.strip(), user.strip()
            elif "@" in user:
                user, domain = user.rsplit("@", 1)
                user, domain = user.strip(), domain.strip()
            creds.append(Credential(username=user, password=pwd, domain=domain))
        return creds

    # ----------------- 事件：扫描 -----------------
    def _import_targets(self):
        path = filedialog.askopenfilename(parent=self.root, title="选择目标列表文件",
                                          filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")])
        if not path:
            return
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            self.target_text.insert("end", f.read() + "\n")

    def _import_creds(self):
        path = filedialog.askopenfilename(
            parent=self.root, title="导入凭据字典",
            filetypes=[("文本/CSV", "*.txt *.csv"), ("所有文件", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            messagebox.showerror("导入失败", str(e))
            return

        creds = parse_credentials(content)
        if not creds:
            messagebox.showinfo("提示", "文件中未解析到有效凭据")
            return

        for c in creds:
            display_user = f"{c.domain}\\{c.username}" if c.domain else c.username
            self.cred_tree.insert("", "end", values=(display_user, c.password))

        messagebox.showinfo("导入完成", f"已导入 {len(creds)} 条凭据")

    def _start(self):
        targets_raw = self.target_text.get("1.0", "end").strip()
        if not targets_raw:
            messagebox.showwarning("提示", "请先填写目标主机")
            return
        hosts = expand_targets(targets_raw)
        if not hosts:
            messagebox.showwarning("提示", "未解析到任何有效目标")
            return

        if not self.cred_tree.get_children():
            messagebox.showwarning("提示", "请先输入或导入凭据")
            return
        creds = self._read_credentials_from_table()
        if not creds:
            messagebox.showwarning("提示", "未解析到任何有效凭据")
            return

        targets = [Target(host=h, port=p) for h, p in hosts]
        total = len(targets) * len(creds)
        if total > 5000:
            if not messagebox.askyesno("确认", f"共 {total} 项测试，数量较大，确认继续？"):
                return

        self._clear_table_only()
        self.results = []
        self.success_results = []
        self.stat_var.set(f"0 / {total}   成功: 0")
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")

        cfg = ScanConfig(
            targets=targets, credentials=creds,
            timeout=self.timeout_var.get(),
            threads=self.threads_var.get(),
            use_kerberos=(self.auth_var.get() == "Kerberos"),
            kdc_host=self.kdc_var.get().strip(),
        )
        self.runner = ScanRunner(cfg)
        self.runner.on_progress = self._on_progress
        self.runner.on_log = self._on_log
        self.runner.on_finish = self._on_finish
        threading.Thread(target=self.runner.start, daemon=True).start()

    def _stop(self):
        if self.runner:
            self.runner.stop()
            self._log("用户请求停止…")

    def _clear(self):
        if self.runner and getattr(self.runner, "running", False):
            messagebox.showinfo("提示", "请先停止当前扫描")
            return
        self._clear_table_only()
        self.results = []
        self.success_results = []
        self.stat_var.set("已清空")

    def _clear_table_only(self):
        for row in self.tree.get_children():
            self.tree.delete(row)

    def _refresh_table(self):
        # 追加式显示，过滤功能可按需扩展
        pass

    def _export(self):
        success = [r for r in self.results if _is_success(r)]
        if not success:
            messagebox.showinfo("提示", "暂无成功的弱口令记录可导出")
            return
        path = filedialog.asksaveasfilename(parent=self.root, title="导出成功凭据",
                                            defaultextension=".csv",
                                            filetypes=[("CSV 文件", "*.csv"), ("文本文件", "*.txt")])
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f)
                w.writerow(["host", "domain", "username", "password", "method"])
                for r in success:
                    w.writerow([r.host, r.domain, r.username, r.password, r.method])
            messagebox.showinfo("完成", f"已导出 {len(success)} 条成功凭据到\n{path}")
        except Exception as e:
            messagebox.showerror("错误", f"导出失败：{e}")

    def _show_help(self):
        msg = (
            "WMI 弱口令测试工具 使用说明\n"
            "================================\n\n"
            "【目标主机】\n"
            "  - 单个 IP：192.168.1.10\n"
            "  - 主机名：WIN-ABC123\n"
            "  - CIDR 网段：192.168.1.0/24\n\n"
            "【凭据】双列表格输入，一行一个账号：\n"
            "  用户名列：administrator / CORP\\admin / admin@corp.com\n"
            "  密码列  ：Admin@123\n"
            "  双击单元格可编辑，Delete 键删除选中行。\n\n"
            "【命令执行】\n"
            "  - 先完成扫描，在「扫描结果」看到成功项；\n"
            "  - 切到「命令执行」页，勾选授权后选择目标执行；\n"
            "  - 高危命令默认拦截，建议先用「安全探活」。\n\n"
            "【交互终端】\n"
            "  - 直接在黑色区域输入命令回车执行；上下键翻阅历史；\n"
            "  - 每次回车是独立远程进程，cd 不会保持目录。\n\n"
            "【前提】目标需开放 445 端口，账号需有管理员权限。\n\n"
            "? 仅限合法授权测试，后果自负。"
        )
        win = tk.Toplevel(self.root)
        win.title("帮助")
        win.geometry("580x480")
        txt = scrolledtext.ScrolledText(win, wrap="word", padx=10, pady=10)
        txt.insert("1.0", msg)
        txt.config(state="disabled")
        txt.pack(fill="both", expand=True)

    # ----------------- 事件：命令执行 -----------------
    def _refresh_exec_targets(self):
        self.success_results = [r for r in self.results if _is_success(r)]
        values = [
            f"{r.host}  |  {r.domain or '(本地)'}/{r.username}  ({r.method})"
            for r in self.success_results
        ]
        self.exec_combo["values"] = values
        if values:
            self.exec_combo.current(0)
            self.exec_status_var.set(f"共 {len(values)} 个已验证目标")
        else:
            self.exec_combo.set("")
            self.exec_status_var.set("暂无成功目标，请先完成扫描")

    def _current_exec_credential(self):
        idx = self.exec_combo.current()
        if idx < 0 or idx >= len(self.success_results):
            return None, None
        r = self.success_results[idx]
        target = Target(host=r.host)
        cred = Credential(username=r.username, password=r.password, domain=r.domain)
        return target, cred

    def _ensure_executor(self, target, cred):
        use_kerberos = (self.auth_var.get() == "Kerberos")
        need_new = (
            self._executor is None
            or self._executor.host != target.host
            or self._executor.username != cred.username
            or self._executor.password != cred.password
        )
        if need_new:
            if self._executor is not None:
                self._executor.close()
            self._executor = WMIExecutor(
                host=target.host, username=cred.username,
                password=cred.password, domain=cred.domain,
                authorized=self.exec_authorized_var.get(),
                timeout=self.timeout_var.get(),
                use_kerberos=use_kerberos,
                kdc_host=self.kdc_var.get().strip(),
                allow_dangerous=self.exec_danger_var.get(),
            )
            return True
        self._executor.authorized = self.exec_authorized_var.get()
        self._executor.allow_dangerous = self.exec_danger_var.get()
        return False

    def _exec_run(self):
        if not self.exec_authorized_var.get():
            messagebox.showwarning("未授权", "请先勾选授权确认，方可执行远程命令。")
            return
        target, cred = self._current_exec_credential()
        if target is None:
            messagebox.showinfo("提示", "请先选择已验证成功的目标")
            return
        command = self.exec_cmd_var.get().strip()
        if not command:
            messagebox.showinfo("提示", "请输入要执行的命令")
            return
        self.exec_status_var.set("执行中…")
        threading.Thread(target=self._exec_worker, args=(target, cred, command), daemon=True).start()

    def _exec_probe(self):
        target, cred = self._current_exec_credential()
        if target is None:
            messagebox.showinfo("提示", "请先选择已验证成功的目标")
            return
        if not self.exec_authorized_var.get():
            messagebox.showwarning("未授权", "请先勾选授权确认，方可执行远程命令。")
            return
        self.exec_status_var.set("正在安全探活…")
        threading.Thread(target=self._exec_probe_worker, args=(target, cred), daemon=True).start()

    def _exec_probe_worker(self, target, cred):
        exe = WMIExecutor(
            host=target.host, username=cred.username, password=cred.password,
            domain=cred.domain, authorized=True,
            timeout=self.timeout_var.get(),
            use_kerberos=(self.auth_var.get() == "Kerberos"),
            kdc_host=self.kdc_var.get().strip(),
        )
        try:
            with exe:
                result = exe.execute_safe_probe()
        except Exception as e:
            result = ExecResult(host=target.host, command="probe", success=False, error=str(e))
        self.root.after(0, self._show_exec_result, result)

    def _exec_worker(self, target, cred, command):
        is_new = self._ensure_executor(target, cred)
        try:
            if is_new:
                ok, msg = self._executor.connect()
                if not ok:
                    result = ExecResult(host=target.host, command=command, success=False, error=msg)
                    self.root.after(0, self._show_exec_result, result)
                    return
            result = self._executor.execute(command)
        except Exception as e:
            result = ExecResult(host=target.host, command=command, success=False, error=str(e))
        self.root.after(0, self._show_exec_result, result)

    def _show_exec_result(self, result: ExecResult):
        self.exec_status_var.set(f"{'成功' if result.success else '失败'}  耗时 {result.duration:.2f}s")
        self.exec_output.insert("end", f"\n$ {result.command}\n")
        if result.success:
            self.exec_output.insert("end", result.stdout if result.stdout.strip() else "(无输出)\n")
        else:
            self.exec_output.insert("end", f"[错误] {result.error}\n", "err")
        self.exec_output.see("end")

    def _exec_clear(self):
        self.exec_output.delete("1.0", "end")
        self.exec_status_var.set("已清空")

    # ----------------- 结果选择联动 -----------------
    def _on_result_select(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        values = self.tree.item(sel[0])["values"]
        if values and str(values[0]).startswith("?"):
            self._refresh_exec_targets()
            host = values[1]
            for i, r in enumerate(self.success_results):
                if r.host == host:
                    self.exec_combo.current(i)
                    break
            self.notebook.select(1)

    # ----------------- 回调 -----------------
    def _on_progress(self, done, total, result):
        self.results.append(result)
        ok_count = sum(1 for r in self.results if _is_success(r))
        self.root.after(0, self._update_row, result)
        self.root.after(0, lambda: self.stat_var.set(f"{done} / {total}   成功: {ok_count}"))

    def _on_log(self, msg):
        print(msg)

    def _on_finish(self, results):
        ok = sum(1 for r in results if _is_success(r))
        self.root.after(0, lambda: self.stat_var.set(f"完成：{len(results)} 项，成功 {ok} 项"))
        self.root.after(0, lambda: self.start_btn.config(state="normal"))
        self.root.after(0, lambda: self.stop_btn.config(state="disabled"))
        self.root.after(0, self._refresh_exec_targets)

    def _update_row(self, r):
        success = _is_success(r)
        status = "✅ 成功" if success else "❌ 失败"
        values = (
            status, r.host, r.username, r.domain,
            r.password, r.method, "" if success else getattr(r, "error", ""),
        )
        tag = "ok" if success else "fail"
        self.tree.insert("", "end", values=values, tags=(tag,))
        if success:
            self.tree.see(self.tree.get_children()[-1])

    def _log(self, msg):
        print(msg)


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def main():
    root = tk.Tk()
    try:
        ttk.Style().theme_use("clam")
    except Exception:
        pass
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()