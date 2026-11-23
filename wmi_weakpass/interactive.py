# -*- coding: utf-8 -*-
"""wmi_weakpass.interactive - 仿 cmd 交互式终端（最终版）"""

import tkinter as tk


class InteractiveConsole(tk.Text):
    def __init__(self, master, prompt="$ ", on_submit=None, **kwargs):
        kwargs.setdefault("wrap", tk.WORD)
        kwargs.setdefault("bg", "#1e1e1e")
        kwargs.setdefault("fg", "#dcdcdc")
        kwargs.setdefault("insertbackground", "#dcdcdc")
        kwargs.setdefault("font", ("Consolas", 10))
        super().__init__(master, **kwargs)

        self.prompt = prompt
        self._on_submit = on_submit
        self._history = []
        self._hist_index = 0
        self._locked = False

        self.tag_configure("prompt", foreground="#00d787")
        self.tag_configure("command", foreground="#ffffff")
        self.tag_configure("output", foreground="#dcdcdc")
        self.tag_configure("error", foreground="#ff6b6b")
        self.tag_configure("info", foreground="#5fb3ff")

        # 关键：状态始终保持 NORMAL，用 _locked 控制是否允许提交。
        # 一旦用 state=DISABLED，Text 就不接收字符输入，这是"打不了字"的根源。
        self.configure(state=tk.NORMAL)

        self.bind("<Return>", self._on_return)
        self.bind("<KP_Enter>", self._on_return)
        self.bind("<Up>", self._on_history_up)
        self.bind("<Down>", self._on_history_down)
        self.bind("<Control-c>", self._on_ctrl_c)
        self.bind("<Button-1>", self._on_click)

    # ---------------- 基础 ----------------
    def set_prompt(self, prompt):
        self.prompt = prompt

    def write(self, text, tag="output"):
        self.insert("end", text, tag)
        self.see("end")

    def writeln(self, text="", tag="output"):
        self.write(str(text) + "\n", tag)

    def show_prompt(self):
        if self.index("end-1c") != "1.0":
            self.insert("end", "\n")
        self.insert("end", self.prompt, "prompt")
        self.mark_set("insert", "end")
        self.see("end")

    def start(self, banner=True):
        if banner:
            self.writeln("WMI 交互式执行终端", "info")
            self.writeln("在下方输入命令后回车执行；上/下方向键翻阅历史。", "info")
            self.writeln("说明：每次回车是一次独立的远程进程调用。", "info")
            self.writeln("")
        self.show_prompt()
        self.focus_set()

    def lock(self):
        self._locked = True

    def unlock(self):
        self._locked = False

    @property
    def locked(self):
        return self._locked

    # ---------------- 事件 ----------------
    def _on_click(self, event):
        self.focus_set()

    def _on_return(self, event=None):
        if self._locked:
            return "break"

        # 取最后一行提示符之后的文本
        line_start = self.index("insert linestart")
        line_text = self.get(line_start, "end-1c")
        if line_text.startswith(self.prompt):
            command = line_text[len(self.prompt):].strip()
        else:
            command = ""

        if not command:
            self.show_prompt()
            return "break"

        if not self._history or self._history[-1] != command:
            self._history.append(command)
        self._hist_index = len(self._history)

        self.insert("end", "\n")

        try:
            if self._on_submit:
                self._on_submit(command, self)
        except Exception as e:
            self.writeln("[异常] %s" % e, "error")
            self.writeln("")
            self.show_prompt()

        return "break"

    def _on_history_up(self, event=None):
        if not self._history or self._locked:
            return "break"
        if self._hist_index > 0:
            self._hist_index -= 1
            self._replace_input(self._history[self._hist_index])
        return "break"

    def _on_history_down(self, event=None):
        if not self._history or self._locked:
            return "break"
        if self._hist_index < len(self._history) - 1:
            self._hist_index += 1
            self._replace_input(self._history[self._hist_index])
        else:
            self._hist_index = len(self._history)
            self._replace_input("")
        return "break"

    def _replace_input(self, text):
        line_start = self.index("insert linestart")
        # 删除提示符之后的内容
        self.delete(line_start + " + %dc" % len(self.prompt), "end-1c")
        if text:
            self.insert("end-1c", text, "command")
        self.mark_set("insert", "end-1c")
        self.see("end")

    def _on_ctrl_c(self, event=None):
        if self._locked:
            self.writeln("^C", "error")
            self.writeln("[提示] 远程进程已启动，无法强制中断，请等待完成。", "info")
            self.writeln("")
            self._locked = False
            self.show_prompt()
        return "break"