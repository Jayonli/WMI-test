# -*- coding: utf-8 -*-
"""
启动脚本：双击或命令行运行即可启动 WMI 弱口令测试工具 GUI。

支持两种运行方式：
  - 作为脚本直接运行：python run_gui.py
  - 作为模块运行：     python -m wmi_weakpass.gui
"""

import sys
import os

# 确保能找到同目录下的 wmi_weakpass 包
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from wmi_weakpass.gui import main

if __name__ == "__main__":
    main()
