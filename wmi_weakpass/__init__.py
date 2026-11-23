# -*- coding: utf-8 -*-
"""WMI 弱口令测试工具包"""

from .core import Credential, Target, TestResult, test_credential
from .runner import ScanConfig, ScanRunner
from .executor import WMIExecutor, ExecResult, quick_execute, is_command_safe

__version__ = "1.1.0"
__all__ = [
    "Credential", "Target", "TestResult", "test_credential",
    "ScanConfig", "ScanRunner",
    "WMIExecutor", "ExecResult", "quick_execute", "is_command_safe",
]
