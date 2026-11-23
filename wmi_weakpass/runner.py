# -*- coding: utf-8 -*-
"""
并发调度层：在线程池里跑测试，实时回调进度。
"""

import threading
from queue import Queue
from dataclasses import dataclass

from .core import Target, Credential, TestResult, test_credential


@dataclass
class ScanConfig:
    targets: list
    credentials: list
    timeout: int = 10
    threads: int = 10
    use_kerberos: bool = False
    kdc_host: str = ""


class ScanRunner:
    """
    用法：
        runner = ScanRunner(config)
        runner.on_progress = lambda done, total, result: ...
        runner.on_finish = lambda results: ...
        runner.start()
        runner.stop()   # 随时可中断
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self._stop = threading.Event()
        self._thread = None
        self.on_progress = None     # done, total, TestResult
        self.on_log = None          # msg
        self.on_finish = None       # results: list[TestResult]

    @property
    def running(self):
        return self._thread is not None and self._thread.is_alive()

    def stop(self):
        self._stop.set()

    def start(self):
        if self.running:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _log(self, msg):
        if self.on_log:
            self.on_log(msg)

    def _run(self):
        cfg = self.config
        tasks = []
        for t in cfg.targets:
            for c in cfg.credentials:
                tasks.append((t, c))

        total = len(tasks)
        self._log(f"共 {len(cfg.targets)} 个目标 × {len(cfg.credentials)} 条凭据 = {total} 项待测试")

        results = []
        done = 0
        lock = threading.Lock()

        def worker():
            nonlocal done
            while not self._stop.is_set():
                try:
                    t, c = q.get_nowait()
                except Exception:
                    return
                if self._stop.is_set():
                    q.task_done()
                    return
                r = test_credential(
                    t, c,
                    timeout=cfg.timeout,
                    use_kerberos=cfg.use_kerberos,
                    kdc_host=cfg.kdc_host,
                )
                with lock:
                    done += 1
                    current = done
                results.append(r)
                if self.on_progress:
                    try:
                        self.on_progress(current, total, r)
                    except Exception:
                        pass
                q.task_done()

        concurrency = min(cfg.threads, total, 64)
        if concurrency < 1:
            concurrency = 1
        q = Queue()
        for task in tasks:
            q.put(task)

        pool = []
        for _ in range(concurrency):
            th = threading.Thread(target=worker, daemon=True)
            th.start()
            pool.append(th)

        for th in pool:
            th.join()

        self._log("扫描结束" + ("（已中断）" if self._stop.is_set() else ""))
        if self.on_finish:
            try:
                self.on_finish(results)
            except Exception:
                pass
