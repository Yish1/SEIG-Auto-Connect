import requests
import time
import ctypes
from ctypes import wintypes
from PyQt5.QtCore import QRunnable

from modules.State import global_state
from modules.Working_signals import WorkerSignals

state = global_state()

class watch_dog(QRunnable):
    def __init__(self):
        super().__init__()
        self.signals = WorkerSignals()
        try:
            self.ping_timeout = state.watch_dog_timeout
        except Exception:
            self.ping_timeout = 300
        self.last_net_state = None
        self.last_state_change_ts = 0
        self.state_change_cooldown = 5
        self.last_health_check_ts = 0

    def ping_baidu(self):
        try:
            response = requests.head("http://www.baidu.com", timeout=2)
            return response.status_code == 200
        except Exception:
            return False

    def _wininet_net_state(self):
        try:
            flags = wintypes.DWORD()
            res = ctypes.windll.wininet.InternetGetConnectedState(
                ctypes.byref(flags), 0
            )
            return bool(res)
        except Exception:
            return None

    def run(self):
        # debugpy.breakpoint()
        if state.watch_dog_thread_started == True:
            self.signals.print_text.emit("看门狗:线程已启动无需再次启动")
            return

        state.watch_dog_thread_started = True
        self.signals.print_text.emit("看门狗:正在实时监测网络状态...")
        try:
            self.signals.update_progress.emit(1, 0, 0)
        except Exception:
            pass

        self.last_net_state = self._wininet_net_state()
        self.last_health_check_ts = time.time()

        while True:
            if state.stop_watch_dog:
                self.signals.print_text.emit("看门狗:停止监测")
                break

            net_state = self._wininet_net_state()
            self._handle_net_state_change(net_state)
            self._periodic_health_check()
            time.sleep(0.5)

        state.watch_dog_thread_started = False
        try:
            self.signals.update_progress.emit(0, 0, 0)
        except Exception:
            pass

    def _handle_net_state_change(self, net_state):
        if net_state is None:
            return

        if net_state == self.last_net_state:
            return

        now = time.time()
        self.last_net_state = net_state
        if now - self.last_state_change_ts < self.state_change_cooldown:
            return

        self.last_state_change_ts = now

        if net_state:
            self.signals.print_text.emit("看门狗:网络变化(恢复)，立即检测连通性...")
            if self.ping_baidu():
                self.signals.print_text.emit("看门狗:网络正常无需操作")
            else:
                self.signals.print_text.emit("看门狗:网络异常，持续检测中...")
            return

        self.signals.print_text.emit("看门狗:网络变化(断开)，立即检测连通性...")
        if not self.ping_baidu():
            current_time = time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime())
            self.signals.print_text.emit(
                f"看门狗:网络断开，重新登录...[{current_time}]")
            try:
                self.signals.thread_login.emit()
            except Exception as e:
                self.signals.print_text.emit(f"看门狗:登录失败: {e}")

    def _periodic_health_check(self):
        now = time.time()
        if now - self.last_health_check_ts < self.ping_timeout:
            return

        self.last_health_check_ts = now
        if not self.ping_baidu():
            current_time = time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime())
            self.signals.print_text.emit(
                f"看门狗:网络异常(账号可能下线)，重新登录...[{current_time}]")
            try:
                self.signals.thread_login.emit()
            except Exception as e:
                self.signals.print_text.emit(f"看门狗:登录失败: {e}")