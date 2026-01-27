import requests
import time
import pythoncom
import win32com.client
from PyQt5.QtCore import QRunnable

from modules.State import global_state
from modules.Working_signals import WorkerSignals

state = global_state()

class watch_dog(QRunnable):
    class _NLMEvents:
        def __init__(self):
            self._callback = None

        def set_callback(self, callback):
            self._callback = callback

        def ConnectivityChanged(self, newConnectivity):
            if self._callback:
                try:
                    self._callback()
                except Exception:
                    pass

    def __init__(self):
        super().__init__()
        self.signals = WorkerSignals()
        self._nlm = None
        self._nlm_events = None
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

    def get_net_state(self):
        try:
            return bool(self._nlm.IsConnectedToInternet)
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

        pythoncom.CoInitialize()
        try:
            self._nlm = win32com.client.Dispatch("NetworkListManager")
            self._nlm_events = win32com.client.WithEvents(
                self._nlm, self._NLMEvents
            )
            self._nlm_events.set_callback(self._on_network_change)

            self.last_net_state = self.get_net_state()
            self.last_health_check_ts = time.time()

            while True:
                if state.stop_watch_dog:
                    self.signals.print_text.emit("看门狗:停止监测")
                    break
                pythoncom.PumpWaitingMessages()
                self._periodic_health_check()
                time.sleep(0.2)

        except Exception as e:
            self.signals.print_text.emit(f"看门狗:监听失败: {e}")
            
        finally:
            pythoncom.CoUninitialize()
            state.watch_dog_thread_started = False
            try:
                self.signals.update_progress.emit(0, 0, 0)
            except Exception:
                pass

    def _on_network_change(self):
        net_state = self.get_net_state()
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