import requests
import time
import socket
from PyQt5.QtCore import QRunnable

from modules.State import global_state
from modules.Working_signals import WorkerSignals

state = global_state()

class watch_dog(QRunnable):
    def __init__(self):
        super().__init__()
        self.signals = WorkerSignals()
            
        self.reconnect_timeout = 30
        self.check_interval = 1
        self.last_net_state = None
        self.last_state_change_ts = 0
        self.state_change_cooldown = 5

    def ping_baidu(self):
        try:
            response = requests.head("http://www.baidu.com", timeout=2)
            return response.status_code == 200
        except:
            return False

    def quick_net_check(self):
        try:
            conn = socket.create_connection(("223.5.5.5", 53), timeout=1)
            conn.close()
            return True
        except:
            return False

    def handle_state_change(self, is_up, original_interval):
        if is_up:
            self.signals.print_text.emit("看门狗:网络变化(恢复)，立即检测...")
            if self.ping_baidu():
                self.signals.print_text.emit("看门狗:网络正常无需操作")
            return

        self.signals.print_text.emit("看门狗:网络变化(断开)，立即检测...")
        if not self.ping_baidu():
            current_time = time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime())
            self.signals.print_text.emit(
                f"看门狗:网络断开，重新登录...[{current_time}]")

            try:
                self.signals.thread_login.emit()
            except Exception as e:
                self.signals.print_text.emit(f"看门狗:登录失败: {e}")

    def run(self):
        # debugpy.breakpoint()
        if state.watch_dog_thread_started == True:
            print("看门狗:线程已启动无需再次启动")
            return

        state.watch_dog_thread_started = True
        self.signals.print_text.emit("看门狗:正在实时监测网络状态")
        self.signals.update_progress.emit(1, 0, 0)

        self.last_net_state = self.quick_net_check()

        while True:
            if state.stop_watch_dog:
                try:
                    self.signals.print_text.emit("看门狗:停止监测")
                except:
                    pass
                break

            time.sleep(self.check_interval)
            net_state = self.quick_net_check()

            if net_state == self.last_net_state:
                continue

            now = time.time()
            self.last_net_state = net_state
            if now - self.last_state_change_ts < self.state_change_cooldown:
                continue

            self.last_state_change_ts = now

            if net_state:
                self.signals.print_text.emit("看门狗:网络变化(恢复)，立即检测...")
                if self.ping_baidu():
                    self.signals.print_text.emit("看门狗:网络正常无需操作")
                else:
                    self.signals.print_text.emit("看门狗:网络异常，继续监测...")
                continue

            self.signals.print_text.emit("看门狗:网络变化(断开)，立即检测...")
            
            if not self.ping_baidu():
                current_time = time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.localtime())
                self.signals.print_text.emit(
                    f"看门狗:网络断开，重新登录...[{current_time}]")
                try:
                    self.signals.thread_login.emit()
                except Exception as e:
                    self.signals.print_text.emit(f"看门狗:登录失败: {e}")

        state.watch_dog_thread_started = False
        self.signals.update_progress.emit(0, 0, 0)