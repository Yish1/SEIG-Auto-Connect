import requests
import time
from PyQt5.QtCore import QThreadPool, pyqtSignal, QRunnable, QObject, QTimer, QMutex

from modules.State import global_state
from modules.Working_signals import WorkerSignals

state = global_state()

class watch_dog(QRunnable):
    def __init__(self):
        super().__init__()
        self.signals = WorkerSignals()
        try:
            self.ping_timeout = state.watch_dog_timeout  # 默认设置超时时间
        except:
            self.ping_timeout = 300
            
        self.reconnect_timeout = 30

    def ping_baidu(self):
        try:
            response = requests.head("http://www.baidu.com", timeout=2)
            return response.status_code == 200
        except:
            return False

    def run(self):
        # debugpy.breakpoint()

        original_interval = self.ping_timeout
        if state.watch_dog_thread_started != True:
            state.watch_dog_thread_started = True
            self.signals.print_text.emit(
                f"看门狗:已就位！每{self.ping_timeout}秒检测一次网络")
            self.signals.update_progress.emit(1, 0, 100)
            while True:
                if state.stop_watch_dog:
                    self.signals.print_text.emit("看门狗:停止监测")
                    break

                total_sleep_time = self.ping_timeout
                step = 1

                while total_sleep_time > 0:
                    if state.stop_watch_dog:
                        self.signals.print_text.emit("看门狗:停止监测")
                        state.watch_dog_thread_started = False
                        try:
                            self.signals.update_progress.emit(0, 0, 0)
                        except:
                            self.signals.print_text.emit("信号槽已被删除")
                        return
                    time.sleep(step)
                    total_sleep_time -= step
                    progress_value = int(
                        ((self.ping_timeout - total_sleep_time) / self.ping_timeout) * 100)
                    try:
                        self.signals.update_progress.emit(
                            1, progress_value, 100)
                    except:
                        self.signals.print_text.emit("信号槽已被删除")

                if not self.ping_baidu():
                    current_time = time.strftime(
                        "%Y-%m-%d %H:%M:%S", time.localtime())
                    self.signals.print_text.emit(
                        f"看门狗:网络断开，重新登录...[{current_time}]")
                    # 若断开超时改为60s
                    self.ping_timeout = self.reconnect_timeout
                    try:
                        self.signals.thread_login.emit()
                    except Exception as e:
                        self.signals.print_text.emit(f"看门狗:登录失败: {e}")
                else:
                    # 恢复超时
                    self.ping_timeout = original_interval
                    self.signals.print_text.emit("看门狗:网络正常无需操作")
        else:
            self.signals.print_text.emit("看门狗:线程已启动无需再次启动")
