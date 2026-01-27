import requests
import time
import socket
import threading
import pythoncom
import win32com.client
import debugpy
from PyQt5.QtCore import QRunnable

from modules.State import global_state
from modules.Working_signals import WorkerSignals

state = global_state()


class watch_dog(QRunnable):
    def __init__(self):
        super().__init__()
        self.signals = WorkerSignals()
        self._nlm = None
        self._reconnect_lock = threading.Lock()
        self.last_net_state = None
        self.last_auth_state = None
        self.last_state_change_ts = 0
        self.state_change_cooldown = 3
        self.periodic_interval = state.watch_dog_timeout
        self.last_periodic_check_ts = 0

    def _init_nlm(self):
        """初始化NetworkListManager"""
        try:
            pythoncom.CoInitialize()

            # 尝试多种方式初始化NLM
            methods = [
                # NetworkListManager CLSID
                "{DCB00C01-570F-4A9B-8D69-199FDBA5723B}",
                "NetworkListManager",
                "HNetCfg.HNetShare"  # 备选网络API
            ]

            for method in methods:
                try:
                    self._nlm = win32com.client.Dispatch(method)
                    # 测试是否可用
                    if hasattr(self._nlm, 'IsConnectedToInternet') or hasattr(self._nlm, 'GetNetworkConnections'):
                        return True, method

                except Exception as e:
                    continue

            return False, None
        
        except Exception as e:
            self.signals.print_text.emit(f"看门狗:NLM初始化失败: {e}")
            return False, None

    def check_network_layer(self):
        """检测网络层连通性"""
        if state.stop_watch_dog:
            return False
        # 优先使用NLM
        if self._nlm:
            try:
                if hasattr(self._nlm, 'IsConnectedToInternet'):
                    return bool(self._nlm.IsConnectedToInternet())
                elif hasattr(self._nlm, 'GetNetworkConnections'):
                    connections = self._nlm.GetNetworkConnections()
                    return connections and connections.Count > 0
            except Exception as e:
                self.signals.print_text.emit(f"看门狗:NLM查询失败: {e}")

        # 最后备选：socket连接测试
        try:
            conn = socket.create_connection(("223.5.5.5", 53), timeout=2)
            conn.close()
            return True
        except Exception:
            return False

    def check_auth_layer(self):
        """检测认证层连通性（校园网登录状态）"""
        if state.stop_watch_dog:
            return False
        try:
            response = requests.head(
                "http://www.baidu.com", timeout=3, allow_redirects=False, proxies={"http": "", "https": ""})
            return response.status_code == 200

        except:
            return False

    def diagnose_connection(self):
        """诊断连接状态，返回 (网络层状态, 认证层状态)"""
        if state.stop_watch_dog:
            return False, False
        network_ok = self.check_network_layer()
        auth_ok = False

        if network_ok:
            auth_ok = self.check_auth_layer()

        return network_ok, auth_ok

    def handle_connection_change(self, network_ok, auth_ok):
        """处理连接状态变化"""
        with self._reconnect_lock:
            current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

            if not network_ok:
                self.signals.print_text.emit(
                    f"看门狗:网线被拔出(WLAN断开)或网卡被禁用[{current_time}]")
                self.periodic_interval = 10
                return  # 网络物理断开时不重连

            if network_ok and not auth_ok:
                self.signals.print_text.emit(
                    f"看门狗:检测到认证过期，重新登录...[{current_time}]")
                try:
                    self.signals.thread_login.emit()
                except Exception as e:
                    self.signals.print_text.emit(f"看门狗:登录失败: {e}")

                if state.connected == False and state.stop_retry_thread == False:
                    # 增加检查间隔，避免频繁重试，最大不超过600秒
                    self.periodic_interval = min(
                        self.periodic_interval + 120, 600)

            elif network_ok and auth_ok:
                self.signals.print_text.emit(f"看门狗:网络恢复正常[{current_time}]")
                self.periodic_interval = state.watch_dog_timeout

    def _on_network_change(self):
        """网络变化检测（轮询模式）"""
        if state.stop_watch_dog:
            return
        now = time.time()
        if now - self.last_state_change_ts < self.state_change_cooldown:
            return

        self.last_state_change_ts = now
        network_ok = self.check_network_layer()

        # 只在状态确实变化时处理
        if network_ok != self.last_net_state:
            self.last_net_state = network_ok

            if network_ok:
                auth_ok = self.check_auth_layer()
            else:
                auth_ok = False

            self.handle_connection_change(network_ok, auth_ok)

    def _periodic_check(self):
        """定期检查"""
        if state.stop_watch_dog:
            return
        now = time.time()
        if now - self.last_periodic_check_ts < self.periodic_interval:
            return

        self.last_periodic_check_ts = now
        network_ok, auth_ok = self.diagnose_connection()

        # 定期检查只关心认证层问题
        if network_ok and not auth_ok:
            self.handle_connection_change(network_ok, auth_ok)

    def run(self):
        if state.watch_dog_thread_started == True:
            self.signals.print_text.emit("看门狗:线程已启动无需再次启动")
            return

        state.watch_dog_thread_started = True

        # 尝试初始化NLM
        nlm_available, method = self._init_nlm()
        if nlm_available:
            self.signals.print_text.emit(
                f"看门狗:正在持续监测网络状态...             (using:{method})")
        else:
            self.signals.print_text.emit(
                "看门狗:正在持续监测网络状态...              (By:Socket Test)")

        try:
            self.signals.update_progress.emit(1, 0, 0)
        except Exception:
            pass

        # 初始状态检查
        self.last_net_state, self.last_auth_state = self.diagnose_connection()
        self.last_periodic_check_ts = time.time()

        try:
            while True:
                if state.stop_watch_dog:
                    self.signals.print_text.emit("看门狗:停止监测")
                    # debugpy.breakpoint()
                    break

                time.sleep(3)  # 3秒检查一次状态变化

                # 检查状态变化
                self._on_network_change()

                # 定期完整检查
                self._periodic_check()

        finally:
            if self._nlm:
                try:
                    pythoncom.CoUninitialize()
                except Exception:
                    pass

            state.watch_dog_thread_started = False
            try:
                self.signals.update_progress.emit(0, 0, 0)
            except Exception:
                pass
