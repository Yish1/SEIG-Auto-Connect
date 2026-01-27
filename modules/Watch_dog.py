import time
import threading
import pythoncom
import win32com.client
import requests
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
        self.last_reconnect_ts = 0  # 上次重连时间
        self.reconnect_cooldown = 15  # 重连冷却时间（秒）
        self.nlm_check_count = 0  # NLM检查计数器
        self.check_interval = 3  # 检查间隔（秒）
        self.last_nlm_state = None  # 上次NLM状态，用于检测断网
        self.check_internet_timeout = state.wtg_timeout if state.wtg_timeout else 5  # 互联网连通性检查超时

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
                    if hasattr(self._nlm, 'IsConnected') or hasattr(self._nlm, 'GetNetworkConnections'):
                        return True, method

                except Exception as e:
                    continue

            return False, None

        except Exception as e:
            self.signals.print_text.emit(f"看门狗:NLM初始化失败: {e}")
            return False, None

    def check_nlm_connected(self):
        """检测NLM IsConnected（网卡是否连接到网线）"""
        if state.stop_watch_dog:
            return False
        if self._nlm:
            try:
                if hasattr(self._nlm, 'IsConnected'):
                    return bool(self._nlm.IsConnected)
                elif hasattr(self._nlm, 'GetNetworkConnections'):
                    connections = self._nlm.GetNetworkConnections()
                    return connections and connections.Count > 0
            except Exception as e:
                self.signals.print_text.emit(f"看门狗:NLM查询失败: {e}")
        return False

    # 公网连通性检测地址列表
    CONNECTIVITY_CHECK_URLS = [
        # (url, expected_status, method)
        ("http://www.msftconnecttest.com/connecttest.txt", 200, "HEAD"),
        ("http://connectivitycheck.gstatic.com/generate_204", 204, "GET"),
        ("http://www.google.cn/generate_204", 204, "GET"),
        ("http://captive.apple.com/hotspot-detect.html", 200, "HEAD"),
        ("http://connect.rom.miui.com/generate_204", 204, "GET"),
        ("http://wifi.vivo.com.cn/generate_204", 204, "GET"),
    ]

    def check_internet_connected(self):
        """
        检测互联网连通性（实际网络是否通）
        使用多个公网检测地址，有一个通就算通，避免单点故障
        """
        if state.stop_watch_dog:
            return False

        ua = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/121.0.0.0 Safari/537.36"
        )
        headers = {"User-Agent": ua}

        # 尝试多个检测地址，有一个成功就返回True
        for url, expected_status, method in self.CONNECTIVITY_CHECK_URLS:
            try:
                if method == "HEAD":
                    r = requests.head(
                        url,
                        timeout=(2, 4),
                        allow_redirects=False,
                        headers=headers,
                        proxies={"http": "", "https": ""},
                        verify=False
                    )
                else:
                    r = requests.get(
                        url,
                        timeout=(2, 4),
                        allow_redirects=False,
                        headers=headers,
                        proxies={"http": "", "https": ""},
                        verify=False
                    )

                # 检查是否被重定向（通常是认证页面）
                if r.status_code in (301, 302, 303, 307, 308):
                    continue  # 被重定向，尝试下一个

                if r.status_code == expected_status:
                    return True  # 有一个通就算通

            except requests.RequestException:
                continue  # 超时或其他错误，尝试下一个

        # 所有检测地址都失败
        current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        self.signals.print_text.emit(f"看门狗:所有网络检测点均不可达[{current_time}]")
        return False

    def try_reconnect(self):
        """尝试重连，有冷却时间"""
        with self._reconnect_lock:
            now = time.time()
            if now - self.last_reconnect_ts < self.reconnect_cooldown:
                return False  # 冷却中

            self.last_reconnect_ts = now
            try:
                self.signals.thread_login.emit()
                return True
            except Exception as e:
                self.signals.print_text.emit(f"看门狗:登录失败: {e}")
                return False

    def run(self):
        if state.watch_dog_thread_started == True:
            print("看门狗:线程已启动无需再次启动")
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

        try:
            while True:
                if state.stop_watch_dog:
                    self.signals.print_text.emit("看门狗:停止监测")
                    break

                time.sleep(self.check_interval)  # 每3秒检查一次

                # 检查NLM IsConnected
                nlm_ok = self.check_nlm_connected()
                self.nlm_check_count += 1

                current_time = time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.localtime())
                # 检测网卡状态变化
                if self.last_nlm_state == True and not nlm_ok:
                    # 网卡断开（从True变为False）
                    self.signals.print_text.emit(
                        f"看门狗:网线被拔出(WLAN断开)或网卡被禁用[{current_time}]")

                elif self.last_nlm_state == False and nlm_ok:
                    # 网卡恢复（从False变为True）
                    self.signals.print_text.emit(
                        f"看门狗:网卡已恢复连接，继续监测中...[{current_time}]")

                self.last_nlm_state = nlm_ok

                if not nlm_ok:
                    # 网卡未连接（禁用/网线拔出/WiFi断开），不做任何操作，等待网卡就绪
                    continue

                # NLM为True，每检查self.check_internet_timeout次NLM就检查1次互联网连通性
                if self.nlm_check_count % self.check_internet_timeout == 0:
                    internet_ok = self.check_internet_connected()
                    print("网络测试:", internet_ok)

                    if nlm_ok and internet_ok:
                        # 网络正常，无需操作
                        pass
                    elif nlm_ok and not internet_ok:
                        # NLM通但互联网不通，需要重连
                        self.try_reconnect()

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
