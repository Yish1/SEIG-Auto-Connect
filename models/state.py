# 管理全局变量

from PyQt5.QtCore import QThreadPool

class global_state:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if hasattr(self, '_initialized') and self._initialized:
            return
        self._initialized = True

        self.version = 1.3

        # 配置类变量
        self.username = None
        self.password = None
        self.esurfingurl = None
        self.wlanacip = None
        self.wlanuserip = None
        self.save_pwd = None
        self.auto_connect = None
        self.watch_dog_timeout = None
        self.login_mode = 0
        self.mulit_login = 1
        self.mulit_info = {}

        # 运行时变量
        self.stop_watch_dog = False
        self.connected = False
        self.jar_login = False
        self.signature = ""
        self.settings_flag = None
        self.retry_thread_started = False
        self.watch_dog_thread_started = False
        self.new_version_checked = False
        self.login_thread_finished = False

        # 初始化线程池
        self.threadpool = QThreadPool()

app_state = global_state()