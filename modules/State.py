# 管理全局变量
import os
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
        
        # 获取用户 AppData\Roaming 路径
        self.config_path = None
        appdata_dir = os.getenv("APPDATA")  # 通常是 C:\Users\<用户名>\AppData\Roaming
        config_dir = os.path.join(appdata_dir, "SAC")
        self.config_path = os.path.join(config_dir, "config.ini")

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
        self.retry_thread_started = False
        self.watch_dog_thread_started = False
        self.new_version_checked = False
        self.login_thread_finished = False
        self.mulit_status = {}

        # 初始化线程池
        self.threadpool = QThreadPool()

        # RSA公钥
        self.rsa_public_key = """
            -----BEGIN PUBLIC KEY-----
            MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCyhncn4Z4RY8wITqV7n6hAapEM
            ZwNBP6fflsGs3Ke5g6Ji4AWvNflIXZLNTGIuykoU1v2Bitylyuc9nSKLTvBdcytB
            +4X4CvV4oVDr2aLrXs7LhTNyykcxyhyGhokph0Cb4yR/mybK6OeH2ME1/AZS7AZ4
            pe2gw9lcwXQVF8DJwwIDAQAB
            -----END PUBLIC KEY-----
            """
        
app_state = global_state()