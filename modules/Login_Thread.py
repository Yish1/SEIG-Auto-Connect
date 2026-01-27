import re
import os
import requests
import rsa
import json
# import debugpy
import binascii
from io import BytesIO
from PIL import Image, ImageFilter
import ddddocr
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QApplication, QWidget, QInputDialog, QSystemTrayIcon, QMenu, QAction, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox
from PyQt5.QtCore import QThreadPool, pyqtSignal, QRunnable, QObject

from modules.State import global_state
from modules.Working_signals import WorkerSignals

state = global_state()

class login_Thread(QRunnable):
    def __init__(self):
        super().__init__()
        self.signals = WorkerSignals()
    def run(self):
        self.signals.print_text.emit("即将登录: " + state.username + " IP: " + state.wlanuserip)

        session = requests.session()

        code, image = self.show_captcha_and_input_code(session)

        pub_key = rsa.PublicKey.load_pkcs1_openssl_pem(state.rsa_public_key.encode())

        # 登录数据
        login_data = {
            "userName": state.username,
            "password": state.password,
            "rand": code
        }

        login_key = self.encrypt_rsa(json.dumps(login_data), pub_key)
        # 构造请求头和Cookie
        headers = {
            "Origin": f"http://{state.esurfingurl}",
            "Referer": f"http://{state.esurfingurl}/qs/index_gz.jsp?wlanacip={state.wlanacip}&wlanuserip={state.wlanuserip}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
        }

        # 构造请求参数
        post_data = {
            'loginKey': login_key,
            'wlanuserip': state.wlanuserip,
            'wlanacip': state.wlanacip
        }

        # 发送POST请求
        try:
            response = session.post(
                f'http://{state.esurfingurl}/ajax/login', timeout=3, headers=headers, data=post_data, proxies={"http": None, "https": None}, verify=False)

            if response.status_code == 200:
                data = response.json()
                if data['resultCode'] == "0" or data['resultCode'] == "13002000":
                    self.signals.print_text.emit("成功连接校园网！")
                self.signals.login_status.emit(response)

            else:
                self.signals.print_text.emit(f"请求失败，状态码：{response.status_code}")
                
        except Exception as e:
            self.signals.print_text.emit(f"登录请求失败，请先获取配置并确保配置正确：{e}")
            state.connected = True
            self.signals.run_settings.emit()

        state.login_thread_finished = True

    def encrypt_rsa(self, message, pub_key):
        message_bytes = message.encode('utf-8')
        encrypted = rsa.encrypt(message_bytes, pub_key)
        return binascii.hexlify(encrypted).decode('utf-8')

    def preprocess_image(self, image):
        # 转换为灰度图像
        image = image.convert("L")
        # 应用二值化
        threshold = 128
        image = image.point(lambda p: p > threshold and 255)
        image = image.filter(ImageFilter.MedianFilter(size=3))
        return image

    # 获取验证码图片URL
    def get_captcha_image_url(self, session):
        page_url = f"http://{state.esurfingurl}/qs/index_gz.jsp?wlanacip={state.wlanacip}&wlanuserip={state.wlanuserip}"
        headers = {
            "Origin": f"http://{state.esurfingurl}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
        }

        try:
            response = session.get(page_url, timeout=3, headers=headers, proxies={"http": None, "https": None})
            self.signals.print_text.emit("成功获取登录URL")
        except Exception as e:
            self.signals.print_text.emit(f"请求获取登录页面失败：{e}")
            return None

        try:
            url = re.search(r'/common/image_code\.jsp\?time=\d+',
                            str(response.content)).group()

            if url:
                image_url = f'http://{state.esurfingurl}{url}'
                self.signals.print_text.emit(f"获取验证码图片URL: {image_url}")
                return image_url
            else:
                self.signals.print_text.emit("未找到验证码图片")
                return None

        except Exception as e:
            self.signals.print_text.emit(f"解析页面失败：{e}")
            self.run_settings()
            return None
    # 自动识别验证码

    def show_captcha_and_input_code(self, session):
        image_code_url = self.get_captcha_image_url(session)

        if image_code_url:
            try:
                response = session.get(image_code_url, timeout=3, proxies={"http": None, "https": None}, verify=False)
                if response.status_code == 200:
                    image = Image.open(BytesIO(response.content))
                    ocr = ddddocr.DdddOcr(show_ad = False)
                    processed_image = self.preprocess_image(image)
                    # image.show()
                    code = ocr.classification(processed_image)
                    # result = ocr.classification(image)
                    # 使用正则表达式去除空格、换行和无关符号
                    code = re.sub(
                        r'[\s\.\:\(\)\[\]\{\}\-\+\!\@\#\$\%\^\&\￥\*\_\=\;\,\?\/]', '', code)
                    self.signals.print_text.emit(f"识别出的验证码是：{code}")
                    return code, image
                else:
                    self.signals.print_text.emit(f"无法获取验证码图片，状态码：{response.status_code}")
                    return None, None
            except Exception as e:
                self.signals.print_text.emit(f"获取验证码图片失败：{e}")
                return None, None
        else:
            return None, None
