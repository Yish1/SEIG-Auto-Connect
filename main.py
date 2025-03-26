import re
import os
import sys
import ctypes
import requests
import rsa
import json
import time
import win32com.client
import msvcrt
# import debugpy
import builtins
import threading
import binascii
import subprocess
from io import BytesIO
from PIL import Image, ImageFilter
import ddddocr
import webbrowser as web
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QApplication, QWidget, QInputDialog, QSystemTrayIcon, QMenu, QAction, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox
from PyQt5.QtCore import QThreadPool, pyqtSignal, QRunnable, QObject, QTimer, QMutex
from ui import Ui_MainWindow  # 导入ui文件
from settings import Ui_sac_settings

# debugpy.listen(("0.0.0.0", 5678))
# debugpy.wait_for_client()  # 等待调试器连接

version = 1.2
username = None
password = None
esurfingurl = None
wlanacip = None
wlanuserip = None
save_pwd = None
auto_connect = None
watch_dog_timeout = None
mulit_login = 1
mulit_info = {}

stop_watch_dog = False
connected = False
jar_login = False
signature = ""
settings_flag = None
retry_thread_started = False
watch_dog_thread_started = False
new_version_checked = False
login_thread_finished = False

# RSA公钥
rsa_public_key = """
    -----BEGIN PUBLIC KEY-----
    MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCyhncn4Z4RY8wITqV7n6hAapEM
    ZwNBP6fflsGs3Ke5g6Ji4AWvNflIXZLNTGIuykoU1v2Bitylyuc9nSKLTvBdcytB
    +4X4CvV4oVDr2aLrXs7LhTNyykcxyhyGhokph0Cb4yR/mybK6OeH2ME1/AZS7AZ4
    pe2gw9lcwXQVF8DJwwIDAQAB
    -----END PUBLIC KEY-----
    """


class MainWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def setupUi(self, MainWindow):
        super().setupUi(MainWindow)
        self.setWindowTitle(f"SEIG虚空终端{version}")
        self.setWindowIcon(QtGui.QIcon(':/icon/yish.ico'))
        self.run_settings_action = QtWidgets.QAction("登录参数", self)
        self.menu.addAction(self.run_settings_action)

    def __init__(self):
        global retry_thread_started
        super().__init__()
        self.setupUi(self)  # 初始化UI
        self.setMinimumSize(QtCore.QSize(263, 577))
        self.progressBar.hide()

        self.tray_icon = QSystemTrayIcon(QtGui.QIcon(':/icon/yish.ico'), self)
        self.tray_icon.setToolTip(f"SEIG虚空终端{version}")
        # 连接单击托盘图标的事件
        self.tray_icon.activated.connect(self.on_tray_icon_clicked)


        # 托盘菜单
        tray_menu = QMenu(self)
        restore_action = QAction("恢复", self)
        quit_action = QAction("退出", self)

        restore_action.triggered.connect(self.showNormal)
        quit_action.triggered.connect(self.close)

        tray_menu.addAction(restore_action)
        tray_menu.addAction(quit_action)
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()

        self.threadpool = QThreadPool()

        # 重写print
        self.global_print = builtins.print

        def print(*args, **kwargs):
            self.global_print(*args, **kwargs)
            text = " ".join(map(str, args))
            try:
                self.listWidget.addItem(text)
            except:
                pass
            try:
                self.listWidget.setCurrentRow(self.listWidget.count() - 1)
            except Exception as e:
                print(f"ERROR:{e}")
        builtins.print = print

        # 启动时运行
        self.read_config()
        self.init_save_password()
        self.try_auto_connect()

        # 绑定按钮功能
        self.pushButton.clicked.connect(self.login)
        self.pushButton_2.clicked.connect(self.logout)
        self.checkBox.clicked.connect(lambda: self.update_config(
            "save_pwd", 1 if self.checkBox.isChecked() else 0))
        self.checkBox_2.clicked.connect(lambda: self.update_config(
            "auto_connect", 1 if self.checkBox_2.isChecked() else 0) or (
                print("开机将自启，并自动登录，需要记住密码\n看门狗每10分钟检测一次网络连接情况\n下次自动登录成功时，将启动看门狗") if self.checkBox_2.isChecked() else None) or (
                self.checkBox.setChecked(True) if self.checkBox_2.isChecked() else None) or (
                    self.add_to_startup() if self.checkBox_2.isChecked() else self.add_to_startup(1)) or (self.update_config("save_pwd", 1))
        )

        self.pushButton_3.clicked.connect(
            lambda: web.open_new("https://cmxz.top"))
        self.run_settings_action.triggered.connect(self.run_settings)
        print("感谢您使用此工具！\n请不要在任何大型社交平台\n(B站、贴吧、小红书、狐友等)\n讨论此工具！")

    def on_tray_icon_clicked(self, reason):
        if reason == QSystemTrayIcon.Trigger:  # 仅响应左键单击
            self.showNormal()
            self.activateWindow()
            
    def changeEvent(self, event):
        if event.type() == QtCore.QEvent.WindowStateChange:
            if self.isMinimized():
                if settings_flag != None:
                    print("请先关闭设置界面再最小化！")
                    self.showNormal()
                    return
                else:
                    self.hide()  # 隐藏窗口
                    self.tray_icon.showMessage(
                        f"SEIG虚空终端{version}",
                        "程序已最小化到托盘",
                        QSystemTrayIcon.Information,
                        2000
                    )
        super(MainWindow, self).changeEvent(event)

    def closeEvent(self, event):
        global stop_watch_dog
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("退出确认")
        msg_box.setText("您需要退出程序 还是最小化到托盘？")
        msg_box.setIcon(QMessageBox.Question)

        btn_quit = msg_box.addButton("退出", QMessageBox.YesRole)
        btn_minimize = msg_box.addButton("最小化到托盘", QMessageBox.NoRole)

        msg_box.exec_()

        if msg_box.clickedButton() == btn_quit:
            # 关闭其他窗口的代码
            try:
                for widget in QApplication.topLevelWidgets():
                    if isinstance(widget, QWidget) and widget != self:
                        widget.close()
            except:
                pass
            stop_watch_dog = True
            event.accept()

        else:
            event.ignore()  # 最小化到托盘
            self.hide()  # 隐藏窗口
            self.tray_icon.showMessage(
                f"SEIG虚空终端{version}",
                "程序已最小化到托盘",
                QSystemTrayIcon.Information,
                2000
            )
    def init_save_password(self):
        if save_pwd == "1":
            decrypted_password = ''.join(
                chr(ord(char) - 10) for char in password)
            if self.lineEdit_2.text() != "":
                pass
            else:
                self.lineEdit_2.setText(decrypted_password)
        else:
            pass
        self.lineEdit.setText(username)

    def add_to_startup(self, mode=None):
        # 获取启动文件夹路径
        startup_folder = os.path.join(os.getenv(
            'APPDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
        # 获取当前程序的完整路径
        app_path = sys.argv[0]
        shortcut_path = os.path.join(startup_folder, 'SEIG_Auto_Connect.lnk')

        if mode == 1:
            # 删除开机自启项
            if os.path.exists(shortcut_path):
                os.remove(shortcut_path)
                print("开机自启已关闭")
            else:
                print("开机自启项不存在，无需删除。")
            return

        # 检查是否已存在开机自启项
        if os.path.exists(shortcut_path):
            pass
        else:
            print(f"已添加{app_path}至启动目录")

        # 写入自启动文件
        shell = win32com.client.Dispatch("WScript.Shell")
        shortcut = shell.CreateShortCut(shortcut_path)
        shortcut.TargetPath = app_path
        shortcut.WorkingDirectory = os.path.dirname(app_path)
        shortcut.IconLocation = app_path
        shortcut.save()

    def try_auto_connect(self):
        global retry_thread_started, jar_login
        self.read_config()
        if auto_connect == "1":
            print("正在尝试自动连接...")

            if not username.startswith('t'):
                jar_login = True
            if jar_login:
                self.login()
                return
            
            try:
                self.auto_thread = login_Thread(5)
                self.auto_thread.signals.enable_buttoms.connect(
                    self.enable_buttoms)
                self.auto_thread.signals.show_input_dialog1.connect(
                    self.show_input_dialog)
                self.auto_thread.signals.thread_login.connect(self.login)
                self.auto_thread.signals.finished.connect(
                    lambda: print("结束线程"))
                self.threadpool.start(self.auto_thread)
                retry_thread_started = True
                self.add_to_startup()
            except Exception as e:
                print(e)
        else:
            pass

    def mulit_login_mode(self, ip, user, pwd):
        global retry_thread_started, mulit_login
        try:
            self.login("mulit", ip, user, pwd)
        except Exception as e:
            print(e)
        # try:
        # self.threadpool = QThreadPool()
        # self.auto_thread = login_Thread(2)
        # self.auto_thread.signals.enable_buttoms.connect(
        #     self.enable_buttoms)
        # self.auto_thread.signals.show_input_dialog1.connect(
        #     self.show_input_dialog)
        # self.auto_thread.signals.thread_login.connect(lambda:self.login("mulit", ip, user, pwd))
        # self.auto_thread.signals.finished.connect(
        #     lambda: print("结束线程"))
        # self.threadpool.start(self.auto_thread)
        # retry_thread_started = True
            # self.add_to_startup()
        # except Exception as e:
        #     print(e)

    def run_settings(self):
        global settings_flag
        if settings_flag is None:
            try:
                settings_window = settingsWindow(mainWindow)
                settings_flag = settings_window.run_settings_window()
            except Exception as e:
                print(f"无法打开设置界面{e}")

    def read_config(self):
        global username, password, esurfingurl, wlanacip, wlanuserip, save_pwd, auto_connect, watch_dog_timeout, mulit_login
        config = {}
        if not os.path.exists('config.ini'):
            with open('config.ini', 'w', encoding='utf-8') as file:
                file.write("")

        with open('config.ini', 'r', encoding='utf-8') as file:
            for line in file:
                if '=' in line:
                    key, value = line.strip().split('=', 1)
                    config[key.strip('[]')] = value.strip()
        try:
            username = config.get('username') if config.get(
                'username') else self.update_config("username", "114514", "w!")
            password = config.get('password') if config.get(
                'password') else self.update_config("password", "114514", "w!")
            wlanacip = str(config.get('wlanacip')) if config.get(
                'wlanacip') else self.update_config("wlanacip", "0.0.0.0", "w!")
            wlanuserip = str(config.get('wlanuserip')) if config.get(
                'wlanuserip') else self.update_config("wlanuserip", "0.0.0.0", "w!")
            esurfingurl = str(config.get('esurfingurl')) if config.get(
                'esurfingurl') else self.update_config("esurfingurl", "0.0.0.0:0", "w!")
            save_pwd = config.get('save_pwd') if config.get(
                'save_pwd') else self.update_config("save_pwd", "1", "w!")
            auto_connect = config.get('auto_connect') if config.get(
                'auto_connect') else self.update_config("auto_connect", "0", "w!")
            watch_dog_timeout = int(config.get('watch_dog_timeout')) if config.get(
                'watch_dog_timeout') else self.update_config("watch_dog_timeout", 300, "w!")
            mulit_login = int(config.get('mulit_login')) if config.get(
                'mulit_login') else self.update_config("mulit_login", "1", "w!")

            if save_pwd == "1":
                self.checkBox.setChecked(True)
            else:
                self.checkBox.setChecked(False)

            if auto_connect == "1":
                self.checkBox_2.setChecked(True)
            else:
                self.checkBox_2.setChecked(False)

        except Exception as e:
            print(f"配置读取失败，已重置为默认值！{e} ")
            os.remove("config.ini")
            self.read_config()
        return config

    def update_config(self, variable, new_value, mode=None):
        lines = []
        with open('config.ini', 'r+', encoding='utf-8') as file:
            lines = file.readlines()

        updated = False
        seen_keys = set()  # 防止重复项

        # 确保每个值都有 \n 结尾，并移除无效行
        for i in range(len(lines)):
            if not lines[i].endswith('\n'):
                lines[i] += '\n'
            if not lines[i].startswith('['):
                lines[i] = ''  # 删除无效行

        for i, line in enumerate(lines):
            if '=' in line:
                key, value = line.strip().split('=', 1)
                key = key.strip('[]')
                value = value.strip()

                # 删除值为空的项
                if not value:
                    lines[i] = ''
                    continue

                if key == variable:  # 如果存在，则替换现有的值
                    if new_value:  # 仅在新值非空时替换
                        lines[i] = f"[{key}]={new_value}\n"
                        updated = True
                    else:
                        lines[i] = ''  # 如果新值为空，则删除此项

                    if key in seen_keys:
                        lines[i] = ''
                    seen_keys.add(key)

                elif key in seen_keys:
                    lines[i] = ''  # 删除重复项
                else:
                    seen_keys.add(key)  # 记录新项

        # 如不存在且新值非空，则在文件末尾添加
        if not updated and new_value:
            lines.append(f"[{variable}]={new_value}\n")

        # 过滤空行
        lines = [line for line in lines if line.strip()]

        with open('config.ini', 'w+', encoding='utf-8') as file:
            file.writelines(lines)

        if mode != "w!":
            self.read_config()

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
        page_url = f"http://{esurfingurl}/qs/index_gz.jsp?wlanacip={wlanacip}&wlanuserip={wlanuserip}"
        headers = {
            "Origin": f"http://{esurfingurl}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
        }

        try:
            response = session.get(page_url, timeout=3, headers=headers)
            print("成功获取登录URL")
        except Exception as e:
            print(f"请求获取登录页面失败：{e}")
            return None

        try:
            url = re.search(r'/common/image_code\.jsp\?time=\d+',
                            str(response.content)).group()

            if url:
                image_url = f'http://{esurfingurl}{url}'
                print(f"获取验证码图片URL: {image_url}")
                return image_url
            else:
                print("未找到验证码图片")
                return None

        except Exception as e:
            print(f"解析页面失败：{e}")
            self.run_settings()
            return None
    # 自动识别验证码

    def show_captcha_and_input_code(self, session):
        image_code_url = self.get_captcha_image_url(session)

        if image_code_url:
            try:
                response = session.get(image_code_url, timeout=3)
                if response.status_code == 200:
                    image = Image.open(BytesIO(response.content))
                    ocr = ddddocr.DdddOcr()
                    processed_image = self.preprocess_image(image)
                    # image.show()
                    code = ocr.classification(processed_image)
                    # result = ocr.classification(image)
                    # 使用正则表达式去除空格、换行和无关符号
                    code = re.sub(
                        r'[\s\.\:\(\)\[\]\{\}\-\+\!\@\#\$\%\^\&\￥\*\_\=\;\,\?\/]', '', code)
                    print(f"识别出的验证码是：{code}")
                    return code, image
                else:
                    print("无法获取验证码图片，状态码：", response.status_code)
                    return None, None
            except Exception as e:
                print(f"获取验证码图片失败：{e}")
                return None, None
        else:
            return None, None

    def login(self, mode=None, ip=None, user=None, pwd=None):
        global username, password, esurfingurl, wlanacip, wlanuserip, signature, retry_thread_started, connected, watch_dog_thread_started, stop_watch_dog, jar_login, login_thread_finished
        username = self.lineEdit.text()
        self.update_config("username", username)
        password = self.lineEdit_2.text()

        if mode == "mulit":
            username = user
            password = pwd
            wlanuserip = ip

        if esurfingurl == "0.0.0.0:0" or esurfingurl == "自动获取失败,请检查网线连接":
            self.run_settings()
            print("请先获取或手动填写参数！")
            return
        if not username:
            print("请输入上网帐号，@后面去掉")
            return
        if not password or password == "0":
            print("请输入密码")
            return
        
        print("即将登录: " + username + " IP: " + wlanuserip)

        if not username.startswith('t'):  # 判断是否以 't' 开头，仅适用于广州软件学院
            self.login_jar(username, password, wlanuserip, wlanacip)
            jar_login = True
            return

        session = requests.session()

        code, image = self.show_captcha_and_input_code(session)

        if mode == 1:
            try:
                image.show()
                self.window = QWidget()
                self.window.setWindowIcon(QtGui.QIcon(':/icon/yish.ico'))
                cust_code, ok_pressed = QInputDialog.getText(
                    self.window, "手动输入验证码", "请输入验证码:")
                if ok_pressed and cust_code:
                    code = cust_code
                else:
                    print("请输入验证码！")
                    return
            except Exception as e:
                print("无法获取验证码:", e)

        pub_key = rsa.PublicKey.load_pkcs1_openssl_pem(rsa_public_key.encode())

        # 登录数据
        login_data = {
            "userName": username,
            "password": password,
            "rand": code
        }

        login_key = self.encrypt_rsa(json.dumps(login_data), pub_key)
        # 构造请求头和Cookie
        headers = {
            "Origin": f"http://{esurfingurl}",
            "Referer": f"http://{esurfingurl}/qs/index_gz.jsp?wlanacip={wlanacip}&wlanuserip={wlanuserip}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
        }

        # 构造请求参数
        post_data = {
            'loginKey': login_key,
            'wlanuserip': wlanuserip,
            'wlanacip': wlanacip
        }

        # 发送POST请求
        try:
            response = session.post(
                f'http://{esurfingurl}/ajax/login', timeout=3, headers=headers, data=post_data)

            if response.status_code == 200:
                data = response.json()
                if data['resultCode'] == "0" or data['resultCode'] == "13002000":
                    signature = response.cookies["signature"]
                    print("成功连接校园网！")
                    connected = True

                    self.check_new_version()

                    if watch_dog_thread_started != True:
                        stop_watch_dog = False
                        self.watchdog_thread = watch_dog()
                        self.watchdog_thread.signals.update_progress.connect(
                            self.update_progress_bar)
                        self.watchdog_thread.signals.print_text.connect(
                            self.update_table)
                        self.watchdog_thread.signals.thread_login.connect(
                            self.login)
                        self.threadpool.start(self.watchdog_thread)
                    if self.checkBox.isChecked():
                        encrypted_password = ''.join(
                            chr(ord(char) + 10) for char in password)
                        self.update_config("password", encrypted_password)
                    self.update_config("username", username)
                elif data['resultCode'] == "13018000":
                    print("已办理一人一号多终端业务的用户，请使用客户端登录")
                else:
                    print(f"登录失败: {data['resultInfo']}")
                    if data['resultInfo'] == "验证码错误":
                        if mode == "mulit":
                            pass
                        else:
                            try:
                                if retry_thread_started == False:
                                    connected = False
                                    print("验证码识别错误，即将重试...")
                                    self.thread = login_Thread(5)
                                    self.thread.signals.enable_buttoms.connect(
                                        self.enable_buttoms)
                                    self.thread.signals.show_input_dialog1.connect(
                                        self.show_input_dialog)
                                    self.thread.signals.thread_login.connect(
                                        self.login)
                                    self.thread.signals.print_text.connect(
                                        self.update_table)
                                    self.thread.signals.finished.connect(
                                        lambda: print("结束线程"))
                                    self.threadpool.start(self.thread)
                                    retry_thread_started = True
                            except:
                                pass
            else:
                print("请求失败，状态码：", response.status_code)
        except Exception as e:
            print(f"登录请求失败，请先获取配置并确保配置正确：{e}")
            connected = True
            self.run_settings()

        login_thread_finished = True

    def login_jar(self, username, password, userip, acip):
        self.enable_buttoms(0)
        try:
            os.remove("logout.signal")
        except:
            pass
        try:
            self.jar_Thread = jar_Thread(username, password, userip, acip)
            self.jar_Thread.signals.enable_buttoms.connect(self.enable_buttoms)
            # self.jar_Thread.signals.connected_success.connect(
            #     self.update_progress_bar)
            self.jar_Thread.signals.print_text.connect(self.update_table)
            self.jar_Thread.signals.update_check.connect(
                self.check_new_version)
            self.jar_Thread.signals.jar_login_success.connect(
                self.save_password)
            self.threadpool.start(self.jar_Thread)
        except Exception as e:
            print(f"登录失败：{e}")
            self.enable_buttoms(1)

    def save_password(self):
        if self.checkBox.isChecked():
            encrypted_password = ''.join(
                chr(ord(char) + 10) for char in password)
            self.update_config("password", encrypted_password)

    def logout(self):
        global stop_watch_dog, jar_login
        username = self.lineEdit.text()
        if jar_login:
            if not os.path.exists('logout.signal'):
                with open('logout.signal', 'w', encoding='utf-8') as file:
                    file.write("")
            jar_Thread.term_all_processes()
            print("执行下线操作中, 请稍后...")
            jar_login = False
            return

        if username and signature:
            try:
                response = requests.post(
                    url=f'http://{esurfingurl}/ajax/logout',
                    headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0',
                        'Cookie': f'signature={signature}; loginUser={username}',
                        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
                    },
                    data=f"wlanuserip={wlanuserip}&wlanacip={wlanacip}",
                    timeout=3
                )

                if response.status_code == 200:
                    data = response.json()
                    print("成功发送下线请求")
                    if data['resultCode'] == "0" or data['resultCode'] == "13002000":
                        stop_watch_dog = True
                        print("下线成功")
                    else:
                        print(f"下线失败: {data['resultInfo']}")
                else:
                    print("请求失败，状态码：", response.status_code)
            except Exception as e:
                print(f"下线失败：{e}")
        else:
            print("您尚未登录，无需下线！")

    def enable_buttoms(self, mode):
        if mode == 0:
            self.lineEdit.setEnabled(False)
            self.lineEdit_2.setEnabled(False)
            self.pushButton.setEnabled(False)
            self.pushButton_2.setEnabled(False)
        if mode == 1:
            self.lineEdit.setEnabled(True)
            self.lineEdit_2.setEnabled(True)
            self.pushButton.setEnabled(True)
            self.pushButton_2.setEnabled(True)

    def show_input_dialog(self):
        self.login(1)

    def update_progress_bar(self, mode, value, value2):
        self.progressBar.setValue(value)
        self.progressBar.setMaximum(value2)
        if mode == 1:
            self.progressBar.show()
        elif mode == 0:
            self.progressBar.hide()

    def update_table(self, text):
        # 超过 150 行，就清空列表
        if self.listWidget.count() >= 150:
            self.listWidget.clear()

        self.listWidget.addItem(text)
        self.listWidget.setCurrentRow(self.listWidget.count() - 1)
        self.global_print(text)

    def check_new_version(self):
        self.update_thread = UpdateThread()
        self.threadpool.start(self.update_thread)
        self.update_thread.signals.show_message.connect(
            self.update_message)
        self.update_thread.signals.print_text.connect(
            self.update_table)
        self.update_thread.signals.logout.connect(self.logout)
        # self.update_thread.signals.finished.connect(
        #     lambda: print("检查更新线程结束"))

    def update_message(self, message):  # 更新弹窗
        msgBox = QMessageBox()
        msgBox.setWindowTitle("检测到新版本！")
        msgBox.setText(message)
        msgBox.setWindowIcon(QtGui.QIcon(':/icons/yish.ico'))
        okButton = msgBox.addButton("立刻前往", QMessageBox.AcceptRole)
        noButton = msgBox.addButton("下次一定", QMessageBox.RejectRole)
        msgBox.exec_()
        clickedButton = msgBox.clickedButton()
        if clickedButton == okButton:
            os.system("start https://cmxz.top/SAC")
        else:
            self.update_table("检测到新版本！")


class WorkerSignals(QObject):
    finished = pyqtSignal()
    enable_buttoms = pyqtSignal(int)
    show_input_dialog1 = pyqtSignal()
    thread_login = pyqtSignal()
    update_progress = pyqtSignal(int, int, int)
    connected_success = pyqtSignal()
    print_text = pyqtSignal(str)
    show_message = pyqtSignal(str, str)
    update_check = pyqtSignal()
    logout = pyqtSignal()
    jar_login_success = pyqtSignal()


class login_Thread(QRunnable):
    def __init__(self, times):
        super().__init__()
        self.signals = WorkerSignals()
        self.times = times

    def run(self):
        global retry_thread_started
        # debugpy.breakpoint()
        self.signals.enable_buttoms.emit(0)
        while self.times > 0:
            time.sleep(3)
            if connected == True:
                retry_thread_started = False
                self.signals.enable_buttoms.emit(1)
                self.signals.finished.emit()
                return
                
            self.signals.print_text.emit(f"登录失败,还剩{self.times}次尝试")
            self.times -= 1
            self.signals.thread_login.emit()
        if connected == False:
            retry_thread_started = False
            self.signals.print_text.emit("已多次尝试无法获取验证码，请手动输入验证码、重试或联系Yish_")
            if self.times == 0:
                self.signals.show_input_dialog1.emit()
        self.signals.enable_buttoms.emit(1)
        self.signals.finished.emit()


class jar_Thread(QRunnable):
    processes = []
    lock = QMutex()  # 线程锁，防止竞争条件

    def __init__(self, username, password, userip, acip):
        super().__init__()
        self.signals = WorkerSignals()
        self.username = username
        self.password = password
        self.userip = userip
        self.acip = acip
        self.process = None  # 存储当前线程的进程

    def run(self):
        # debugpy.breakpoint()
        try:
            java_executable = os.path.join(
                os.getcwd(), "jre", "bin", "java.exe")
            jar_path = os.path.join(os.getcwd(), "login.jar")

            if not os.path.exists(java_executable):
                self.signals.print_text.emit("错误：找不到 Java 运行环境！")
                return
            if not os.path.exists(jar_path):
                self.signals.print_text.emit("错误：找不到 login.jar！")
                return

            java_cmd = [
                java_executable, "-jar", jar_path,
                "-u", self.username,
                "-p", self.password,
                "-t", self.userip,
                "-a", self.acip
            ]

            startupinfo = None
            if os.name == "nt":  # 仅 Windows 适用
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

            # 启动新的子进程
            self.process = subprocess.Popen(
                java_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,  # 兼容不同 Python 版本
                startupinfo=startupinfo,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            )

            pid = self.process.pid

            jar_Thread.lock.lock()  # 手动上锁
            jar_Thread.processes.append(self.process)
            jar_Thread.lock.unlock()  # 解锁

            self.signals.print_text.emit(f"进程 {pid} 启动成功！")
            # 处理子进程的输出
            def read_output():
                global connected, login_thread_finished
                while True:
                    output = self.process.stdout.readline()
                    if output:
                        self.signals.print_text.emit(
                            f"{pid}: {output.strip()}")

                        if "The network has been connected" in output:
                            jar_Thread.term_all_processes(pid)  # 终止当前进程
                            self.signals.print_text.emit(
                                f"{pid}: 当前设备已连接互联网，无需再次登录\n如果没有使用此工具登录\n将不能使用此工具的下线功能\n请使用天翼校园网手动下线，或等待8分钟")
                            self.signals.update_check.emit()
                            self.signals.enable_buttoms.emit(1)

                        if "The login has been authorized" in output:
                            self.signals.connected_success.emit()
                            self.signals.enable_buttoms.emit(1)
                            connected = True
                            self.signals.print_text.emit(
                                f"{pid}: 登录成功！即将发送心跳... :)")
                            self.signals.print_text.emit(f"{pid}:『只要心跳仍在，我们就不会掉线』")
                            # 发送保存密码信号
                            self.signals.jar_login_success.emit()

                        if "Send Keep Packet" in output:
                            self.signals.print_text.emit(f"{pid}: 心跳成功，请不要关闭此程序，\n需要每480秒心跳保持连接！")
                            self.signals.update_check.emit()

                        if "KeepUrl is empty" in output:
                            jar_Thread.term_all_processes(pid)
                            self.signals.print_text.emit(
                                f"{pid}: 登录失败，账号或密码错误！")
                            # self.signals.update_check.emit()
                            self.signals.enable_buttoms.emit(1)
                        
                        login_thread_finished = True

                    if self.process.poll() is not None:  # 进程结束时跳出
                        break

                self.process.stdout.close()
                self.process.stderr.close()

            output_thread = threading.Thread(target=read_output, daemon=True)
            output_thread.start()

        except Exception as e:
            self.signals.print_text.emit(f"登录失败: {str(e)}")
            self.signals.enable_buttoms.emit(1)

        self.signals.finished.emit()

    @staticmethod
    def term_all_processes(pid=None):
        def term_jar():
            global login_thread_finished
            jar_Thread.lock.lock()  # 手动上锁
            try:
                if pid is None:
                    # 终止所有进程
                    for process in jar_Thread.processes:
                        try:
                            process.terminate()
                            process.wait()
                            print(f"进程 {process.pid} 已终止。")
                        except Exception as e:
                            print(f"终止进程 {process.pid} 时出错: {str(e)}")
                    jar_Thread.processes.clear()
                else:
                    # 终止特定进程
                    for process in jar_Thread.processes[:]:
                        if process.pid == pid:
                            try:
                                process.terminate()
                                process.wait()
                                print(f"进程 {pid} 已终止。")
                                jar_Thread.processes.remove(process)
                            except Exception as e:
                                print(f"终止进程 {pid} 时出错: {str(e)}")
                            break  # 找到并终止后即可退出循环
            finally:
                jar_Thread.lock.unlock()
                login_thread_finished = True
                try:
                    os.remove("logout.signal")
                except FileNotFoundError:
                    pass

        # 延迟 5.5 秒执行
        QTimer.singleShot(5500, term_jar)

class watch_dog(QRunnable):
    def __init__(self):
        super().__init__()
        self.signals = WorkerSignals()
        try:
            self.ping_timeout = watch_dog_timeout  # 默认设置超时时间
            self.signals.print_text.emit(
                f"看门狗:已就位！每{self.ping_timeout}秒检测一次网络")
            self.signals.update_progress.emit(1, 0, 100)
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
        global watch_dog_thread_started
        original_interval = self.ping_timeout
        if watch_dog_thread_started != True:
            watch_dog_thread_started = True
            while True:
                if stop_watch_dog:
                    self.signals.print_text.emit("看门狗:停止监测")
                    break

                total_sleep_time = self.ping_timeout
                step = 1

                while total_sleep_time > 0:
                    if stop_watch_dog:
                        self.signals.print_text.emit("看门狗:停止监测")
                        watch_dog_thread_started = False
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


class settingsWindow(QtWidgets.QMainWindow, Ui_sac_settings):  # 设置窗口
    def __init__(self, main_instance=None):
        super().__init__()
        central_widget = QtWidgets.QWidget(self)
        self.setCentralWidget(central_widget)
        self.setupUi(central_widget)
        self.setWindowTitle("登录参数")
        self.setWindowIcon(QtGui.QIcon(':/icon/yish.ico'))
        # self.setWindowFlags(QtCore.Qt.WindowStaysOnTopHint)
        self.resize(260, 420)

        self.label_4.hide()

        self.main_instance = main_instance
        self.esurfingurl = esurfingurl
        self.wlanacip = wlanacip
        self.wlanuserip = wlanuserip
        self.stop_flag = False
        self.init_finished = False

        self.pushButton.clicked.connect(self.save_config)
        self.pushButton_2.clicked.connect(self.close)
        self.pushButton_3.clicked.connect(self.get_default)
        self.tabWidget_2.currentChanged.connect(
            lambda index: self.tab_changed(index, 0))
        self.tabWidget.currentChanged.connect(
            lambda index: self.tab_changed(index, 1))
        self.pushButton_4.clicked.connect(lambda: self.add_new_tab("add"))
        self.pushButton_5.clicked.connect(self.del_tab)
        self.pushButton_6.clicked.connect(self.mulit_login_now)

        self.get_config_value()

    def add_new_tab(self, mode=None):
        global mulit_login

        def add_new_tab_func():
            latest_index = self.tabWidget_2.count() - 1
            if latest_index == 4:
                self.show_message("不是哥们，你真有这么多账号吗？", "Vocal")
            elif latest_index >= 14:
                self.show_message("不要啊！不要再加进去了！怎么想都进不去吧", "Stop")
                return

            if latest_index > 0:
                previous_tab_name = self.tabWidget_2.tabText(latest_index)
                new_tab_name = "配置" + str(int(previous_tab_name[2:]) + 1)
            else:
                new_tab_name = "配置2"

            new_tab = QWidget()
            self.tabWidget_2.addTab(new_tab, new_tab_name)
            if mode == "init":
                pass
            else:
                self.tabWidget_2.setCurrentIndex(self.tabWidget_2.count() - 1)

        if mode == "init":
            if self.init_finished == False:
                if mulit_login:
                    pass
                else:
                    mulit_login = 1
                for i in range(mulit_login - 1):
                    add_new_tab_func()
            self.init_finished = True

        elif mode == "add":
            add_new_tab_func()
            mulit_login += 1
            self.main_instance.update_config("mulit_login", mulit_login)

    def del_tab(self):
        global mulit_login
        latest_index = self.tabWidget_2.count() - 1

        if latest_index > 0:
            # 删除最新的标签页
            self.tabWidget_2.removeTab(latest_index)
            mulit_login -= 1
            self.main_instance.update_config("mulit_login", mulit_login)
            for i in range(3):
                self.main_instance.update_config(
                    f"line_edit_{mulit_login}_{i + 1}", "")
        else:
            QMessageBox.warning(self, "警告", "必须保留一个配置项")

    def show_message(self, message, title):
        msgBox = QMessageBox()
        msgBox.setWindowTitle(title)
        msgBox.setWindowIcon(QtGui.QIcon(':/icon/yish.ico'))
        if message is None:
            message = "未知错误"
        message = str(message)
        msgBox.setText(message)
        msgBox.exec_()

    def tab_changed(self, index, mode):
        if mode == 1:
            if index == 1:
                index = self.tabWidget_2.currentIndex()
                self.add_controls_to_tab(index)
                self.add_new_tab("init")
        elif mode == 0:
            self.add_controls_to_tab(index)

    def add_controls_to_tab(self, index):
        current_tab = self.tabWidget_2.widget(index)  # 获取当前选中的 tab 页

        # 检查当前 tab 是否已有布局，如果已有布局则不再重复设置
        current_layout = current_tab.layout()
        if current_layout is not None:
            # print("当前tab已有布局，无需重复设置布局")
            return

        layout = QVBoxLayout()
        current_tab.setLayout(layout)  # 设置新的布局

        labelname = ["IP地址:", "账号:", "密码:"]
        # 三个 QLabel 和三个 QLineEdit
        for i in range(3):
            label = QLabel(labelname[i])
            line_edit = QLineEdit()

            line_edit.setObjectName(f"line_edit_{index}_{i + 1}")
            if i == 2:
                line_edit.setEchoMode(QLineEdit.Password)
            # 将控件添加到新的布局
            layout.addWidget(label)
            layout.addWidget(line_edit)

            line_edit.textChanged.connect(
                lambda text, le=line_edit: self.on_text_changed(le, text))
            text = self.read_config(line_edit.objectName())
            line_edit.setText(text)

        # print(f"Layout and controls added to tab {current_tab.objectName()}")

    def read_config(self, le_name, mode=None):
        global mulit_info
        mconfig = {}

        if not os.path.exists('config.ini'):
            self.main_instance.read_config()

        with open('config.ini', 'r', encoding='utf-8') as file:
            for line in file:
                if '=' in line:
                    key, value = line.strip().split('=', 1)

                    if "line_edit" in key:
                        if key.strip('[]').split('_')[3] == '3':
                            value = ''.join(
                                chr(ord(char) - 10) for char in value)

                        tab_num = key.strip('[]').split('_')[2]
                        login_info = key.strip('[]').split('_')[3]

                        if tab_num not in mulit_info:
                            mulit_info[tab_num] = {}

                        mulit_info[tab_num][login_info] = value
                        # [line_edit_0_1]=192.168.1.1
                        # [line_edit_0_2]=123123
                        # [line_edit_0_3]=123123
                        # [line_edit_1_1]=192.168.1.2
                        # [line_edit_1_2]=114514
                        # [line_edit_1_3]=114514
                    mconfig[key.strip('[]')] = value.strip()
                    if mode:
                        return
        try:
            text = mconfig.get(le_name)
            return text

        except:
            return ""

    def on_text_changed(self, line_edit, text):
        # 在这里处理文本变化的信号
        if line_edit.objectName().split('_')[3] == "3":
            encrypted_password = ''.join(
                chr(ord(char) + 10) for char in text)
            self.main_instance.update_config(
                line_edit.objectName(), encrypted_password)
            return
        self.main_instance.update_config(line_edit.objectName(), text)

    def mulit_login_now(self):
        global mulit_info
        mulit_info = {}
        a = self.read_config("")
        # {'0': {'1': '192.168.1.1', '2': '123123', '3': ''}, '1': {'1': '', '2': '', '3': ''}}

        # 定义登录的任务
        def login_task(key):
            ip = mulit_info[key].get('1', '')
            user = mulit_info[key].get('2', '')
            pwd = mulit_info[key].get('3', '')

            if ip != '' and user != '' and pwd != '':
                self.main_instance.mulit_login_mode(ip, user, pwd)

            else:
                self.stop_flag = True
                self.show_message("存在为空的登录配置，请完善或删除！", "提示")
                print("存在为空的登录配置，请完善或删除！")
                return

        def start_login(index=0):
            self.stop_flag = False
            if index < len(mulit_info):
                key = list(mulit_info.keys())[index]
                login_task(key)  # 执行登录任务

                if self.stop_flag:
                    return

                if index < len(mulit_info) - 1:
                    print("5秒后执行下一拨号任务")
                    QTimer.singleShot(5000, lambda: start_login(index + 1))
            else:
                print("所有任务已完成")

        # 启动登录过程
        start_login()

    def get_config_value(self):
        self.lineEdit.setText(self.esurfingurl)
        self.lineEdit_2.setText(self.wlanacip)
        self.lineEdit_3.setText(self.wlanuserip)

    def save_config(self):
        self.main_instance.update_config("esurfingurl", self.lineEdit.text())
        self.main_instance.update_config("wlanacip", self.lineEdit_2.text())
        self.main_instance.update_config("wlanuserip", self.lineEdit_3.text())
        self.close()

    def get_default(self):
        try:
            response = requests.get(url="http://189.cn/", timeout=2)
            self.esurfingurl = re.search(
                "http://(.+?)/", response.url).group(1)
            self.wlanacip = re.search("wlanacip=(.+?)&", response.url).group(1)
            self.wlanuserip = re.search(
                "wlanuserip=(.+)", response.url).group(1)
            self.get_config_value()
            try:
                self.pushButton.setEnabled(True)
                self.label_4.hide()
                print("成功获取参数")
            except:
                pass
        except Exception as e:
            print(f"获取参数失败(请检查网线，并确保断开了热点)：{e}")
            self.label_4.show()
            self.pushButton.setEnabled(False)

    def run_settings_window(self):
        self.show()
        return self

    def closeEvent(self, event):
        # print("设置被关闭")
        global settings_flag
        settings_flag = None
        event.accept()


class UpdateThread(QRunnable):
    def __init__(self):
        super().__init__()
        self.signals = WorkerSignals()

    def run(self):
        # debugpy.breakpoint()  # 在此线程启动断点调试
        global new_version_checked
        headers = {
            'User-Agent': 'CMXZ-SAC_%s' % (version)
        }
        # self.signals.print_text.emit(str(headers))
        updatecheck = "https://cmxz.top/programs/sac/check.php"

        if new_version_checked == True:
            return

        try:
            page = requests.get(updatecheck, timeout=5, headers=headers)
            newversion = float(page.text)
            # self.signals.print_text.emit("云端版本号为:", newversion)
            findnewversion = "检测到新版本！"
            # self.signals.print_text.emit(str(newversion))
            if newversion > version:  # and float(latest_version) < newversion:
                # self.signals.print_text.emit(f"检测到新版本:{newversion},当前版本为:{version}")
                new_version_detail = requests.get(
                    updatecheck + "?detail", timeout=5, headers=headers)
                new_version_detail = new_version_detail.text
                self.signals.show_message.emit("云端最新版本: %s<br>当前版本: %s<br><br>%s" % (
                    newversion, version, new_version_detail), findnewversion)
                        
        except Exception as e:
            self.signals.print_text.emit(f"CMXZ_API_CHECK_UPDATE_ERROR: {e}")

        try:
            is_enable = requests.get(
                updatecheck + "?enable", timeout=5, headers=headers)
            is_enable = int(is_enable.text)
            new_version_checked = True

            if is_enable == 0:
                self.signals.show_message.emit("当前版本已被停用，请及时更新！", "警告")
                self.signals.logout.emit()
                return
        except:
            pass

        self.signals.finished.emit()


if __name__ == "__main__":
    try:
        # 防止重复运行
        lock_file = os.path.expanduser("~/.Seig-auto-connect.lock")
        fd = os.open(lock_file, os.O_RDWR | os.O_CREAT)
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError:
            os.close(fd)
            user32 = ctypes.windll.user32
            result = user32.MessageBoxW(
                None,
                "另一个虚空终端正在运行。\n是否继续运行？\n\nAnother SAC is already running.\nDo you want to continue?",
                "Warning!",
                0x31
            )
            if result == 2:
                sys.exit()  # 退出程序
            elif result == 1:
                print("用户选择继续运行。")

        if hasattr(QtCore.Qt, "AA_EnableHighDpiScaling"):
            QtWidgets.QApplication.setAttribute(
                QtCore.Qt.AA_EnableHighDpiScaling, True)
        # 启用高DPI自适应
        if hasattr(QtCore.Qt, "AA_UseHighDpiPixmaps"):
            QtWidgets.QApplication.setAttribute(
                QtCore.Qt.AA_UseHighDpiPixmaps, True)
        app = QtWidgets.QApplication(sys.argv)
        mainWindow = MainWindow()
        mainWindow.show()
        sys.exit(app.exec_())
    except Exception as e:
        user32 = ctypes.windll.user32
        user32.MessageBoxW(None, f"程序启动时遇到严重错误:{e}", "Warning!", 0x30)
        sys.exit()
# 编译指令nuitka --standalone --lto=yes --msvc=latest --disable-ccache --windows-console-mode=disable --enable-plugin=pyqt5,upx --upx-binary=F:\Programs\upx\upx.exe --output-dir=SAC --windows-uac-admin  --windows-icon-from-ico=yish.ico --nofollow-import-to=unittest main.py 
