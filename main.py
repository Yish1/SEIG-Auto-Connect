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
from PyQt5.QtCore import QThreadPool, pyqtSignal, QRunnable, QObject
from Ui.Main_UI import Ui_MainWindow  # 导入ui文件
from Ui.Settings import Ui_sac_settings

from modules import *

state = global_state()
# debugpy.listen(("0.0.0.0", 5678))
# debugpy.wait_for_client()  # 等待调试器连接

class MainWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def setupUi(self, MainWindow):
        super().setupUi(MainWindow)
        self.setWindowTitle(f"SEIG虚空终端{state.version}")
        self.setWindowIcon(QtGui.QIcon(':/icon/yish.ico'))
        self.run_settings_action = QtWidgets.QAction("登录参数", self)
        self.menu.addAction(self.run_settings_action)

    def __init__(self):

        super().__init__()
        self.setupUi(self)  # 初始化UI
        self.setMinimumSize(QtCore.QSize(296, 705))
        self.progressBar.hide()

        self.tray_icon = QSystemTrayIcon(QtGui.QIcon(':/icon/yish.ico'), self)
        self.tray_icon.setToolTip(f"SEIG虚空终端{state.version}")
        # 连接单击托盘图标的事件
        self.tray_icon.activated.connect(self.on_tray_icon_clicked)


        # 托盘菜单
        tray_menu = QMenu(self)
        restore_action = QAction("恢复", self)
        quit_action = QAction("退出", self)
        self.close_now = False
        restore_action.triggered.connect(self.showNormal)
        quit_action.triggered.connect(lambda: (setattr(self, 'close_now', True), self.close()))

        tray_menu.addAction(restore_action)
        tray_menu.addAction(quit_action)
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()

        # 启动时运行
        self.read_config()
        self.init_save_password()
        self.try_auto_connect()

        # 初始化Setting
        self.settings_window = settingsWindow(self)

        # 绑定按钮功能
        self.pushButton.clicked.connect(self.login)
        self.pushButton_2.clicked.connect(self.logout)
        self.checkBox.clicked.connect(lambda: self.update_config(
            "save_pwd", 1 if self.checkBox.isChecked() else 0))
        self.checkBox_2.clicked.connect(lambda: self.update_config(
            "auto_connect", 1 if self.checkBox_2.isChecked() else 0) or (
                self.update_table("开机将自启，并自动登录，需要记住密码\n看门狗每10分钟检测一次网络连接情况\n下次自动登录成功时，将启动看门狗") if self.checkBox_2.isChecked() else None) or (
                self.checkBox.setChecked(True) if self.checkBox_2.isChecked() else None) or (
                    self.add_to_startup() if self.checkBox_2.isChecked() else self.add_to_startup(1)) or (self.update_config("save_pwd", 1))
        )

        self.pushButton_3.clicked.connect(
            lambda: web.open_new("https://cmxz.top"))
        self.run_settings_action.triggered.connect(self.run_settings)
        self.pushButton_4.clicked.connect(self.settings_window.mulit_login_now)

        self.radioButton_2.toggled.connect(lambda checked: checked and self.change_login_mode(0))
        self.radioButton_3.toggled.connect(lambda checked: checked and self.change_login_mode(1))

        self.update_table("感谢您使用此工具！\n请不要在任何大型社交平台\n(B站、贴吧、小红书、狐友等)\n讨论此工具！")

    def on_tray_icon_clicked(self, reason):
        if reason == QSystemTrayIcon.Trigger:  # 仅响应左键单击
            self.showNormal()
            self.activateWindow()
            
    def changeEvent(self, event):
        if event.type() == QtCore.QEvent.WindowStateChange:
            if self.isMinimized():
                self.hide()  # 隐藏窗口
                self.tray_icon.showMessage(
                    f"SEIG虚空终端{state.version}",
                    "程序已最小化到托盘",
                    QSystemTrayIcon.Information,
                    2000
                )
        super(MainWindow, self).changeEvent(event)

    def closeEvent(self, event):
        if self.close_now == False:
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle("退出确认")
            msg_box.setText("您需要退出程序 还是最小化到托盘？")
            msg_box.setIcon(QMessageBox.Question)

            btn_quit = msg_box.addButton("退出", QMessageBox.YesRole)
            btn_minimize = msg_box.addButton("最小化到托盘", QMessageBox.NoRole)

            msg_box.exec_()

            if msg_box.clickedButton() == btn_minimize:
                if state.settings_flag != None:
                    self.update_table("请先关闭设置界面再最小化！")
                    event.ignore()
                    return
                event.ignore()  # 最小化到托盘
                self.hide()  # 隐藏窗口
                self.tray_icon.showMessage(
                    f"SEIG虚空终端{state.version}",
                    "程序已最小化到托盘",
                    QSystemTrayIcon.Information,
                    2000
                )
                return

        # 关闭其他窗口的代码
        try:
            for widget in QApplication.topLevelWidgets():
                if isinstance(widget, QWidget) and widget != self:
                    widget.close()
        except:
            pass
        state.stop_watch_dog = True
        event.accept()
    def init_save_password(self):
        if state.save_pwd == "1" and state.password:
            decrypted_password = ''.join(
                chr(ord(char) - 10) for char in state.password)
            if self.lineEdit_2.text() != "":
                pass
            else:
                self.lineEdit_2.setText(decrypted_password)
        else:
            pass
        self.lineEdit.setText(state.username)

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
                self.update_table("开机自启已关闭")
            else:
                self.update_table("开机自启项不存在，无需删除。")
            return

        # 检查是否已存在开机自启项
        if os.path.exists(shortcut_path):
            pass
        else:
            self.update_table(f"已添加{app_path}至启动目录")

        # 写入自启动文件
        shell = win32com.client.Dispatch("WScript.Shell")
        shortcut = shell.CreateShortCut(shortcut_path)
        shortcut.TargetPath = app_path
        shortcut.WorkingDirectory = os.path.dirname(app_path)
        shortcut.IconLocation = app_path
        shortcut.save()

    def try_auto_connect(self):

        self.read_config()
        if state.auto_connect == "1":
            self.update_table("正在尝试自动连接...")

            if not state.username.startswith('t') and state.login_mode == 0:
                state.jar_login = True
            if state.jar_login:
                self.login()
                return

            self.auto_thread = login_Retry_Thread(5)
            self.auto_thread.signals.enable_buttoms.connect(
                self.enable_buttoms)
            self.auto_thread.signals.show_input_dialog1.connect(
                self.show_input_dialog)
            self.auto_thread.signals.thread_login.connect(self.login)
            self.auto_thread.signals.finished.connect(
                lambda: self.update_table("结束自动登录线程"))
            state.threadpool.start(self.auto_thread)
            state.retry_thread_started = True
            self.add_to_startup()

        else:
            pass

    def mulit_login_mode(self, ip=None, user=None, pwd=None):
        try:
            self.login("mulit", ip, user, pwd)
        except Exception as e:
            self.update_table(e)
        # try:
        # state.threadpool = QThreadPool()
        # self.auto_thread = login_Retry_Thread(2)
        # self.auto_thread.signals.enable_buttoms.connect(
        #     self.enable_buttoms)
        # self.auto_thread.signals.show_input_dialog1.connect(
        #     self.show_input_dialog)
        # self.auto_thread.signals.thread_login.connect(lambda:self.login("mulit", ip, user, pwd))
        # self.auto_thread.signals.finished.connect(
        #     lambda: self.update_table("结束线程"))
        # state.threadpool.start(self.auto_thread)
        # state.retry_thread_started = True
            # self.add_to_startup()
        # except Exception as e:
        #     self.update_table(e)

    def run_settings(self):

        if self.settings_window is not None:
            try:
                self.settings_window.run_settings_window()
            except Exception as e:
                self.update_table(f"无法打开设置界面{e}")

    def read_config(self):
        config = {}

        config = read_config_file(state.config_path)

        # 配置项定义: (属性名, 默认值, 类型转换函数)
        config_maps = [
            ('username', "", str),
            ('password', "", str),
            ('wlanacip', "0.0.0.0", str),
            ('wlanuserip', "0.0.0.0", str),
            ('esurfingurl', "0.0.0.0:0", str),
            ('save_pwd', "1", str),
            ('auto_connect', "0", str),
            ('watch_dog_timeout', 300, int),
            ('mulit_login', 1, int),
            ('login_mode', 0, int),
        ]

        try:
            for key, default, converter in config_maps:
                value = config.get(key)
                if value:
                    setattr(state, key, converter(value))
                else:
                    self.update_config(key, default, "w!")
                    setattr(state, key, default)

            # 更新UI状态
            self.checkBox.setChecked(state.save_pwd == "1")
            self.checkBox_2.setChecked(state.auto_connect == "1")
            self.radioButton_2.setChecked(state.login_mode == 0)
            self.radioButton_3.setChecked(state.login_mode != 0)

        except Exception as e:
            self.update_table(f"配置读取失败，已重置为默认值！{e} ")
            os.remove(state.config_path)
            self.read_config()

        return config

    def update_config(self, variable, new_value, mode=None):
        # delegate to config manager
        update_entry(variable, str(new_value)
                     if new_value is not None else None, state.config_path)
        print(f"更新配置文件：[{variable}]={new_value}\n")

        if mode == "w!":
            pass
        else:
            self.read_config()


    def login(self, mode=None, ip=None, user=None, pwd=None):
        
        state.username = self.lineEdit.text()
        state.password = self.lineEdit_2.text()

        if mode != "mulit":
            # 保存账号密码
            if self.checkBox.isChecked():
                encrypted_password = ''.join(
                    chr(ord(char) + 10) for char in state.password)
                self.update_config("password", encrypted_password)

            self.update_config("username", state.username)

        if mode == "mulit":
            state.username = user
            state.password = pwd
            state.wlanuserip = ip
            current_ip = ip

        if state.esurfingurl == "0.0.0.0:0" or state.esurfingurl == "自动获取失败,请检查网线连接":
            self.run_settings()
            self.update_table("请先获取或手动填写参数！")
            return
        if not state.username:
            self.update_table("账号都不输入登录个锤子啊！")
            return
        if not state.password or state.password == "0":
            self.update_table("你账号没有密码的吗？？？")
            return
        
        if not state.username.startswith('t') and state.login_mode == 0:  # 判断是否以 't' 开头，仅适用于SEIG
            self.login_jar(state.username, state.password, state.wlanuserip, state.wlanacip)
            state.jar_login = True
            return

        def login_status(response):
            data = response.json()
            status = ""
            if data['resultCode'] == "0" or data['resultCode'] == "13002000":
                status = "登录成功"
                state.signature = response.cookies["signature"]
                state.connected = True

                self.check_new_version()

                if state.watch_dog_thread_started != True and mode != "mulit":
                    self.run_watch_dog()

            elif data['resultCode'] == "13018000":
                status = "登录失败：已办理一人一号多终端业务的用户，请使用客户端登录"
                self.update_table("已办理一人一号多终端业务的用户，请使用客户端登录")

            else:
                status = f"登录失败: {data['resultInfo']}"
                self.update_table(status)

                if data['resultInfo'] == "用户认证失败":
                    self.update_table("用户名或密码错误，请重新输入！")
                    return

                if data['resultInfo'] == "验证码错误":
                    if mode == "mulit":
                        pass
                    else:
                        try:
                            if state.retry_thread_started == False:
                                state.connected = False
                                self.update_table("验证码识别错误，即将重试...")
                                self.thread = login_Retry_Thread(5,self)
                                self.thread.signals.enable_buttoms.connect(
                                    self.enable_buttoms)
                                self.thread.signals.show_input_dialog1.connect(
                                    self.show_input_dialog)
                                self.thread.signals.thread_login.connect(
                                    self.login)
                                self.thread.signals.print_text.connect(
                                    self.update_table)
                                self.thread.signals.finished.connect(
                                    lambda: self.update_table("结束线程"))
                                state.threadpool.start(self.thread)
                                state.retry_thread_started = True
                        except Exception as e:
                            print(e)

            if mode == "mulit":
                state.mulit_status[current_ip] = status

                if len(state.mulit_status) == len(state.mulit_info):
                    self.update_table("***多拨登录结果汇总***")
                    success = False
                    
                    for ip, stat in state.mulit_status.items():
                        self.update_table(f"{ip} : {stat}")
                        if stat == "登录成功": success = True

                    state.mulit_status = {}
                    if success : self.run_watch_dog()

        login_thread = login_Thread()
        login_thread.signals.enable_buttoms.connect(
            self.enable_buttoms)
        login_thread.signals.show_input_dialog1.connect(
            self.show_input_dialog)
        login_thread.signals.thread_login.connect(
            self.login)
        login_thread.signals.print_text.connect(
            self.update_table)
        login_thread.signals.login_status.connect(
            login_status)
        login_thread.signals.run_settings.connect(
            self.run_settings)
        login_thread.signals.finished.connect(
            lambda: self.update_table("结束线程"))
        state.threadpool.start(login_thread)
        state.retry_thread_started = True

    def run_watch_dog(self):
        state.stop_watch_dog = False
        self.watchdog_thread = watch_dog()
        self.watchdog_thread.signals.update_progress.connect(
            self.update_progress_bar)
        self.watchdog_thread.signals.print_text.connect(
            self.update_table)
        self.watchdog_thread.signals.thread_login.connect(
            self.login)
        state.threadpool.start(self.watchdog_thread)

    def login_jar(self, username, password, userip, acip):
        self.update_table("即将登录: " + username + " IP: " + userip)
        self.enable_buttoms(0)
        try:
            os.remove("logout.signal")
        except:
            pass
        try:
            self.jar_Thread = jar_Thread(username, password, userip, acip, mainWindow=self)
            self.jar_Thread.signals.enable_buttoms.connect(self.enable_buttoms)
            # self.jar_Thread.signals.connected_success.connect(
            #     self.update_progress_bar)
            self.jar_Thread.signals.print_text.connect(self.update_table)
            self.jar_Thread.signals.update_check.connect(
                self.check_new_version)
            self.jar_Thread.signals.jar_login_success.connect(
                self.save_password)
            state.threadpool.start(self.jar_Thread)
        except Exception as e:
            self.update_table(f"登录失败：{e}")
            self.enable_buttoms(1)

    def save_password(self):
        if self.checkBox.isChecked():
            encrypted_password = ''.join(
                chr(ord(char) + 10) for char in state.password)
            self.update_config("password", encrypted_password)

    def logout(self):

        state.username = self.lineEdit.text()
        if state.jar_login:
            if not os.path.exists('logout.signal'):
                with open('logout.signal', 'w', encoding='utf-8') as file:
                    file.write("")
            jar_Thread.term_all_processes()
            self.update_table("执行下线操作中, 请稍后...")
            state.jar_login = False
            return

        if state.username and state.signature:
            try:
                response = requests.post(
                    url=f'http://{state.esurfingurl}/ajax/logout',
                    headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0',
                        'Cookie': f'signature={state.signature}; loginUser={state.username}',
                        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
                    },
                    data=f"wlanuserip={state.wlanuserip}&wlanacip={state.wlanacip}",
                    timeout=3, 
                    proxies={"http": None, "https": None}, 
                    verify=False
                )

                if response.status_code == 200:
                    data = response.json()
                    self.update_table("成功发送下线请求")
                    if data['resultCode'] == "0" or data['resultCode'] == "13002000":
                        state.stop_watch_dog = True
                        self.update_table("下线成功")
                    else:
                        self.update_table(f"下线失败: {data['resultInfo']}")
                else:
                    self.update_table(f"请求失败，状态码：{response.status_code}")
            except Exception as e:
                self.update_table(f"下线失败：{e}")
        else:
            self.update_table("您尚未登录，无需下线！")

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
        # 超过 500 行，就清空列表
        if self.listWidget.count() >= 500:
            self.listWidget.clear()

        self.listWidget.addItem(text)
        self.listWidget.setCurrentRow(self.listWidget.count() - 1)
        print(text)

    def check_new_version(self):
        self.update_thread = UpdateThread()
        state.threadpool.start(self.update_thread)
        self.update_thread.signals.show_message.connect(
            self.update_message)
        self.update_thread.signals.print_text.connect(
            self.update_table)
        self.update_thread.signals.logout.connect(self.logout)
        # self.update_thread.signals.finished.connect(
        #     lambda: self.update_table("检查更新线程结束"))

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

    def change_login_mode(self, mode):

        if mode == 0:
            self.update_table("已切换为自动识别模式")
            state.login_mode = 0
            self.update_config("login_mode", "0")
        elif mode == 1:
            self.update_table("已切换为t模式")
            state.login_mode = 1
            self.update_config("login_mode", "1")

class login_Retry_Thread(QRunnable):
    def __init__(self, times, parent=None):
        super().__init__()
        self.signals = WorkerSignals()
        self.times = times
        # self.parent = parent

    def run(self):

        # debugpy.breakpoint()
        self.signals.enable_buttoms.emit(0)
        
        while self.times > 0:
            time.sleep(3)
            if state.connected == True:
                state.retry_thread_started = False
                self.signals.enable_buttoms.emit(1)
                self.signals.finished.emit()
                return

            # if hasattr(self.parent, 'thread_stop_flag') and self.parent.thread_stop_flag == True: # 外部停止线程
            #     self.signals.enable_buttoms.emit(1)
            #     state.retry_thread_started = False
            #     self.signals.finished.emit()
            #     self.signals.print_text.emit(f"验证码错误，但此账号认证失败，因此不重试")
            #     return

            self.signals.print_text.emit(f"登录失败,还剩{self.times}次尝试")
            self.times -= 1
            self.signals.thread_login.emit()
            
        if state.connected == False:
            state.retry_thread_started = False
            self.signals.print_text.emit("已多次尝试无法获取验证码，请手动输入验证码、重试或联系Yish_")
            if self.times == 0:
                self.signals.show_input_dialog1.emit()
        self.signals.enable_buttoms.emit(1)
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


        # 启用 Windows DPI 感知（优先 Per-Monitor V2，回退到 System Aware）
        if sys.platform == "win32":
            try:
                ctypes.windll.shcore.SetProcessDpiAwareness(
                    2)  # PROCESS_PER_MONITOR_DPI_AWARE
            except Exception:
                try:
                    print("启用 Windows DPI 感知失败，尝试回退到系统感知。")
                    ctypes.windll.user32.SetProcessDPIAware()
                except Exception:
                    pass

        # Qt 高 DPI 设置（需在创建 QApplication 之前）
        # 自动根据屏幕缩放因子调整
        os.environ.setdefault("QT_AUTO_SCREEN_SCALE_FACTOR", "1")
        # 缩放舍入策略（Qt 5.14+ 生效）
        # 注意：在 Windows 7 上启用 PassThrough 会导致文字不显示，这里仅在 Win10+ 启用
        if hasattr(QtGui, "QGuiApplication") and hasattr(QtCore.Qt, "HighDpiScaleFactorRoundingPolicy"):
            try:
                ok_to_set = True
                if sys.platform == "win32":
                    try:
                        v = sys.getwindowsversion()
                        # 仅在 Windows 10 及以上启用（Windows 7/8/8.1 跳过）
                        ok_to_set = (v.major >= 10)
                    except Exception:
                        ok_to_set = False
                if ok_to_set:
                    QtGui.QGuiApplication.setHighDpiScaleFactorRoundingPolicy(
                        QtCore.Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
                    )
                else:
                    print("跳过设置 HighDpiScaleFactorRoundingPolicy")
            except Exception:
                pass

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
# 编译指令nuitka --standalone --lto=yes --msvc=latest --disable-ccache --windows-console-mode=disable --enable-plugin=pyqt5,upx --upx-binary="F:\Programs\upx\upx.exe" --include-data-dir=ddddocr=ddddocr --include-data-dir=jre=jre --include-data-file=login.jar=login.jar --include-package=models --output-dir=SAC --windows-icon-from-ico=yish.ico --nofollow-import-to=unittest main.py