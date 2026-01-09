import os
import sys
import ctypes
import requests
import win32com.client
import msvcrt
# import debugpy
import builtins
import webbrowser as web
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QApplication, QWidget, QInputDialog, QSystemTrayIcon, QMenu, QAction, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox
from PyQt5.QtCore import QThreadPool

from models import state
from models.config_manager import ConfigManager
from models.threads import WorkerSignals, login_retry, jar_Thread, watch_dog, UpdateThread, LoginWorker
from models.windows import settingsWindow
from Ui.mainwindow import Ui_MainWindow

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
        # 配置管理器
        self.config_manager = ConfigManager()
        self.config_path = self.config_manager.config_path
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

        # 初始化Setting
        self.settings_window = settingsWindow(self)

        # 根据配置初始化首页控件状态
        if str(state.login_mode) == "1":
            self.radioButton_3.setChecked(True)
        else:
            self.radioButton_2.setChecked(True)
        self.checkBox.setChecked(str(state.save_pwd) == "1")
        self.checkBox_2.setChecked(str(state.auto_connect) == "1")

        # 绑定按钮功能
        self.pushButton.clicked.connect(lambda: (setattr(self, 'thread_stop_flag', False), self.login())[1])
        self.pushButton_2.clicked.connect(self.logout)

        self.checkBox.clicked.connect(lambda: self.update_config(
            "save_pwd", 1 if self.checkBox.isChecked() else 0))
        self.checkBox_2.clicked.connect(self.on_auto_connect_clicked)

        self.pushButton_3.clicked.connect(
            lambda: web.open_new("https://cmxz.top"))
        self.run_settings_action.triggered.connect(self.run_settings)
        self.pushButton_4.clicked.connect(self.settings_window.mulit_login_now)

        self.radioButton_2.toggled.connect(lambda checked: checked and self.change_login_mode(0))
        self.radioButton_3.toggled.connect(lambda checked: checked and self.change_login_mode(1))

        print("感谢您使用此工具！\n请不要在任何大型社交平台\n(B站、贴吧、小红书、狐友等)\n讨论此工具！")

    def on_tray_icon_clicked(self, reason):
        if reason == QSystemTrayIcon.Trigger:  # 仅响应左键单击
            self.showNormal()
            self.activateWindow()
            
    def changeEvent(self, event):
        if event.type() == QtCore.QEvent.WindowStateChange:
            if self.isMinimized():
                # 允许主界面最小化到托盘，即使设置窗口处于打开状态
                self.hide()
                self.tray_icon.showMessage(
                    f"SEIG虚空终端{state.version}",
                    "程序已最小化到托盘",
                    QSystemTrayIcon.Information,
                    2000
                )
        super(MainWindow, self).changeEvent(event)

    def closeEvent(self, event):
        # global stop_watch_dog
        if self.close_now == False:
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle("退出确认")
            msg_box.setText("您需要退出程序 还是最小化到托盘？")
            msg_box.setIcon(QMessageBox.Question)

            btn_quit = msg_box.addButton("退出", QMessageBox.YesRole)
            btn_minimize = msg_box.addButton("最小化到托盘", QMessageBox.NoRole)

            msg_box.exec_()

            if msg_box.clickedButton() == btn_minimize:
                # 允许直接最小化到托盘
                event.ignore()
                self.hide()
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
        self.read_config()
        if state.auto_connect == "1":
            print("正在尝试自动连接...")

            if not state.username.startswith('t') and state.login_mode == 0:
                state.jar_login = True
            if state.jar_login:
                self.login()
                return
            
            try:
                self.auto_thread = login_retry(5, self)
                self.auto_thread.signals.enable_buttoms.connect(self.enable_buttoms)
                self.auto_thread.signals.thread_login.connect(lambda: self.start_login_worker())
                self.auto_thread.signals.finished.connect(lambda: print("结束自动登录线程"))
                self.threadpool.start(self.auto_thread)
                state.retry_thread_started = True
            except Exception as e:
                print(e)
        else:
            pass

    def mulit_login_mode(self, ip, user, pwd):
        try:
            self.login("mulit", ip, user, pwd)
        except Exception as e:
            print(e)

    def run_settings(self):
        # 显示已创建的设置窗口，若不存在则创建；若已打开则聚焦
        try:
            if self.settings_window is None:
                self.settings_window = settingsWindow(self)
            # 刷新基础配置显示
            try:
                self.settings_window.get_config_value()
            except Exception:
                pass
            # 若窗口最小化则恢复，并置顶聚焦
            if self.settings_window.isMinimized():
                self.settings_window.showNormal()
            self.settings_window.raise_()
            self.settings_window.activateWindow()
            self.settings_window.show()
            state.settings_flag = self.settings_window
        except Exception as e:
            print(f"无法打开设置界面{e}")

    def read_config(self):
        return self.config_manager.read_config()

    def update_config(self, variable, new_value, mode=None):
        return self.config_manager.update_config(variable, new_value, mode)

    def login(self, mode=None, ip=None, user=None, pwd=None):
        state.username = self.lineEdit.text()
        state.password = self.lineEdit_2.text()

        if mode == "mulit":
            state.username = user
            state.password = pwd
            state.wlanuserip = ip

        if state.esurfingurl == "0.0.0.0:0" or state.esurfingurl == "自动获取失败,请检查网线连接":
            self.run_settings()
            print("请先获取或手动填写参数！")
            return
        if not state.username:
            print("账号都不输入登录个锤子啊！")
            return
        if not state.password or state.password == "0":
            print("你账号没有密码的吗？？？")
            return

        self.start_login_worker(mode)
        return
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
            plain_pwd = self.lineEdit_2.text()
            if plain_pwd:
                encrypted_password = ''.join(chr(ord(char) + 10) for char in plain_pwd)
                self.update_config("password", encrypted_password)


    def logout(self):
        
        state.username = self.lineEdit.text()
        if state.jar_login:
            if not os.path.exists('logout.signal'):
                with open('logout.signal', 'w', encoding='utf-8') as file:
                    file.write("")
            jar_Thread.term_all_processes()
            print("执行下线操作中, 请稍后...")
            state.stop_watch_dog = True
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
                    proxies={"http": None, "https": None}
                )

                if response.status_code == 200:
                    data = response.json()
                    print("成功发送下线请求")
                    if data['resultCode'] == "0" or data['resultCode'] == "13002000":
                        state.stop_watch_dog = True
                        print("下线成功")
                    else:
                        print(f"下线失败: {data['resultInfo']}")
                else:
                    print("请求失败，状态码：", response.status_code)
            except Exception as e:
                print(f"下线失败：{e}")
        else:
            print("您尚未登录，无需下线！")

    def start_login_worker(self, mode=None, ip=None, user=None, pwd=None):
        """在后台启动 LoginWorker，并绑定结果回调。"""
        try:
            if getattr(self, 'thread_stop_flag', False):
                return
            # 根据模式和账号前缀决定走 jar 还是网页登录
            u = user or state.username
            p = pwd or state.password
            ip_addr = ip or state.wlanuserip
            acip = state.wlanacip

            if str(state.login_mode) == "0" and (u or "").startswith('t') is False:
                state.jar_login = True
                self.login_jar(u, p, ip_addr, acip)
                return

            worker = LoginWorker(u, p, ip_addr, acip, mode=mode or 0)
            worker.signals.print_text.connect(self.update_table)
            worker.signals.login_result.connect(self.on_login_result)
            self.threadpool.start(worker)
        except Exception as e:
            print(f"无法启动登录线程: {e}")

    def on_login_result(self, result):
        """处理后台登录结果，更新 UI 与状态。"""
        if result.get('success'):
            sig = result.get('signature')
            if sig:
                state.signature = sig
            state.connected = True
            print("成功连接校园网！")
            self.check_new_version()
            self.save_password()
            
            if state.watch_dog_thread_started != True:
                state.stop_watch_dog = False
                self.watchdog_thread = watch_dog()
                self.watchdog_thread.signals.update_progress.connect(self.update_progress_bar)
                self.watchdog_thread.signals.print_text.connect(self.update_table)
                self.watchdog_thread.signals.thread_login.connect(lambda: self.start_login_worker())
                self.threadpool.start(self.watchdog_thread)

            self.update_config("username", state.username)
        else:
            print(f"登录失败: {result.get('message')}")
            # 密码错误则停止自动重试
            msg = str(result.get('message') or '')
            if ('用户认证失败' in msg) or ('账号或密码错误' in msg) or ('密码错误' in msg):
                print("检测到密码错误，停止自动重试")
                self.thread_stop_flag = True
                state.retry_thread_started = False

        # 汇总多拨结果（仅在多拨流程中）
        if hasattr(self, 'settings_window') and self.settings_window:
            if getattr(self.settings_window, 'is_mulit_running', False):
                ip = result.get('userip') or state.wlanuserip
                success = bool(result.get('success'))
                message = result.get('message') or ('登录成功' if success else '登录失败')
                if hasattr(self.settings_window, 'add_mulit_summary'):
                    self.settings_window.add_mulit_summary(ip, success, message)

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

    def change_login_mode(self, mode):
        if mode == 0:
            print("已切换为自动识别模式")
            state.login_mode = 0
            self.update_config("login_mode", "0")
        elif mode == 1:
            print("已切换为t模式")
            state.login_mode = 1
            self.update_config("login_mode", "1")

    def on_auto_connect_clicked(self):
        is_checked = self.checkBox_2.isChecked()
        
        # 更新自动登录配置
        self.update_config("auto_connect", 1 if is_checked else 0)
        
        if is_checked:
            # 勾选时的操作
            print("开机将自启,并自动登录,需要记住密码\n"
                "看门狗每10分钟检测一次网络连接情况\n"
                "下次自动登录成功时,将启动看门狗")
            self.checkBox.setChecked(True)  # 自动勾选记住密码
            self.add_to_startup()  # 添加开机自启
        else:
            self.add_to_startup(1)  # 移除开机自启
        
        # 强制保存密码
        self.update_config("save_pwd", 1)


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