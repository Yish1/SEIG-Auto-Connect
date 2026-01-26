import re
import os
import requests
import webbrowser as web
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QApplication, QWidget, QInputDialog, QSystemTrayIcon, QMenu, QAction, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox
from PyQt5.QtCore import QThreadPool, pyqtSignal, QRunnable, QObject, QTimer, QMutex
from Ui.Main_UI import Ui_MainWindow  # 导入ui文件
from Ui.Settings import Ui_sac_settings

from modules.State import global_state

state = global_state()

class settingsWindow(QtWidgets.QMainWindow, Ui_sac_settings):  # 设置窗口
    def __init__(self, Main_window=None):
        super().__init__()
        central_widget = QtWidgets.QWidget(self)
        self.setCentralWidget(central_widget)
        self.setupUi(central_widget)
        self.setWindowTitle("登录参数")
        self.setWindowIcon(QtGui.QIcon(':/icon/yish.ico'))
        # self.setWindowFlags(QtCore.Qt.WindowStaysOnTopHint)
        self.resize(260, 420)

        self.label_4.hide()

        self.Main_window = Main_window
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
        self.pushButton_7.clicked.connect(self.clear_config)

        self.get_config_value()

    def clear_config(self):
        reply = QMessageBox.question(self, '确认清除配置',
                                     "此操作将清除所有配置并恢复默认值，是否继续？",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            try:
                if os.path.exists(self.Main_window.config_path):
                    os.remove(self.Main_window.config_path)
                self.Main_window.read_config()
                self.get_config_value()
                self.Main_window.radioButton_2.setChecked(True)
                self.Main_window.lineEdit.setText("")
                self.Main_window.lineEdit_2.setText("")
                self.show_message("配置已清除并恢复默认值！", "成功")
            except Exception as e:
                self.show_message(f"清除配置失败: {e}", "错误")
        else:
            print("用户取消了清除配置操作")
            
    def add_new_tab(self, mode=None):

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
                if state.mulit_login:
                    pass
                else:
                    state.mulit_login = 1
                for i in range(state.mulit_login - 1):
                    add_new_tab_func()
            self.init_finished = True

        elif mode == "add":
            add_new_tab_func()
            state.mulit_login += 1
            self.Main_window.update_config("mulit_login", state.mulit_login)

    def del_tab(self):

        latest_index = self.tabWidget_2.count() - 1

        if latest_index > 0:
            # 删除最新的标签页
            self.tabWidget_2.removeTab(latest_index)
            state.mulit_login -= 1
            self.Main_window.update_config("mulit_login", state.mulit_login)
            for i in range(3):
                self.Main_window.update_config(
                    f"line_edit_{state.mulit_login}_{i + 1}", "")
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

        mconfig = {}

        if not os.path.exists(self.Main_window.config_path):
            self.Main_window.read_config()

        with open(self.Main_window.config_path, 'r', encoding='utf-8') as file:
            for line in file:
                if '=' in line:
                    key, value = line.strip().split('=', 1)

                    if "line_edit" in key:
                        if key.strip('[]').split('_')[3] == '3':
                            value = ''.join(
                                chr(ord(char) - 10) for char in value)

                        tab_num = key.strip('[]').split('_')[2]
                        login_info = key.strip('[]').split('_')[3]

                        if tab_num not in state.mulit_info:
                            state.mulit_info[tab_num] = {}

                        state.mulit_info[tab_num][login_info] = value
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
            self.Main_window.update_config(
                line_edit.objectName(), encrypted_password)
            return
        self.Main_window.update_config(line_edit.objectName(), text)

    def mulit_login_now(self):

        state.mulit_info = {}
        a = self.read_config("")
        # {'0': {'1': '192.168.1.1', '2': '123123', '3': ''}, '1': {'1': '', '2': '', '3': ''}}

        # 定义登录的任务
        def login_task(key):
            ip = state.mulit_info[key].get('1', '')
            user = state.mulit_info[key].get('2', '')
            pwd = state.mulit_info[key].get('3', '')

            if ip != '' and user != '' and pwd != '':
                self.Main_window.mulit_login_mode(ip, user, pwd)

            else:
                self.stop_flag = True
                self.show_message("存在为空的登录配置，请完善或删除！", "提示")
                print("存在为空的登录配置，请完善或删除！")
                return

        def start_login(index=0):
            self.stop_flag = False
            if index < len(state.mulit_info):
                key = list(state.mulit_info.keys())[index]
                login_task(key)  # 执行登录任务

                if self.stop_flag:
                    return

                if index < len(state.mulit_info) - 1:
                    QTimer.singleShot(500, lambda: start_login(index + 1))

                elif index == len(state.mulit_info) - 1:
                    print(f"多拨线程执行完毕，共多拨 {len(state.mulit_info)} 次")


        # 启动登录过程
        start_login()

    def get_config_value(self):
        self.lineEdit.setText(state.esurfingurl)
        self.lineEdit_2.setText(state.wlanacip)
        self.lineEdit_3.setText(state.wlanuserip)

    def save_config(self):
        self.Main_window.update_config("esurfingurl", self.lineEdit.text())
        self.Main_window.update_config("wlanacip", self.lineEdit_2.text())
        self.Main_window.update_config("wlanuserip", self.lineEdit_3.text())
        self.close()

    def get_default(self):
        try:
            response = requests.get(url="http://189.cn/", timeout=2)
            state.esurfingurl = re.search(
                "http://(.+?)/", response.url).group(1)
            state.wlanacip = re.search("wlanacip=(.+?)&", response.url).group(1)
            state.wlanuserip = re.search(
                "wlanuserip=(.+)", response.url).group(1)
            self.get_config_value()
            try:
                self.pushButton.setEnabled(True)
                self.label_4.hide()
                print("成功获取参数")
            except:
                pass
        except Exception as e:
            if "'NoneType' object has no attribute 'group'" in str(e):
                print(f"没有从重定向的链接中获取到参数，请检查网线连接，或者是否已经能够上网了？{e}")
            else:
                print(f"获取参数失败(请检查网线，并确保断开了热点)：{e}")
            self.label_4.show()
            self.pushButton.setEnabled(False)

    def run_settings_window(self):
        self.show()
        return self

    def closeEvent(self, event):
        # print("设置被关闭")

        state.settings_flag = None
        event.accept()