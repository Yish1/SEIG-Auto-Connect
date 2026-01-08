import os
import time
import threading
import subprocess
import requests
from PyQt5.QtCore import QRunnable, QObject, pyqtSignal, QTimer, QMutex
from PyQt5.QtWidgets import QMessageBox

from models import state
import rsa
import json
import ddddocr

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
    login_result = pyqtSignal(dict)


class login_Thread(QRunnable):
    def __init__(self, times, parent=None):
        super().__init__()
        self.signals = WorkerSignals()
        self.times = times

    def run(self):
        self.signals.enable_buttoms.emit(0)

        while self.times > 0:
            time.sleep(3)
            if state.connected == True:
                state.retry_thread_started = False
                self.signals.enable_buttoms.emit(1)
                self.signals.finished.emit()
                return

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


class LoginWorker(QRunnable):
    """在后台执行网络登录的 Worker，避免在主线程阻塞。"""
    def __init__(self, username, password, userip, acip, mode=0):
        super().__init__()
        self.signals = WorkerSignals()
        self.username = username
        self.password = password
        self.userip = userip
        self.acip = acip
        self.mode = mode

    def get_captcha_image_url(self, session):
        try:
            page_url = f"http://{state.esurfingurl}/qs/index_gz.jsp?wlanacip={state.wlanacip}&wlanuserip={state.wlanuserip}"
            headers = {"Origin": f"http://{state.esurfingurl}", "User-Agent": "Mozilla/5.0"}
            response = session.get(page_url, timeout=5, headers=headers)
            m = __import__('re').search(r'/common/image_code\.jsp\?time=\d+', str(response.content))
            if m:
                return f'http://{state.esurfingurl}' + m.group()
            else:
                self.signals.print_text.emit("未找到验证码图片URL")
        except Exception as e:
            self.signals.print_text.emit(f"获取验证码URL失败: {e}")
        return None

    def run(self):
        result = {"success": False, "message": "", "resultCode": None}
        try:
            session = requests.session()
            self.signals.print_text.emit(f"即将登录: {self.username} IP: {state.wlanuserip}")
            # 获取验证码并识别
            image_url = self.get_captcha_image_url(session)
            code = ''
            if image_url:
                self.signals.print_text.emit(f"验证码url: {image_url}")
                try:
                    resp = session.get(image_url, timeout=5)
                    if resp.status_code == 200:
                        from io import BytesIO
                        from PIL import Image
                        image = Image.open(BytesIO(resp.content))
                        ocr = ddddocr.DdddOcr(show_ad=False)
                        code = ocr.classification(image)
                        code = __import__('re').sub(r'[\s\.:()\[\]{}\-+!@#$%^&*_=;,?\/]', '', code)
                        self.signals.print_text.emit(f"识别到的验证码: {code}")
                except Exception as e:
                    self.signals.print_text.emit(f"识别验证码失败: {e}")

            pub_key = rsa.PublicKey.load_pkcs1_openssl_pem(state.rsa_public_key.encode())
            login_data = {"userName": self.username, "password": self.password, "rand": code}
            login_key = __import__('binascii').hexlify(rsa.encrypt(json.dumps(login_data).encode('utf-8'), pub_key)).decode('utf-8')
            headers = {"Origin": f"http://{state.esurfingurl}", "Referer": f"http://{state.esurfingurl}/qs/index_gz.jsp?wlanacip={state.wlanacip}&wlanuserip={state.wlanuserip}", "User-Agent": "Mozilla/5.0"}
            post_data = {'loginKey': login_key, 'wlanuserip': state.wlanuserip, 'wlanacip': state.wlanacip}
            resp = session.post(f'http://{state.esurfingurl}/ajax/login', timeout=5, headers=headers, data=post_data)
            if resp.status_code == 200:
                data = resp.json()
                result['resultCode'] = data.get('resultCode')
                if data.get('resultCode') in ("0", "13002000"):
                    result['success'] = True
                    try:
                        result['signature'] = resp.cookies.get('signature')
                    except:
                        result['signature'] = None
                    result['message'] = '登录成功'
                else:
                    result['message'] = data.get('resultInfo', '登录失败')
            else:
                result['message'] = f'HTTP状态码:{resp.status_code}'
        except Exception as e:
            result['message'] = str(e)

        # 发出结果
        self.signals.login_result.emit(result)


class jar_Thread(QRunnable):
    processes = []
    lock = QMutex()

    def __init__(self, username, password, userip, acip):
        super().__init__()
        self.signals = WorkerSignals()
        self.username = username
        self.password = password
        self.userip = userip
        self.acip = acip
        self.process = None

    def run(self):
        try:
            java_executable = os.path.join(os.getcwd(), "jre", "bin", "java.exe")
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
            if os.name == "nt":
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

            self.process = subprocess.Popen(
                java_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                startupinfo=startupinfo,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            )

            pid = self.process.pid

            jar_Thread.lock.lock()
            jar_Thread.processes.append(self.process)
            jar_Thread.lock.unlock()

            self.signals.print_text.emit(f"进程 {pid} 启动成功！")

            def read_output():
                while True:
                    output = self.process.stdout.readline()
                    if output:
                        self.signals.print_text.emit(f"{pid}: {output.strip()}")

                        if "The network has been connected" in output:
                            jar_Thread.term_all_processes(pid)
                            self.signals.print_text.emit(
                                f"{pid}: 当前设备已连接互联网，无需再次登录\n如果没有使用此工具登录\n将不能使用此工具的下线功能\n请使用天翼校园网手动下线，或等待8分钟")
                            self.signals.update_check.emit()
                            self.signals.enable_buttoms.emit(1)

                        if "The login has been authorized" in output:
                            self.signals.connected_success.emit()
                            self.signals.enable_buttoms.emit(1)
                            state.connected = True
                            self.signals.print_text.emit(f"{pid}: 登录成功！即将发送心跳... :)")
                            self.signals.print_text.emit(f"{pid}:『只要心跳仍在，我们就不会掉线』")
                            self.signals.jar_login_success.emit()

                        if "Send Keep Packet" in output:
                            self.signals.print_text.emit(f"{pid}: 心跳成功，请不要关闭此程序，\n需要每480秒心跳保持连接！")
                            self.signals.update_check.emit()

                        if "KeepUrl is empty" in output:
                            jar_Thread.term_all_processes(pid)
                            self.signals.print_text.emit(f"{pid}: 登录失败，账号或密码错误！")
                            self.signals.enable_buttoms.emit(1)

                        state.login_thread_finished = True

                    if self.process.poll() is not None:
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
            jar_Thread.lock.lock()
            try:
                if pid is None:
                    for process in jar_Thread.processes:
                        try:
                            process.terminate()
                            process.wait()
                            print(f"进程 {process.pid} 已终止。")
                        except Exception as e:
                            print(f"终止进程 {process.pid} 时出错: {str(e)}")
                    jar_Thread.processes.clear()
                else:
                    for process in jar_Thread.processes[:]:
                        if process.pid == pid:
                            try:
                                process.terminate()
                                process.wait()
                                print(f"进程 {pid} 已终止。")
                                jar_Thread.processes.remove(process)
                            except Exception as e:
                                print(f"终止进程 {pid} 时出错: {str(e)}")
                            break
            finally:
                jar_Thread.lock.unlock()
                state.login_thread_finished = True
                try:
                    os.remove("logout.signal")
                except FileNotFoundError:
                    pass
        if pid:
            term_jar()
        else:
            QTimer.singleShot(5500, term_jar)


class watch_dog(QRunnable):
    def __init__(self):
        super().__init__()
        self.signals = WorkerSignals()
        try:
            self.ping_timeout = state.watch_dog_timeout
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
        original_interval = self.ping_timeout
        if state.watch_dog_thread_started != True:
            state.watch_dog_thread_started = True
            self.signals.print_text.emit(f"看门狗:已就位！每{self.ping_timeout}秒检测一次网络")
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
                    progress_value = int(((self.ping_timeout - total_sleep_time) / self.ping_timeout) * 100)
                    try:
                        self.signals.update_progress.emit(1, progress_value, 100)
                    except:
                        print("信号槽已被删除")

                if not self.ping_baidu():
                    current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                    self.signals.print_text.emit(f"看门狗:网络断开，重新登录...[{current_time}]")
                    self.ping_timeout = self.reconnect_timeout
                    try:
                        self.signals.thread_login.emit()
                    except Exception as e:
                        self.signals.print_text.emit(f"看门狗:登录失败: {e}")
                else:
                    self.ping_timeout = original_interval
                    self.signals.print_text.emit("看门狗:网络正常无需操作")
        else:
            self.signals.print_text.emit("看门狗:线程已启动无需再次启动")


class UpdateThread(QRunnable):
    def __init__(self):
        super().__init__()
        self.signals = WorkerSignals()

    def run(self):
        headers = {'User-Agent': 'CMXZ-SAC_%s' % (state.version)}
        updatecheck = "https://cmxz.top/programs/sac/check.php"

        if state.new_version_checked == True:
            return

        try:
            page = requests.get(updatecheck, timeout=5, headers=headers)
            newversion = float(page.text)
            findnewversion = "检测到新版本！"
            if newversion > state.version:
                new_version_detail = requests.get(updatecheck + "?detail", timeout=5, headers=headers)
                new_version_detail = new_version_detail.text
                self.signals.show_message.emit("云端最新版本: %s<br>当前版本: %s<br><br>%s" % (
                    newversion, state.version, new_version_detail), findnewversion)
        except Exception as e:
            self.signals.print_text.emit(f"CMXZ_API_CHECK_UPDATE_ERROR: {e}")

        try:
            is_enable = requests.get(updatecheck + "?enable", timeout=5, headers=headers)
            is_enable = int(is_enable.text)
            state.new_version_checked = True

            if is_enable == 0:
                self.signals.show_message.emit("当前版本已被停用，请及时更新！", "警告")
                self.signals.logout.emit()
                return
        except:
            pass

        self.signals.finished.emit()
