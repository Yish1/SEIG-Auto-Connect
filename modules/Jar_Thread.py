import os
# import debugpy
import threading
import subprocess
from PyQt5.QtCore import QThreadPool, pyqtSignal, QRunnable, QObject, QTimer, QMutex

from modules.State import global_state
from modules.Working_signals import WorkerSignals

state = global_state()


class jar_Thread(QRunnable):
    processes = []
    lock = QMutex()  # 线程锁，防止竞争条件
    mainWindow = None  # 类变量存储主窗口引用

    def __init__(self, username, password, userip, acip, mainWindow=None):
        super().__init__()
        self.signals = WorkerSignals()
        self.username = username
        self.password = password
        self.userip = userip
        self.acip = acip
        self.process = None  # 存储当前线程的进程
        jar_Thread.mainWindow = mainWindow  # 设置类变量

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

                        if "The login has been authorized" in output:
                            self.signals.connected_success.emit()
                            state.connected = True
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
                        
                        state.login_thread_finished = True
                        self.signals.enable_buttoms.emit(1)

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
                state.login_thread_finished = True
                jar_Thread.mainWindow.enable_buttoms(1)
                
                try:
                    os.remove("logout.signal")
                except FileNotFoundError:
                    pass
        if pid:
            term_jar()
        else:
            # 延迟 5.5 秒执行
            QTimer.singleShot(5500, term_jar)
