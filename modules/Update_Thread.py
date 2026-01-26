import requests
from PyQt5.QtCore import QThreadPool, pyqtSignal, QRunnable, QObject, QTimer, QMutex

from modules.State import global_state
from modules.Working_signals import WorkerSignals

state = global_state()

class UpdateThread(QRunnable):
    def __init__(self):
        super().__init__()
        self.signals = WorkerSignals()

    def run(self):
        # debugpy.breakpoint()  # 在此线程启动断点调试

        headers = {
            'User-Agent': 'CMXZ-SAC_%s' % (state.version)
        }
        # self.signals.print_text.emit(str(headers))
        updatecheck = "https://cmxz.top/programs/sac/check.php"

        if state.new_version_checked == True:
            return

        try:
            page = requests.get(updatecheck, timeout=5, headers=headers)
            newversion = float(page.text)
            # self.signals.print_text.emit("云端版本号为:", newversion)
            findnewversion = "检测到新版本！"
            # self.signals.print_text.emit(str(newversion))
            if newversion > state.version:  # and float(latest_version) < newversion:
                # self.signals.print_text.emit(f"检测到新版本:{newversion},当前版本为:{state.version}")
                new_version_detail = requests.get(
                    updatecheck + "?detail", timeout=5, headers=headers)
                new_version_detail = new_version_detail.text
                self.signals.show_message.emit("云端最新版本: %s<br>当前版本: %s<br><br>%s" % (
                    newversion, state.version, new_version_detail), findnewversion)
                        
        except Exception as e:
            self.signals.print_text.emit(f"CMXZ_API_CHECK_UPDATE_ERROR: {e}")

        try:
            is_enable = requests.get(
                updatecheck + "?enable", timeout=5, headers=headers)
            is_enable = int(is_enable.text)
            state.new_version_checked = True

            if is_enable == 0:
                self.signals.show_message.emit("当前版本已被停用，请及时更新！", "警告")
                self.signals.logout.emit()
                return
        except:
            pass

        self.signals.finished.emit()
