from PyQt5.QtCore import QObject, pyqtSignal

class WorkerSignals(QObject):
    # 定义信号
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